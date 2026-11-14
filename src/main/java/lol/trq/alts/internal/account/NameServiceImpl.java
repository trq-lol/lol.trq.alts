package lol.trq.alts.internal.account;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import lol.trq.alts.AltsFailure;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.account.ClaimOptions;
import lol.trq.alts.account.ClaimResult;
import lol.trq.alts.account.NameAvailability;
import lol.trq.alts.account.NameChangeResult;
import lol.trq.alts.account.NameEligibility;
import lol.trq.alts.account.NameService;
import lol.trq.alts.account.PlayerProfile;
import lol.trq.alts.internal.net.FailureText;
import lol.trq.alts.internal.net.HttpTransport;
import lol.trq.alts.net.NetworkScope;
import lol.trq.alts.time.TimeSource;

/**
 * Concrete {@link NameService}. The reads and the single change are ordinary bearer calls; the scheduled
 * claim borrows the bulk runner's structural concurrency — worker chains over the library executor, first
 * success cancels the rest, no executor created — and adds a two-phase wait that sleeps coarsely then
 * spins briefly, because a scheduler sleep overshoots a millisecond target.
 *
 * @author trq
 * @since 1.0.0
 */
public final class NameServiceImpl implements NameService {

    /** The kinds of failed change that end a claim run rather than being tried again. */
    private static final java.util.Set<Kind> TERMINAL = java.util.EnumSet.of(
            Kind.UNAUTHORIZED, Kind.REAUTH_REQUIRED, Kind.NOT_ENTITLED, Kind.RATE_LIMITED, Kind.CANCELLED);

    /** Below this much remaining, the wait switches from sleeping to a bounded spin for accuracy. */
    private static final long SPIN_THRESHOLD_MILLIS = 20L;

    private final AccountHttp http;
    private final AccountUrls endpoints;
    private final Gson gson;

    public NameServiceImpl(AccountHttp http, AccountUrls endpoints, Gson gson) {
        this.http = http;
        this.endpoints = endpoints;
        this.gson = gson;
    }

    @Override
    public NameAvailability checkAvailability(String name) {
        JsonObject body = http.get(endpoints.nameAvailability(name), NetworkScope.Purpose.PROFILE);
        return NameAvailability.from(AccountHttp.string(body, "status"));
    }

    @Override
    public NameEligibility eligibility() {
        JsonObject body = http.get(endpoints.nameChangeInfo(), NetworkScope.Purpose.PROFILE);
        // Read as a boolean only when it is one: a JSON null, or any other shape, means the service did
        // not say the change is allowed, which is not the same as the request having failed.
        JsonElement flag = body.get("nameChangeAllowed");
        boolean allowed = flag != null
                && flag.isJsonPrimitive()
                && flag.getAsJsonPrimitive().isBoolean()
                && flag.getAsBoolean();
        return new NameEligibility(
                allowed,
                parseInstant(AccountHttp.string(body, "createdAt")),
                parseInstant(AccountHttp.string(body, "changedAt")));
    }

    @Override
    public NameChangeResult change(String name) {
        HttpTransport.HttpResponse response;
        try {
            response = http.transport()
                    .sendForStatus(
                            "PUT",
                            endpoints.nameChange(name),
                            null,
                            java.util.Map.of("Authorization", "Bearer " + http.token()),
                            null,
                            NetworkScope.forAccount(NetworkScope.Purpose.PROFILE, http.accountUuid(), name));
        } catch (Exception transport) {
            // Unreachable is a failed change like any other: the result says what kind it was.
            return NameChangeResult.failed(FailureText.toFailure("Name change", transport));
        }
        return classify(response);
    }

    /**
     * Maps a name-change response onto a result: an invalid name and an unavailable one are outcomes;
     * a refused token, an account with nothing to rename, a rate limit and anything else are a
     * {@link NameChangeResult.Outcome#FAILED} carrying the kind. The service's own error text is not
     * repeated.
     *
     * @param response the change response
     * @return the classified result
     */
    private NameChangeResult classify(HttpTransport.HttpResponse response) {
        int status = response.status();
        if (status >= 200 && status < 300) {
            PlayerProfile profile = AccountHttp.decode(gson, response.body(), PlayerProfile.class);
            return new NameChangeResult(NameChangeResult.Outcome.CHANGED, profile, "Name changed", Optional.empty());
        }
        return switch (status) {
            case 400 ->
                new NameChangeResult(
                        NameChangeResult.Outcome.INVALID_NAME, null, "The name is not valid", Optional.empty());
            case 403 ->
                new NameChangeResult(
                        NameChangeResult.Outcome.UNAVAILABLE,
                        null,
                        "The name is unavailable, or the account cannot change its name yet",
                        Optional.empty());
            case 404 ->
                NameChangeResult.failed(
                        AltsFailure.of(Kind.NOT_ENTITLED, "Name change: the account owns no Java profile to rename"));
            default ->
                NameChangeResult.failed(AccountHttp.failure("PUT", "/minecraft/profile/name", response)
                        .failure());
        };
    }

    @Override
    public CompletableFuture<ClaimResult> claimAt(String name, Instant target, ClaimOptions options) {
        ClaimOptions opts = options == null ? ClaimOptions.defaults() : options;
        Instant begin = target.minus(opts.leadTime());
        ClaimRun run = new ClaimRun(name, target.plus(opts.window()), opts);

        // The future handed back is one this method owns rather than the tail of the chain below, so
        // that completing it from outside — a cancel() — is observable here and stops the run. A
        // dependent future would swallow the cancellation and leave the workers firing.
        CompletableFuture<ClaimResult> result = new CompletableFuture<>();
        result.whenComplete((ignored, failure) -> run.stop(ClaimResult.StopReason.CANCELLED, null, null));

        CompletableFuture<Void> waited;
        try {
            waited = waitUntil(begin, opts.timeSource(), run::stopped);
        } catch (RuntimeException refused) {
            // The executor refused the final spin (the runtime is closed): the run ends, with a result.
            waited = CompletableFuture.failedFuture(refused);
        }
        waited.thenCompose(ignored -> {
                    List<CompletableFuture<Void>> workers = new ArrayList<>(opts.concurrency());
                    for (int i = 0; i < opts.concurrency(); i++) {
                        workers.add(worker(run));
                    }
                    return CompletableFuture.allOf(workers.toArray(CompletableFuture[]::new));
                })
                .whenComplete((ignored, failure) -> {
                    if (failure != null) {
                        // A wait the closed runtime ended, or an executor that refused an attempt: the run
                        // stops on that failure, classified, and the future still holds a result.
                        run.stop(
                                ClaimResult.StopReason.TERMINAL_FAILURE,
                                null,
                                FailureText.toFailure("Name claim", failure));
                    }
                    result.complete(run.result());
                });
        return result;
    }

    /**
     * One attempt chain: try the change, and if it neither ended the run nor ran out of time, wait the
     * spacing and try again.
     *
     * @param run the claim this chain belongs to
     * @return a future completing when this chain has stopped
     */
    private CompletableFuture<Void> worker(ClaimRun run) {
        if (run.stopped() || run.opts.timeSource().now().isAfter(run.deadline)) {
            return CompletableFuture.completedFuture(null);
        }
        // Re-checked on the worker thread: a run stopped while this attempt sat queued must not fire it.
        return CompletableFuture.supplyAsync(
                        () -> run.stopped() ? null : attemptChange(run.name),
                        http.transport().executor())
                .thenCompose(result -> {
                    if (result == null) {
                        return CompletableFuture.completedFuture((Void) null);
                    }
                    run.attempts.incrementAndGet();
                    run.last.set(result);
                    if (result.success()) {
                        run.claimed(result);
                        return CompletableFuture.completedFuture((Void) null);
                    }
                    // A dead token or an unentitled account will never succeed; stop the whole run
                    // rather than hammer a change that cannot land. The name was not claimed. And the
                    // service asking to be left alone ends it too: several workers a few milliseconds
                    // apart for the rest of the window is the opposite of that, and it is how an address
                    // turns a short limit into a long one. A closed runtime ends it as well.
                    if (result.failure().map(f -> TERMINAL.contains(f.kind())).orElse(false)) {
                        run.stop(
                                ClaimResult.StopReason.TERMINAL_FAILURE,
                                result,
                                result.failure().orElseThrow());
                        return CompletableFuture.completedFuture((Void) null);
                    }
                    return delay(run.opts.attemptSpacing()).thenCompose(ignored -> worker(run));
                });
    }

    /**
     * Runs one change attempt. A transport blip is a failed result, not an exception, so it does not
     * abort the whole burst; anything else thrown is classified the same way.
     */
    private NameChangeResult attemptChange(String name) {
        try {
            return change(name);
        } catch (RuntimeException failed) {
            return NameChangeResult.failed(FailureText.toFailure("Name change", failed));
        }
    }

    /**
     * Waits until {@code target}, sleeping coarsely down to {@link #SPIN_THRESHOLD_MILLIS} and then
     * spinning the final stretch, because a scheduler sleep overshoots a millisecond deadline. The spin
     * is bounded by that threshold so it never becomes a core-pinning busy loop, and both phases give up
     * as soon as the run is stopped.
     */
    private CompletableFuture<Void> waitUntil(Instant target, TimeSource clock, BooleanSupplier stopped) {
        if (stopped.getAsBoolean()) {
            return CompletableFuture.completedFuture(null);
        }
        long remaining = Duration.between(clock.now(), target).toMillis();
        if (remaining <= 0) {
            return CompletableFuture.completedFuture(null);
        }
        if (remaining <= SPIN_THRESHOLD_MILLIS) {
            return CompletableFuture.supplyAsync(
                    () -> {
                        while (!stopped.getAsBoolean() && clock.now().isBefore(target)) {
                            Thread.onSpinWait();
                        }
                        return null;
                    },
                    http.transport().executor());
        }
        long sleep = remaining - SPIN_THRESHOLD_MILLIS;
        return delay(Duration.ofMillis(sleep)).thenCompose(ignored -> waitUntil(target, clock, stopped));
    }

    // Fails, rather than waiting for good, once the runtime has closed: a claim scheduled for hours
    // ahead ends with the runtime instead of outliving it.
    private CompletableFuture<Void> delay(Duration duration) {
        return http.transport().delay(duration);
    }

    private static Instant parseInstant(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return Instant.parse(value);
        } catch (DateTimeParseException notIso) {
            return null;
        }
    }

    /**
     * The shared state of one scheduled claim.
     *
     * <p>"The name was claimed" and "the run stopped" are kept apart, and so is why it stopped: a
     * terminal failure, a rate limit, and a cancellation each end the run without the name having been
     * claimed, and a success that lands while another chain is reporting a refusal is still a success.
     */
    private static final class ClaimRun {

        final String name;
        final Instant deadline;
        final ClaimOptions opts;

        final AtomicInteger attempts = new AtomicInteger();
        final AtomicReference<NameChangeResult> last = new AtomicReference<>();

        private final AtomicBoolean claimed = new AtomicBoolean();
        private final AtomicReference<ClaimResult.StopReason> stopReason = new AtomicReference<>();
        private final AtomicReference<NameChangeResult> deciding = new AtomicReference<>();
        private final AtomicReference<NameChangeResult> winning = new AtomicReference<>();
        private final AtomicReference<AltsFailure> failure = new AtomicReference<>();

        ClaimRun(String name, Instant deadline, ClaimOptions opts) {
            this.name = name;
            this.deadline = deadline;
            this.opts = opts;
        }

        boolean stopped() {
            return stopReason.get() != null;
        }

        /** Records the winning change and stops the run. */
        void claimed(NameChangeResult result) {
            winning.compareAndSet(null, result);
            claimed.set(true);
            stopReason.compareAndSet(null, ClaimResult.StopReason.CLAIMED);
        }

        /**
         * Stops the run for a reason other than success. The first reason given is the one reported.
         *
         * @param reason why the run is stopping
         * @param result the change result that caused it, or null when none did
         * @param cause what ended it, for {@link ClaimResult.StopReason#TERMINAL_FAILURE}; else null
         */
        void stop(ClaimResult.StopReason reason, NameChangeResult result, AltsFailure cause) {
            if (stopReason.compareAndSet(null, reason)) {
                if (result != null) {
                    deciding.set(result);
                }
                failure.set(cause);
            }
        }

        ClaimResult result() {
            if (claimed.get()) {
                return new ClaimResult(
                        true, attempts.get(), winning.get(), ClaimResult.StopReason.CLAIMED, Optional.empty());
            }
            ClaimResult.StopReason reason = stopReason.get();
            NameChangeResult decisive = deciding.get();
            return new ClaimResult(
                    false,
                    attempts.get(),
                    decisive != null ? decisive : last.get(),
                    reason == null ? ClaimResult.StopReason.WINDOW_ELAPSED : reason,
                    reason == ClaimResult.StopReason.TERMINAL_FAILURE ? Optional.of(failure.get()) : Optional.empty());
        }
    }
}

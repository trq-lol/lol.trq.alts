package lol.trq.alts.account;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import lol.trq.alts.net.FailureText;
import lol.trq.alts.net.HttpUtil;
import lol.trq.alts.net.IoExecutor;
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
final class NameServiceImpl implements NameService {

    /** Below this much remaining, the wait switches from sleeping to a bounded spin for accuracy. */
    private static final long SPIN_THRESHOLD_MILLIS = 20L;

    private final AccountHttp http;
    private final AccountEndpoints endpoints;
    private final Gson gson;

    NameServiceImpl(AccountHttp http, AccountEndpoints endpoints, Gson gson) {
        this.http = http;
        this.endpoints = endpoints;
        this.gson = gson;
    }

    @Override
    public NameAvailability checkAvailability(String name) throws AccountException {
        JsonObject body = http.get(endpoints.nameAvailability(name), NetworkScope.Purpose.PROFILE);
        return NameAvailability.from(AccountHttp.string(body, "status"));
    }

    @Override
    public NameEligibility eligibility() throws AccountException {
        JsonObject body = http.get(endpoints.nameChangeInfo(), NetworkScope.Purpose.PROFILE);
        boolean allowed =
                body.has("nameChangeAllowed") && body.get("nameChangeAllowed").getAsBoolean();
        return new NameEligibility(
                allowed,
                parseInstant(AccountHttp.string(body, "createdAt")),
                parseInstant(AccountHttp.string(body, "changedAt")));
    }

    @Override
    public NameChangeResult change(String name) throws AccountException {
        HttpUtil.HttpResponse response;
        try {
            response = HttpUtil.sendForStatus(
                    "PUT",
                    endpoints.nameChange(name),
                    null,
                    java.util.Map.of("Authorization", "Bearer " + http.token()),
                    null,
                    NetworkScope.forAccount(NetworkScope.Purpose.PROFILE, http.accountUuid(), name));
        } catch (Exception transport) {
            throw new AccountException("PUT name change: " + FailureText.of(transport), transport);
        }
        return classify(response);
    }

    /**
     * Maps a name-change response onto a result, reading the error body so the message says why.
     *
     * @param response the change response
     * @return the classified result
     */
    private NameChangeResult classify(HttpUtil.HttpResponse response) {
        int status = response.status();
        if (status >= 200 && status < 300) {
            PlayerProfile profile =
                    response.body() == null ? null : gson.fromJson(response.body(), PlayerProfile.class);
            return new NameChangeResult(NameChangeResult.Outcome.CHANGED, profile, "Name changed", null);
        }
        NameChangeResult.Outcome outcome =
                switch (status) {
                    case 400 -> NameChangeResult.Outcome.INVALID_NAME;
                    case 401 -> NameChangeResult.Outcome.UNAUTHORIZED;
                    case 403 -> NameChangeResult.Outcome.UNAVAILABLE;
                    case 404 -> NameChangeResult.Outcome.NOT_ENTITLED;
                    case 429 -> NameChangeResult.Outcome.RATE_LIMITED;
                    default -> NameChangeResult.Outcome.FAILED;
                };
        return new NameChangeResult(outcome, null, message(response, outcome), response.retryAfter());
    }

    private static String message(HttpUtil.HttpResponse response, NameChangeResult.Outcome outcome) {
        JsonObject body = response.body();
        if (body != null) {
            for (String field : new String[] {"errorMessage", "error", "details"}) {
                if (body.has(field) && body.get(field).isJsonPrimitive()) {
                    return body.get(field).getAsString();
                }
            }
        }
        return outcome + " (status " + response.status() + ")";
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
        result.whenComplete((ignored, failure) -> run.stop(ClaimResult.StopReason.CANCELLED, null));

        waitUntil(begin, opts.timeSource(), run::stopped)
                .thenCompose(ignored -> {
                    List<CompletableFuture<Void>> workers = new ArrayList<>(opts.concurrency());
                    for (int i = 0; i < opts.concurrency(); i++) {
                        workers.add(worker(run));
                    }
                    return CompletableFuture.allOf(workers.toArray(CompletableFuture[]::new));
                })
                .whenComplete((ignored, failure) -> {
                    if (failure != null) {
                        result.completeExceptionally(failure);
                    } else {
                        result.complete(run.result());
                    }
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
                        () -> run.stopped() ? null : attemptChange(run.name), IoExecutor.executor())
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
                    // rather than hammer a change that cannot land. The name was not claimed.
                    if (result.outcome() == NameChangeResult.Outcome.UNAUTHORIZED
                            || result.outcome() == NameChangeResult.Outcome.NOT_ENTITLED) {
                        run.stop(ClaimResult.StopReason.TERMINAL_FAILURE, result);
                        return CompletableFuture.completedFuture((Void) null);
                    }
                    // The service has asked to be left alone. Several workers a few milliseconds apart
                    // for the rest of the window is the opposite of that, and it is how an address
                    // turns a short limit into a long one — so one stated limit ends every chain.
                    if (result.outcome() == NameChangeResult.Outcome.RATE_LIMITED) {
                        run.stop(ClaimResult.StopReason.RATE_LIMITED, result);
                        return CompletableFuture.completedFuture((Void) null);
                    }
                    return delay(run.opts.attemptSpacing()).thenCompose(ignored -> worker(run));
                });
    }

    /**
     * Runs one change attempt, flattening a thrown {@link AccountException} into a failed result so a
     * transport blip does not abort the whole burst.
     */
    private NameChangeResult attemptChange(String name) {
        try {
            return change(name);
        } catch (AccountException failed) {
            return new NameChangeResult(NameChangeResult.Outcome.FAILED, null, failed.getMessage(), null);
        }
    }

    /**
     * Waits until {@code target}, sleeping coarsely down to {@link #SPIN_THRESHOLD_MILLIS} and then
     * spinning the final stretch, because a scheduler sleep overshoots a millisecond deadline. The spin
     * is bounded by that threshold so it never becomes a core-pinning busy loop, and both phases give up
     * as soon as the run is stopped.
     */
    private static CompletableFuture<Void> waitUntil(Instant target, TimeSource clock, BooleanSupplier stopped) {
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
                    IoExecutor.executor());
        }
        long sleep = remaining - SPIN_THRESHOLD_MILLIS;
        return delay(Duration.ofMillis(sleep)).thenCompose(ignored -> waitUntil(target, clock, stopped));
    }

    private static CompletableFuture<Void> delay(Duration duration) {
        long millis = duration == null ? 0L : duration.toMillis();
        if (millis <= 0L) {
            return CompletableFuture.completedFuture(null);
        }
        return CompletableFuture.supplyAsync(
                        () -> null,
                        CompletableFuture.delayedExecutor(millis, TimeUnit.MILLISECONDS, IoExecutor.executor()))
                .thenApply(ignored -> null);
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
         */
        void stop(ClaimResult.StopReason reason, NameChangeResult result) {
            if (stopReason.compareAndSet(null, reason) && result != null) {
                deciding.set(result);
            }
        }

        ClaimResult result() {
            if (claimed.get()) {
                return new ClaimResult(true, attempts.get(), winning.get(), ClaimResult.StopReason.CLAIMED);
            }
            ClaimResult.StopReason reason = stopReason.get();
            NameChangeResult decisive = deciding.get();
            return new ClaimResult(
                    false,
                    attempts.get(),
                    decisive != null ? decisive : last.get(),
                    reason == null ? ClaimResult.StopReason.WINDOW_ELAPSED : reason);
        }
    }
}

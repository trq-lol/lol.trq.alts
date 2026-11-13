package lol.trq.alts.bulk;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReferenceArray;
import java.util.function.Function;
import java.util.function.IntFunction;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.account.EntitlementService;
import lol.trq.alts.account.Entitlements;
import lol.trq.alts.auth.AccountStatus;
import lol.trq.alts.auth.AltAccountService;
import lol.trq.alts.auth.AltLoginService;
import lol.trq.alts.auth.LoginResult;
import lol.trq.alts.model.AltAccount;
import lol.trq.alts.model.LoginMode;
import lol.trq.alts.net.Backoff;
import lol.trq.alts.net.FailureText;
import lol.trq.alts.net.HttpTransport;
import lol.trq.alts.store.AccountStore;

/**
 * Concrete {@link BulkOperations}.
 *
 * <p>No executor is created. The concurrency bound is structural: that many worker chains each pull the
 * next entry off a shared cursor and recurse, so everything runs on the runtime's executor where the
 * rest of the library's blocking work already runs, and a host is never surprised by threads it did not
 * ask for.
 *
 * @author trq
 * @since 0.9.0
 */
public final class BulkOperationsImpl implements BulkOperations {

    /**
     * How long a rate limit is waited out when the service named no wait and the options give no retry
     * delay to grow one from. Retrying a throttled request at once is the one thing never done.
     */
    private static final Duration UNSTATED_RATE_LIMIT_WAIT = Duration.ofSeconds(1);

    private final AccountStore store;
    private final AltLoginService importService;
    private final AltAccountService accountService;
    private final Function<AltAccount, EntitlementService> entitlementServices;
    private final HttpTransport transport;

    /**
     * Creates the bulk surface with a given source of per-account entitlement services: the runtime's
     * own account services, so the sweep reaches the same endpoints and transport as everything else.
     *
     * @param store the runtime's account store, whose current account an import puts back when it ends
     * @param importService a login service whose session injector does nothing, so importing resolves
     *     and stores without moving the live session
     * @param accountService the account service the refresh and check runs are built on
     * @param entitlementServices builds the entitlement service for one account, over its access token
     * @param transport the runtime's transport, on whose executor the reads and the waits between entries
     *     run; a run in flight when it closes ends rather than waits
     * @since 1.0.0
     */
    public BulkOperationsImpl(
            AccountStore store,
            AltLoginService importService,
            AltAccountService accountService,
            Function<AltAccount, EntitlementService> entitlementServices,
            HttpTransport transport) {
        this.store = Objects.requireNonNull(store, "store");
        this.importService = Objects.requireNonNull(importService, "importService");
        this.accountService = Objects.requireNonNull(accountService, "accountService");
        this.entitlementServices = Objects.requireNonNull(entitlementServices, "entitlementServices");
        this.transport = Objects.requireNonNull(transport, "transport");
    }

    @Override
    public BulkHandle importCredentials(
            List<String> entries, LoginMode mode, BulkOptions options, BulkProgress progress) {
        List<String> items = List.copyOf(entries == null ? List.of() : entries);

        // Resolving an account stamps it as the store's current one, which a host may well be rendering
        // as "the account you are on". Importing fifty must not leave the fiftieth sitting there, so the
        // pointer is put back where the run found it.
        Optional<AltAccount> before = store.currentAccount();

        // A route tag makes every sign-in of the run go through a tagged view, so each request it makes,
        // on every hop, reaches the provider with the tag.
        BulkOptions paced = options == null ? BulkOptions.defaults() : options;
        AltLoginService logins = paced.routeTag().map(importService::routed).orElse(importService);
        Run run = new Run(
                transport,
                items.size(),
                paced,
                progress,
                index -> BulkEntryResult.positionalLabel(index),
                index -> importOne(logins, items.get(index), mode));
        run.report.whenComplete((report, failure) -> store.useAccount(before.orElse(null)));
        return start(run);
    }

    @Override
    public BulkHandle refreshAll(List<AltAccount> accounts, BulkOptions options, BulkProgress progress) {
        return overAccounts(accounts, options, progress, accountService::refresh);
    }

    @Override
    public BulkHandle checkAll(List<AltAccount> accounts, BulkOptions options, BulkProgress progress) {
        return overAccounts(accounts, options, progress, accountService::check);
    }

    @Override
    public BulkHandle entitlementsAll(List<AltAccount> accounts, BulkOptions options, BulkProgress progress) {
        List<AltAccount> items = List.copyOf(accounts == null ? List.of() : accounts);
        return start(new Run(
                transport,
                items.size(),
                options,
                progress,
                index -> items.get(index).username(),
                index -> CompletableFuture.supplyAsync(() -> entitlementsOf(items.get(index)), transport.executor())));
    }

    /**
     * Reads one account's entitlements and classifies the outcome the way the runner expects.
     *
     * <p>A refused token is terminal for this entry, since the sweep only looks and never renews. A
     * rate limit is reported as one, with the wait the service named when it named one. Everything else
     * that is not an answer is a service or transport failure, which is worth a retry.
     *
     * @param account the account to read
     * @return the attempt
     */
    private Attempt entitlementsOf(AltAccount account) {
        if (account.accessToken() == null || account.accessToken().isBlank()) {
            return Attempt.failed(AltsFailure.of(Kind.UNAUTHORIZED, "Account has no access token"));
        }
        try {
            Entitlements owned = entitlementServices.apply(account).fetch();
            String summary = owned.isEmpty() ? "Owns nothing" : owned.products().size() + " product(s)";
            return new Attempt(account, Optional.empty(), summary, owned);
        } catch (AltsException failure) {
            // Classified where it happened: a refused token, a throttle with its wait, an outage.
            return Attempt.failed(failure.failure());
        }
    }

    /**
     * Runs one account-service operation over a list.
     *
     * @param accounts the accounts to run over
     * @param options how to pace the run
     * @param progress where to report progress
     * @param operation the per-account operation
     * @return a handle on the running operation
     */
    private BulkHandle overAccounts(
            List<AltAccount> accounts,
            BulkOptions options,
            BulkProgress progress,
            java.util.function.Function<AltAccount, CompletableFuture<AccountStatus>> operation) {
        List<AltAccount> items = List.copyOf(accounts == null ? List.of() : accounts);
        return start(new Run(
                transport,
                items.size(),
                options,
                progress,
                index -> items.get(index).username(),
                index -> operation.apply(items.get(index)).thenApply(BulkOperationsImpl::toAttempt)));
    }

    /**
     * Sends one credential line to the route that fits it.
     *
     * @param importService the login service to sign in through, tagged or not
     * @param entry the line
     * @param mode whether to store what it resolves to
     * @return the attempt
     */
    private static CompletableFuture<Attempt> importOne(AltLoginService importService, String entry, LoginMode mode) {
        CredentialKind kind = CredentialKind.detect(entry);
        return switch (kind) {
            case REFRESH_TOKEN -> importService.loginRefreshToken(entry, mode).thenApply(BulkOperationsImpl::toAttempt);
            case SESSION_TOKEN -> importService.loginSession(entry, mode).thenApply(BulkOperationsImpl::toAttempt);
            case COOKIE_TEXT -> importService.loginCookie(entry, mode).thenApply(BulkOperationsImpl::toAttempt);
            case OFFLINE_NAME -> importService.loginOffline(entry, mode).thenApply(BulkOperationsImpl::toAttempt);
            case UNKNOWN ->
                CompletableFuture.completedFuture(
                        Attempt.failed(AltsFailure.of(Kind.UNAUTHORIZED, "Unrecognised credential format")));
        };
    }

    // The stated wait travels with the result, so an import that chooses to wait a limit out waits as
    // long as the service asked rather than guessing.
    private static Attempt toAttempt(LoginResult result) {
        return new Attempt(result.account(), result.failure(), result.message(), null);
    }

    private static Attempt toAttempt(AccountStatus status) {
        return new Attempt(status.account(), status.failure(), status.message(), null);
    }

    /**
     * Launches the worker chains and hands back the handle.
     *
     * @param run the run to start
     * @return a handle on it
     */
    private static BulkHandle start(Run run) {
        int workers = Math.min(run.options.concurrency(), Math.max(run.total, 1));
        List<CompletableFuture<Void>> chains = new ArrayList<>(workers);
        for (int i = 0; i < workers; i++) {
            chains.add(worker(run));
        }
        CompletableFuture.allOf(chains.toArray(CompletableFuture[]::new))
                .whenComplete((ignored, failure) -> run.finish());
        return run;
    }

    /**
     * One worker chain: take the next entry, run it, then take the next.
     *
     * @param run the run
     * @return a future completing when this chain has nothing left to take
     */
    private static CompletableFuture<Void> worker(Run run) {
        int index = run.cursor.getAndIncrement();
        if (index >= run.total || run.halted()) {
            return CompletableFuture.completedFuture(null);
        }
        CompletableFuture<Void> slot;
        try {
            slot = run.awaitSlot();
        } catch (RuntimeException refused) {
            slot = CompletableFuture.failedFuture(refused);
        }
        return slot.thenCompose(ignored -> {
                    // Re-checked after the wait: a run cancelled while this entry was queued must not
                    // then start it.
                    if (run.halted()) {
                        return CompletableFuture.completedFuture(null);
                    }
                    if (!announce(run, index)) {
                        return CompletableFuture.completedFuture(null);
                    }
                    return attempt(run, index, 1).thenAccept(result -> run.record(index, result));
                })
                .thenCompose(ignored -> worker(run))
                // The chain was cut short (the runtime closed under a wait, the executor refused a task):
                // this entry and every one no worker has taken yet are reported as cancelled, so the
                // report still holds every entry and says why the run ended where it did.
                .exceptionally(failure -> {
                    AltsFailure cut = FailureText.toFailure("Bulk run", failure);
                    AltsFailure cancelled = cut.kind() == Kind.CANCELLED
                            ? cut
                            : AltsFailure.of(Kind.CANCELLED, "Bulk run: cut short (" + cut.message() + ")");
                    run.cancelFrom(index, cancelled);
                    return null;
                });
    }

    /**
     * Tells the host an entry is starting. A {@link BulkProgress#started} that throws is the host's own
     * failure, not the run's: that entry fails with kind {@link Kind#UNKNOWN} and is not attempted, and
     * the run goes on with the next entry.
     *
     * @param run the run
     * @param index the entry
     * @return true when the entry should be attempted
     */
    private static boolean announce(Run run, int index) {
        try {
            run.progress.started(index, run.total, run.labeller.apply(index));
            return true;
        } catch (RuntimeException hostFailure) {
            run.record(
                    index,
                    BulkEntryResult.failure(
                            index,
                            BulkEntryResult.positionalLabel(index),
                            AltsFailure.of(Kind.UNKNOWN, "Entry: the host's progress callback failed"),
                            0));
            return false;
        }
    }

    /**
     * Runs one entry, retrying a transient failure until the budget runs out.
     *
     * <p>Three kinds of failure, three treatments. A rate limit — recognised by its reason, or by a
     * stated wait on any reason — ends the run when the options say to stop, and otherwise holds the
     * whole run back for the wait before this entry tries again, so no worker keeps sending into it. An
     * unreachable or failing service is retried on a growing delay. Everything else is an answer about
     * the credential or the account, which asking again does not change.
     *
     * @param run the run
     * @param index the entry
     * @param attempt which attempt this is, counting from 1
     * @return the entry's result
     */
    private static CompletableFuture<BulkEntryResult> attempt(Run run, int index, int attempt) {
        CompletableFuture<Attempt> started;
        try {
            started = run.attempts.apply(index);
        } catch (RuntimeException refused) {
            // An executor that refused the task throws here rather than failing the future.
            started = CompletableFuture.failedFuture(refused);
        }
        return started
                // An attempt that threw rather than returning a result failed somewhere the library did not
                // classify (or the runtime closed under it), so it is classified here by type, never by text.
                .exceptionally(failure -> Attempt.failed(FailureText.toFailure("Entry", failure)))
                .thenCompose(outcome -> {
                    if (outcome.success()) {
                        return CompletableFuture.completedFuture(
                                outcome.entitlements() != null
                                        ? BulkEntryResult.success(
                                                index,
                                                outcome.account(),
                                                outcome.entitlements(),
                                                outcome.message(),
                                                attempt)
                                        : BulkEntryResult.success(
                                                index, outcome.account(), outcome.message(), attempt));
                    }
                    String label = outcome.account() != null ? outcome.account().username() : run.labeller.apply(index);
                    BulkEntryResult failed = BulkEntryResult.failure(
                            index, label, outcome.failure().orElseThrow(), attempt);

                    if (outcome.rateLimited()) {
                        if (run.options.stopOnRateLimit()) {
                            // Continuing to send to a service that has asked to be left alone is how an
                            // address earns a longer ban than the one it is already serving.
                            run.stopped.set(true);
                            return CompletableFuture.completedFuture(failed);
                        }
                        if (attempt > run.options.maxRetries()) {
                            return CompletableFuture.completedFuture(failed);
                        }
                        // The caller chose to wait limits out. The wait is the one the service named, or a
                        // growing one when it named none -- never an immediate retry -- and it holds back
                        // every other entry too, since the limit is on the address rather than the account.
                        Duration stated = outcome.failure()
                                .flatMap(AltsFailure::retryAfter)
                                .orElse(null);
                        Duration wait =
                                positive(stated) ? stated : Backoff.exponential(attempt, run.options.retryBaseDelay());
                        if (!positive(wait)) {
                            wait = UNSTATED_RATE_LIMIT_WAIT;
                        }
                        run.holdBack(wait);
                        return delay(run.transport, wait).thenCompose(ignored -> attempt(run, index, attempt + 1));
                    }
                    boolean retryable = outcome.failure().orElseThrow().kind() == Kind.NETWORK;
                    if (!retryable || attempt > run.options.maxRetries()) {
                        return CompletableFuture.completedFuture(failed);
                    }
                    return delay(run.transport, Backoff.exponential(attempt, run.options.retryBaseDelay()))
                            .thenCompose(ignored -> attempt(run, index, attempt + 1));
                });
    }

    /**
     * Waits without holding a thread.
     *
     * @param transport the runtime's transport, whose executor the wait completes on
     * @param duration how long to wait
     * @return a future completing after it, or failing once the runtime has closed
     */
    private static CompletableFuture<Void> delay(HttpTransport transport, Duration duration) {
        return transport.delay(duration);
    }

    private static boolean positive(Duration duration) {
        return duration != null && !duration.isZero() && !duration.isNegative();
    }

    /** One attempt's outcome, flattened so both surfaces feed the same runner. */
    private record Attempt(
            AltAccount account, Optional<AltsFailure> failure, String message, Entitlements entitlements) {

        static Attempt failed(AltsFailure failure) {
            return new Attempt(null, Optional.of(failure), failure.message(), null);
        }

        boolean success() {
            return failure.isEmpty();
        }

        /** Whether the service asked to be left alone: a rate limit by kind, or a stated wait on any kind. */
        boolean rateLimited() {
            return failure.map(
                            f -> f.kind() == Kind.RATE_LIMITED || f.retryAfter().isPresent())
                    .orElse(false);
        }
    }

    /** The mutable state of one run, and its handle. */
    private static final class Run implements BulkHandle {

        private final HttpTransport transport;
        private final int total;
        private final BulkOptions options;
        private final BulkProgress progress;
        private final IntFunction<String> labeller;
        private final IntFunction<CompletableFuture<Attempt>> attempts;

        private final AtomicInteger cursor = new AtomicInteger();
        private final AtomicReferenceArray<BulkEntryResult> results;
        private final AtomicBoolean cancelled = new AtomicBoolean();
        private final AtomicBoolean stopped = new AtomicBoolean();
        private final AtomicBoolean finishing = new AtomicBoolean();
        private final CompletableFuture<BulkReport> report = new CompletableFuture<>();

        private final Object spacingLock = new Object();
        private long nextStartMillis;

        Run(
                HttpTransport transport,
                int total,
                BulkOptions options,
                BulkProgress progress,
                IntFunction<String> labeller,
                IntFunction<CompletableFuture<Attempt>> attempts) {
            this.transport = transport;
            this.total = total;
            this.options = options == null ? BulkOptions.defaults() : options;
            this.progress = progress == null ? BulkProgress.NONE : progress;
            this.labeller = labeller;
            this.attempts = attempts;
            this.results = new AtomicReferenceArray<>(Math.max(total, 0));
        }

        boolean halted() {
            return cancelled.get() || stopped.get();
        }

        /**
         * Waits until this entry is allowed to start.
         *
         * <p>Spacing is global rather than per proxy route, which the design record called for. Doing it
         * per route means asking the host's provider which route an entry would take before making the
         * request — and a rotating provider treats every ask as an allocation, so the library would
         * consume two pool slots per entry and hand one back unused. A host wanting per-route pacing
         * shards its own runs.
         *
         * @return a future completing when the entry may begin
         */
        CompletableFuture<Void> awaitSlot() {
            long waitMillis;
            synchronized (spacingLock) {
                long now = System.currentTimeMillis();
                long earliest = Math.max(now, nextStartMillis);
                waitMillis = earliest - now;
                nextStartMillis = earliest + options.minSpacing().toMillis();
            }
            return delay(transport, Duration.ofMillis(waitMillis));
        }

        /**
         * Pushes the next entry's start back, so a rate limit being waited out pauses the run rather
         * than only the entry that met it.
         *
         * @param wait how long nothing new should start
         */
        void holdBack(Duration wait) {
            synchronized (spacingLock) {
                nextStartMillis = Math.max(nextStartMillis, System.currentTimeMillis() + wait.toMillis());
            }
        }

        void record(int index, BulkEntryResult result) {
            results.set(index, result);
            progress.completed(index, total, result);
        }

        /**
         * Records {@code from}, if it has no result yet, and every entry no worker has taken, as
         * {@code failure}. Each is claimed through the shared cursor, so no entry another worker is
         * running is overwritten.
         *
         * @param from the entry whose chain was cut short
         * @param failure the failure to record, of kind {@link Kind#CANCELLED}
         */
        void cancelFrom(int from, AltsFailure failure) {
            List<Integer> untaken = new ArrayList<>();
            if (from < total) {
                untaken.add(from);
            }
            for (int next = cursor.getAndIncrement(); next < total; next = cursor.getAndIncrement()) {
                untaken.add(next);
            }
            for (int index : untaken) {
                BulkEntryResult cancelled = BulkEntryResult.failure(index, labelOrPosition(index), failure, 0);
                if (results.compareAndSet(index, null, cancelled)) {
                    try {
                        progress.completed(index, total, cancelled);
                    } catch (RuntimeException hostFailure) {
                        // The report is what matters here; a callback that throws does not stop it.
                    }
                }
            }
        }

        private String labelOrPosition(int index) {
            try {
                return labeller.apply(index);
            } catch (RuntimeException unlabelled) {
                return BulkEntryResult.positionalLabel(index);
            }
        }

        void finish() {
            List<BulkEntryResult> collected = new ArrayList<>(total);
            for (int i = 0; i < total; i++) {
                BulkEntryResult result = results.get(i);
                if (result != null) {
                    collected.add(result);
                }
            }
            BulkReport built = new BulkReport(collected, cancelled.get(), stopped.get());
            if (!finishing.compareAndSet(false, true)) {
                return;
            }
            // The last callback is delivered before the report completes, so a caller woken by the
            // report has seen every callback; and the report completes even if that callback throws.
            try {
                progress.finished(built);
            } finally {
                report.complete(built);
            }
        }

        @Override
        public CompletableFuture<BulkReport> report() {
            return report;
        }

        @Override
        public void cancel() {
            cancelled.set(true);
        }
    }
}

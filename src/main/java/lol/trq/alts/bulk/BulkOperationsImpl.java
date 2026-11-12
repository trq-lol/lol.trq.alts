package lol.trq.alts.bulk;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReferenceArray;
import java.util.function.Function;
import java.util.function.IntFunction;
import lol.trq.alts.account.AccountException;
import lol.trq.alts.account.AccountServices;
import lol.trq.alts.account.EntitlementService;
import lol.trq.alts.account.Entitlements;
import lol.trq.alts.auth.AccountStatus;
import lol.trq.alts.auth.AltAccountService;
import lol.trq.alts.auth.AltLoginCallback.FailureReason;
import lol.trq.alts.auth.AltLoginCallback.LoginResult;
import lol.trq.alts.auth.AltLoginService;
import lol.trq.alts.model.AltAccount;
import lol.trq.alts.model.LoginMode;
import lol.trq.alts.net.Backoff;
import lol.trq.alts.net.IoExecutor;
import lol.trq.alts.store.AltStore;

/**
 * Concrete {@link BulkOperations}.
 *
 * <p>No executor is created. The concurrency bound is structural: that many worker chains each pull the
 * next entry off a shared cursor and recurse, so everything runs on {@link IoExecutor#executor()} where the
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

    private final AltLoginService importService;
    private final AltAccountService accountService;
    private final Function<AltAccount, EntitlementService> entitlementServices;

    /**
     * Creates the bulk surface, reading entitlements from the public Minecraft services.
     *
     * @param importService a login service whose session injector does nothing, so importing resolves
     *     and stores without moving the live session
     * @param accountService the account service the refresh and check runs are built on
     * @since 0.9.0
     */
    public BulkOperationsImpl(AltLoginService importService, AltAccountService accountService) {
        this(
                importService,
                accountService,
                account -> AccountServices.of(account.accessToken(), account.uuid())
                        .entitlements());
    }

    /**
     * Creates the bulk surface with a given source of per-account entitlement services — for a host
     * whose account services go to an overridden endpoint base, so the sweep reaches the same origin.
     *
     * @param importService a login service whose session injector does nothing, so importing resolves
     *     and stores without moving the live session
     * @param accountService the account service the refresh and check runs are built on
     * @param entitlementServices builds the entitlement service for one account, over its access token
     * @since 0.12.0
     */
    public BulkOperationsImpl(
            AltLoginService importService,
            AltAccountService accountService,
            Function<AltAccount, EntitlementService> entitlementServices) {
        this.importService = Objects.requireNonNull(importService, "importService");
        this.accountService = Objects.requireNonNull(accountService, "accountService");
        this.entitlementServices = Objects.requireNonNull(entitlementServices, "entitlementServices");
    }

    @Override
    public BulkHandle importCredentials(
            List<String> entries, LoginMode mode, BulkOptions options, BulkProgress progress) {
        List<String> items = List.copyOf(entries == null ? List.of() : entries);

        // Resolving an account stamps it as the store's current one, which a host may well be rendering
        // as "the account you are on". Importing fifty must not leave the fiftieth sitting there, so the
        // pointer is put back where the run found it.
        Optional<AltAccount> before = AltStore.currentAccount();

        Run run = new Run(
                items.size(),
                options,
                progress,
                index -> BulkEntryResult.positionalLabel(index),
                index -> importOne(items.get(index), mode));
        run.report.whenComplete((report, failure) -> AltStore.useAccount(before.orElse(null)));
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
                items.size(),
                options,
                progress,
                index -> items.get(index).username(),
                index -> CompletableFuture.supplyAsync(() -> entitlementsOf(items.get(index)), IoExecutor.executor())));
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
            return new Attempt(false, account, FailureReason.INVALID_TOKEN, "Account has no access token", null, null);
        }
        try {
            Entitlements owned = entitlementServices.apply(account).fetch();
            String summary = owned.isEmpty() ? "Owns nothing" : owned.products().size() + " product(s)";
            return new Attempt(true, account, FailureReason.NONE, summary, null, owned);
        } catch (AccountException failure) {
            if (failure.rateLimited()) {
                return new Attempt(
                        false,
                        account,
                        FailureReason.RATE_LIMITED,
                        "Rate limited by the entitlement service",
                        failure.retryAfter(),
                        null);
            }
            if (failure.tokenRefused()) {
                return new Attempt(false, account, FailureReason.INVALID_TOKEN, "Access token was refused", null, null);
            }
            return new Attempt(
                    false,
                    account,
                    FailureReason.NETWORK,
                    "Entitlement lookup failed" + (failure.status() > 0 ? " with status " + failure.status() : ""),
                    null,
                    null);
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
                items.size(),
                options,
                progress,
                index -> items.get(index).username(),
                index -> operation.apply(items.get(index)).thenApply(BulkOperationsImpl::toAttempt)));
    }

    /**
     * Sends one credential line to the route that fits it.
     *
     * @param entry the line
     * @param mode whether to store what it resolves to
     * @return the attempt
     */
    private CompletableFuture<Attempt> importOne(String entry, LoginMode mode) {
        CredentialKind kind = CredentialKind.detect(entry);
        return switch (kind) {
            case REFRESH_TOKEN -> importService.loginRefreshToken(entry, mode).thenApply(BulkOperationsImpl::toAttempt);
            case SESSION_TOKEN -> importService.loginSession(entry, mode).thenApply(BulkOperationsImpl::toAttempt);
            case COOKIE_TEXT -> importService.loginCookie(entry, mode).thenApply(BulkOperationsImpl::toAttempt);
            case OFFLINE_NAME -> importService.loginOffline(entry, mode).thenApply(BulkOperationsImpl::toAttempt);
            case UNKNOWN ->
                CompletableFuture.completedFuture(new Attempt(
                        false, null, FailureReason.INVALID_TOKEN, "Unrecognised credential format", null, null));
        };
    }

    // A login result carries no stated wait, so a throttled import is recognised by its reason alone.
    private static Attempt toAttempt(LoginResult result) {
        return new Attempt(result.success(), result.account(), result.reason(), result.message(), null, null);
    }

    private static Attempt toAttempt(AccountStatus status) {
        return new Attempt(
                status.usable(), status.account(), status.reason(), status.message(), status.retryAfter(), null);
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
        return run.awaitSlot()
                .thenCompose(ignored -> {
                    // Re-checked after the wait: a run cancelled while this entry was queued must not
                    // then start it.
                    if (run.halted()) {
                        return CompletableFuture.completedFuture(null);
                    }
                    run.progress.started(index, run.total, run.labeller.apply(index));
                    return attempt(run, index, 1).thenAccept(result -> run.record(index, result));
                })
                .thenCompose(ignored -> worker(run));
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
        return run.attempts
                .apply(index)
                .exceptionally(
                        failure -> new Attempt(false, null, FailureReason.UNKNOWN, describe(failure), null, null))
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
                    BulkEntryResult failed =
                            BulkEntryResult.failure(index, label, outcome.reason(), outcome.message(), attempt);

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
                        Duration wait = positive(outcome.retryAfter())
                                ? outcome.retryAfter()
                                : Backoff.exponential(attempt, run.options.retryBaseDelay());
                        if (!positive(wait)) {
                            wait = UNSTATED_RATE_LIMIT_WAIT;
                        }
                        run.holdBack(wait);
                        return delay(wait).thenCompose(ignored -> attempt(run, index, attempt + 1));
                    }
                    boolean retryable = outcome.reason() == FailureReason.NETWORK;
                    if (!retryable || attempt > run.options.maxRetries()) {
                        return CompletableFuture.completedFuture(failed);
                    }
                    return delay(Backoff.exponential(attempt, run.options.retryBaseDelay()))
                            .thenCompose(ignored -> attempt(run, index, attempt + 1));
                });
    }

    /**
     * Waits without holding a thread.
     *
     * @param duration how long to wait
     * @return a future completing after it
     */
    private static CompletableFuture<Void> delay(Duration duration) {
        long millis = duration == null ? 0L : duration.toMillis();
        if (millis <= 0L) {
            return CompletableFuture.completedFuture(null);
        }
        return CompletableFuture.supplyAsync(
                        () -> null,
                        CompletableFuture.delayedExecutor(millis, TimeUnit.MILLISECONDS, IoExecutor.executor()))
                .thenAccept(ignored -> {});
    }

    private static boolean positive(Duration duration) {
        return duration != null && !duration.isZero() && !duration.isNegative();
    }

    private static String describe(Throwable failure) {
        Throwable cause = failure.getCause() != null ? failure.getCause() : failure;
        return cause.getMessage() != null
                ? cause.getMessage()
                : cause.getClass().getSimpleName();
    }

    /** One attempt's outcome, flattened so both surfaces feed the same runner. */
    private record Attempt(
            boolean success,
            AltAccount account,
            FailureReason reason,
            String message,
            Duration retryAfter,
            Entitlements entitlements) {

        /** Whether the service asked to be left alone: a rate limit by reason, or a stated wait on any. */
        boolean rateLimited() {
            return reason == FailureReason.RATE_LIMITED || retryAfter != null;
        }
    }

    /** The mutable state of one run, and its handle. */
    private static final class Run implements BulkHandle {

        private final int total;
        private final BulkOptions options;
        private final BulkProgress progress;
        private final IntFunction<String> labeller;
        private final IntFunction<CompletableFuture<Attempt>> attempts;

        private final AtomicInteger cursor = new AtomicInteger();
        private final AtomicReferenceArray<BulkEntryResult> results;
        private final AtomicBoolean cancelled = new AtomicBoolean();
        private final AtomicBoolean stopped = new AtomicBoolean();
        private final CompletableFuture<BulkReport> report = new CompletableFuture<>();

        private final Object spacingLock = new Object();
        private long nextStartMillis;

        Run(
                int total,
                BulkOptions options,
                BulkProgress progress,
                IntFunction<String> labeller,
                IntFunction<CompletableFuture<Attempt>> attempts) {
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
            return delay(Duration.ofMillis(waitMillis));
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

        void finish() {
            List<BulkEntryResult> collected = new ArrayList<>(total);
            for (int i = 0; i < total; i++) {
                BulkEntryResult result = results.get(i);
                if (result != null) {
                    collected.add(result);
                }
            }
            BulkReport built = new BulkReport(collected, cancelled.get(), stopped.get());
            if (report.complete(built)) {
                progress.finished(built);
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

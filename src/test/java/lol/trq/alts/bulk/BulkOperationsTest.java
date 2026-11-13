package lol.trq.alts.bulk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import lol.trq.alts.auth.AccountStatus;
import lol.trq.alts.auth.AltAccountService;
import lol.trq.alts.auth.AltLoginCallback.FailureReason;
import lol.trq.alts.auth.AltLoginCallback.LoginResult;
import lol.trq.alts.model.AccountType;
import lol.trq.alts.model.AltAccount;
import lol.trq.alts.model.LoginMode;
import lol.trq.alts.net.HttpTransport;
import lol.trq.alts.net.TestTransports;
import lol.trq.alts.store.AccountStore;
import lol.trq.alts.store.StoreTestHooks;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The pacing and stopping rules, exercised against a stub account service so no network is involved.
 * What each test defends is a way a real run goes wrong: too many at once earns a rate limit, a retry
 * that never gives up turns one dead credential into an endless loop, and a run that ignores a stated
 * rate limit earns a longer ban than the one it is already serving.
 */
class BulkOperationsTest {

    private static final BulkOptions FAST = new BulkOptions(4, Duration.ZERO, 2, Duration.ofMillis(1), true);

    @TempDir
    static Path storeDir;

    /** The store an import puts the current account back into; nothing here asserts on its file. */
    private static AccountStore store;

    @BeforeAll
    static void openStore() {
        store = StoreTestHooks.openAccountStore(storeDir);
    }

    @AfterAll
    static void closeStore() {
        StoreTestHooks.close(store);
    }

    private static AltAccount account(int index) {
        return AltAccount.of("0000000-0000-4000-8000-" + index, "Alt" + index, "token", AccountType.MICROSOFT);
    }

    private static List<AltAccount> accounts(int count) {
        List<AltAccount> list = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            list.add(account(i));
        }
        return list;
    }

    /** Builds a bulk surface whose every account operation is the given function. */
    private static BulkOperations bulkOver(Function<AltAccount, CompletableFuture<AccountStatus>> operation) {
        AltAccountService service = new AltAccountService() {
            @Override
            public CompletableFuture<AccountStatus> check(AltAccount account) {
                return operation.apply(account);
            }

            @Override
            public CompletableFuture<AccountStatus> refresh(AltAccount account) {
                return operation.apply(account);
            }
        };
        // The import service is unused by these runs; a null-injecting login service would need a config.
        return new BulkOperationsImpl(
                store,
                new UnusedLoginService(),
                service,
                account -> {
                    throw new AssertionError("this run reads no entitlements");
                },
                TestTransports.EXECUTOR);
    }

    @Test
    void everyAccountRunsAndTheReportCountsThem() throws Exception {
        BulkOperations bulk = bulkOver(account -> CompletableFuture.completedFuture(AccountStatus.valid(account)));

        BulkReport report =
                bulk.refreshAll(accounts(10), FAST, BulkProgress.NONE).report().get();

        assertEquals(10, report.succeeded());
        assertTrue(report.complete());
        assertTrue(report.failures().isEmpty());
    }

    @Test
    void noMoreThanTheConfiguredNumberRunAtOnce() throws Exception {
        AtomicInteger inFlight = new AtomicInteger();
        AtomicInteger peak = new AtomicInteger();

        BulkOperations bulk = bulkOver(account -> CompletableFuture.supplyAsync(() -> {
            peak.accumulateAndGet(inFlight.incrementAndGet(), Math::max);
            try {
                Thread.sleep(20);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
            inFlight.decrementAndGet();
            return AccountStatus.valid(account);
        }));

        bulk.refreshAll(accounts(12), FAST.withConcurrency(3), BulkProgress.NONE)
                .report()
                .get();

        assertTrue(peak.get() <= 3, "the concurrency bound must hold, saw " + peak.get());
        assertTrue(peak.get() > 1, "the run must actually be concurrent, saw " + peak.get());
    }

    @Test
    void spacingHoldsBetweenStarts() throws Exception {
        BulkOptions spaced = new BulkOptions(1, Duration.ofMillis(30), 0, Duration.ZERO, true);
        BulkOperations bulk = bulkOver(account -> CompletableFuture.completedFuture(AccountStatus.valid(account)));

        long start = System.currentTimeMillis();
        bulk.refreshAll(accounts(4), spaced, BulkProgress.NONE).report().get();
        long elapsed = System.currentTimeMillis() - start;

        assertTrue(elapsed >= 90, "four entries spaced 30ms apart cannot finish in " + elapsed + "ms");
    }

    @Test
    void aTransientFailureIsRetriedUpToTheBudgetAndNoFurther() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        BulkOperations bulk = bulkOver(account -> {
            calls.incrementAndGet();
            return CompletableFuture.completedFuture(AccountStatus.failure(
                    account, AccountStatus.State.UNREACHABLE, FailureReason.NETWORK, "service is down"));
        });

        BulkReport report = bulk.refreshAll(List.of(account(0)), FAST, BulkProgress.NONE)
                .report()
                .get();

        assertEquals(3, calls.get(), "one attempt plus two retries");
        assertEquals(3, report.results().get(0).attempts());
        assertFalse(report.results().get(0).success());
    }

    /** Retrying a refused credential spends rotations to no purpose; only a transient failure is retried. */
    @Test
    void aRefusedCredentialIsNeverRetried() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        BulkOperations bulk = bulkOver(account -> {
            calls.incrementAndGet();
            return CompletableFuture.completedFuture(AccountStatus.failure(
                    account, AccountStatus.State.REAUTH_REQUIRED, FailureReason.REAUTH_REQUIRED, "spent"));
        });

        bulk.refreshAll(List.of(account(0)), FAST, BulkProgress.NONE).report().get();

        assertEquals(1, calls.get(), "a permanently spent credential is not worth a second attempt");
    }

    @Test
    void aStatedRateLimitStopsTheRunAndSaysSo() throws Exception {
        BulkOperations bulk = bulkOver(account -> CompletableFuture.completedFuture(AccountStatus.failure(
                account, AccountStatus.State.UNREACHABLE, FailureReason.NETWORK, "slow down", Duration.ofSeconds(30))));

        BulkReport report = bulk.refreshAll(accounts(20), FAST.withConcurrency(1), BulkProgress.NONE)
                .report()
                .get();

        assertTrue(report.stoppedEarly(), "a service asking to be left alone must end the run");
        assertFalse(report.cancelled(), "stopping early is not the same as being cancelled");
        assertTrue(report.results().size() < 20, "the run must not have worked through the whole list");
    }

    @Test
    void aRateLimitCanBeWaitedOutInsteadWhenTheCallerInsists() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        BulkOperations bulk = bulkOver(account -> {
            if (calls.incrementAndGet() == 1) {
                return CompletableFuture.completedFuture(AccountStatus.failure(
                        account,
                        AccountStatus.State.UNREACHABLE,
                        FailureReason.NETWORK,
                        "slow down",
                        Duration.ofMillis(5)));
            }
            return CompletableFuture.completedFuture(AccountStatus.valid(account));
        });

        BulkReport report = bulk.refreshAll(List.of(account(0)), FAST.withoutStoppingOnRateLimit(), BulkProgress.NONE)
                .report()
                .get();

        assertFalse(report.stoppedEarly());
        assertEquals(1, report.succeeded(), "the entry succeeded on the attempt after the wait");
    }

    /**
     * A 429 that names no wait is still the service asking to be left alone. It used to pass for an
     * outage, so a run retried it and then moved on to the next account, into the same limit.
     */
    @Test
    void aRateLimitWithNoStatedWaitStopsTheRunWithoutARetry() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        BulkOperations bulk = bulkOver(account -> {
            calls.incrementAndGet();
            return CompletableFuture.completedFuture(AccountStatus.failure(
                    account, AccountStatus.State.UNREACHABLE, FailureReason.RATE_LIMITED, "slow down"));
        });

        BulkReport checked = bulk.checkAll(accounts(20), FAST.withConcurrency(1), BulkProgress.NONE)
                .report()
                .get();

        assertTrue(checked.stoppedEarly(), "a rate limit must end the run whether or not it names a wait");
        assertEquals(1, calls.get(), "the limited entry is not retried and the next is never started");
        assertEquals(FailureReason.RATE_LIMITED, checked.failures().get(0).reason());
        assertEquals(1, checked.failures().get(0).attempts());

        calls.set(0);
        BulkReport refreshed = bulk.refreshAll(accounts(20), FAST.withConcurrency(1), BulkProgress.NONE)
                .report()
                .get();

        assertTrue(refreshed.stoppedEarly());
        assertEquals(1, calls.get());
    }

    /**
     * Waiting a limit out means waiting. With no stated wait the delay grows from the retry base rather
     * than being zero (jittered, so at least half the base), and it holds the rest of the run back too: the limit is on the address, so the
     * next account would only walk into it.
     */
    @Test
    void aRateLimitBeingWaitedOutHoldsTheWholeRunBack() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        List<Long> startedAt = new java.util.concurrent.CopyOnWriteArrayList<>();
        BulkOperations bulk = bulkOver(account -> {
            startedAt.add(System.nanoTime());
            if (calls.incrementAndGet() == 1) {
                return CompletableFuture.completedFuture(AccountStatus.failure(
                        account, AccountStatus.State.UNREACHABLE, FailureReason.RATE_LIMITED, "slow down"));
            }
            return CompletableFuture.completedFuture(AccountStatus.valid(account));
        });
        BulkOptions patient = new BulkOptions(2, Duration.ZERO, 2, Duration.ofMillis(80), false);

        BulkReport report = bulk.refreshAll(accounts(3), patient, BulkProgress.NONE)
                .report()
                .get();

        assertFalse(report.stoppedEarly());
        assertEquals(3, report.succeeded());
        assertEquals(4, calls.get(), "the limited entry is tried once more, after the wait");
        long firstToLast = (startedAt.get(startedAt.size() - 1) - startedAt.get(0)) / 1_000_000L;
        assertTrue(firstToLast >= 35, "the retry must have waited out the backoff, not fired at once");
        long firstToThird = (startedAt.get(2) - startedAt.get(0)) / 1_000_000L;
        assertTrue(firstToThird >= 35, "entries queued behind the limit must wait it out too: " + firstToThird);
    }

    /** A limit that never lifts still ends: waiting it out is bounded by the same budget a retry is. */
    @Test
    void aRateLimitThatNeverLiftsGivesUpAtTheRetryBudget() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        BulkOperations bulk = bulkOver(account -> {
            calls.incrementAndGet();
            return CompletableFuture.completedFuture(AccountStatus.failure(
                    account, AccountStatus.State.UNREACHABLE, FailureReason.RATE_LIMITED, "slow down"));
        });

        BulkReport report = bulk.checkAll(List.of(account(0)), FAST.withoutStoppingOnRateLimit(), BulkProgress.NONE)
                .report()
                .get();

        assertEquals(3, calls.get(), "one attempt plus two waits");
        assertEquals(FailureReason.RATE_LIMITED, report.failures().get(0).reason());
    }

    /**
     * Each of these is an answer about the credential or the account. Asking again does not change it,
     * and for a refresh every ask spends a rotation.
     */
    @Test
    void anAnswerAboutTheAccountIsNeverRetried() throws Exception {
        for (FailureReason reason : List.of(
                FailureReason.XBOX_DENIED,
                FailureReason.DECLINED,
                FailureReason.TIMED_OUT,
                FailureReason.INVALID_TOKEN,
                FailureReason.NOT_ENTITLED,
                FailureReason.NOT_CONFIGURED,
                FailureReason.UNKNOWN)) {
            AtomicInteger calls = new AtomicInteger();
            BulkOperations bulk = bulkOver(account -> {
                calls.incrementAndGet();
                return CompletableFuture.completedFuture(
                        AccountStatus.failure(account, AccountStatus.State.UNKNOWN, reason, "no"));
            });

            BulkReport report = bulk.refreshAll(accounts(2), FAST.withConcurrency(1), BulkProgress.NONE)
                    .report()
                    .get();

            assertEquals(2, calls.get(), reason + " must fail its entry on the first attempt");
            assertFalse(report.stoppedEarly(), reason + " is about one account and must not end the run");
            assertEquals(reason, report.failures().get(0).reason());
        }
    }

    /**
     * A login result carries no wait, so an import used to be unable to see a rate limit at all: every
     * remaining credential was sent into it.
     */
    @Test
    void aRateLimitedImportStopsTheRun() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        BulkOperations bulk = importingThrough(token -> {
            calls.incrementAndGet();
            return LoginResult.failure("slow down", FailureReason.RATE_LIMITED);
        });

        BulkReport report = bulk.importCredentials(sessionTokens(20), LoginMode.DIRECT, FAST.withConcurrency(1), null)
                .report()
                .get();

        assertTrue(report.stoppedEarly(), "a throttled import must stop sending credentials");
        assertEquals(1, calls.get());
        assertEquals(FailureReason.RATE_LIMITED, report.failures().get(0).reason());
    }

    @Test
    void anImportRetriesAnOutageButNotARefusal() throws Exception {
        AtomicInteger outages = new AtomicInteger();
        BulkOperations flaky = importingThrough(token -> {
            outages.incrementAndGet();
            return LoginResult.failure("down", FailureReason.NETWORK);
        });
        flaky.importCredentials(sessionTokens(1), LoginMode.DIRECT, FAST, null)
                .report()
                .get();
        assertEquals(3, outages.get(), "an outage is worth the retry budget");

        for (FailureReason reason : List.of(
                FailureReason.XBOX_DENIED,
                FailureReason.DECLINED,
                FailureReason.TIMED_OUT,
                FailureReason.INVALID_TOKEN)) {
            AtomicInteger calls = new AtomicInteger();
            BulkOperations bulk = importingThrough(token -> {
                calls.incrementAndGet();
                return LoginResult.failure("no", reason);
            });

            bulk.importCredentials(sessionTokens(1), LoginMode.DIRECT, FAST, null)
                    .report()
                    .get();

            assertEquals(1, calls.get(), reason + " must not be retried");
        }
    }

    private static List<String> sessionTokens(int count) {
        List<String> tokens = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            tokens.add("eyJ" + i);
        }
        return tokens;
    }

    /** Builds a bulk surface whose session-token import is the given function. */
    private static BulkOperations importingThrough(Function<String, LoginResult> login) {
        AltAccountService unused = new AltAccountService() {
            @Override
            public CompletableFuture<AccountStatus> check(AltAccount account) {
                throw new AssertionError("an import does not check accounts");
            }

            @Override
            public CompletableFuture<AccountStatus> refresh(AltAccount account) {
                throw new AssertionError("an import does not refresh accounts");
            }
        };
        return new BulkOperationsImpl(
                store,
                new UnusedLoginService() {
                    @Override
                    public CompletableFuture<LoginResult> loginSession(String sessionToken, LoginMode mode) {
                        return CompletableFuture.completedFuture(login.apply(sessionToken));
                    }
                },
                unused,
                account -> {
                    throw new AssertionError("an import reads no entitlements");
                },
                TestTransports.EXECUTOR);
    }

    @Test
    void cancellingStopsStartingNewEntries() throws Exception {
        BulkOptions slow = new BulkOptions(1, Duration.ofMillis(20), 0, Duration.ZERO, true);
        BulkOperations bulk = bulkOver(account -> CompletableFuture.completedFuture(AccountStatus.valid(account)));

        BulkHandle handle = bulk.refreshAll(accounts(50), slow, BulkProgress.NONE);
        Thread.sleep(60);
        handle.cancel();
        BulkReport report = handle.report().get();

        assertTrue(report.cancelled());
        assertTrue(
                report.results().size() < 50,
                "cancelling must stop the run, saw " + report.results().size());
        assertFalse(report.complete());
    }

    @Test
    void anEmptyListCompletesRatherThanHanging() throws Exception {
        BulkOperations bulk = bulkOver(account -> CompletableFuture.completedFuture(AccountStatus.valid(account)));

        BulkReport report =
                bulk.checkAll(List.of(), FAST, BulkProgress.NONE).report().get();

        assertEquals(0, report.results().size());
        assertTrue(report.complete());
    }

    @Test
    void progressReportsEveryEntryOnceAndFinishesOnce() throws Exception {
        AtomicInteger started = new AtomicInteger();
        AtomicInteger completed = new AtomicInteger();
        AtomicInteger finished = new AtomicInteger();

        BulkOperations bulk = bulkOver(account -> CompletableFuture.completedFuture(AccountStatus.valid(account)));
        bulk.refreshAll(accounts(6), FAST, new BulkProgress() {
                    @Override
                    public void started(int index, int total, String label) {
                        started.incrementAndGet();
                    }

                    @Override
                    public void completed(int index, int total, BulkEntryResult result) {
                        completed.incrementAndGet();
                    }

                    @Override
                    public void finished(BulkReport report) {
                        finished.incrementAndGet();
                    }
                })
                .report()
                .get();

        assertEquals(6, started.get());
        assertEquals(6, completed.get());
        assertEquals(1, finished.get(), "the run ends once, however it ends");
    }

    @Test
    void anExceptionFromTheOperationFailsOnlyThatEntry() throws Exception {
        BulkOperations bulk = bulkOver(account -> account.username().equals("Alt1")
                ? CompletableFuture.failedFuture(new IllegalStateException("something broke"))
                : CompletableFuture.completedFuture(AccountStatus.valid(account)));

        BulkReport report =
                bulk.refreshAll(accounts(3), FAST, BulkProgress.NONE).report().get();

        assertEquals(2, report.succeeded());
        assertEquals(1, report.failures().size());
        assertEquals(FailureReason.UNKNOWN, report.failures().get(0).reason());
    }

    /** A loopback entitlements endpoint answering per bearer token, and counting what it was asked. */
    private static final class EntitlementServer implements AutoCloseable {

        final com.sun.net.httpserver.HttpServer server;
        final List<String> tokens = new java.util.concurrent.CopyOnWriteArrayList<>();
        volatile java.util.function.Function<String, int[]> statusFor = token -> new int[] {200};
        volatile String retryAfter;

        EntitlementServer() throws java.io.IOException {
            server = com.sun.net.httpserver.HttpServer.create(
                    new java.net.InetSocketAddress(java.net.InetAddress.getLoopbackAddress(), 0), 0);
            server.createContext("/entitlements/mcstore", exchange -> {
                String token =
                        exchange.getRequestHeaders().getFirst("Authorization").substring("Bearer ".length());
                tokens.add(token);
                int status = statusFor.apply(token)[0];
                String body = status != 200
                        ? "{\"error\":\"X\",\"errorMessage\":\"refused\"}"
                        : token.endsWith("pass")
                                ? "{\"items\":[{\"name\":\"product_game_pass_pc\"}]}"
                                : token.endsWith("none")
                                        ? "{\"items\":[]}"
                                        : "{\"items\":[{\"name\":\"product_minecraft\"},{\"name\":\"game_minecraft\"}]}";
                byte[] bytes = body.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                if (status == 429 && retryAfter != null) {
                    exchange.getResponseHeaders().add("Retry-After", retryAfter);
                }
                exchange.sendResponseHeaders(status, bytes.length);
                exchange.getResponseBody().write(bytes);
                exchange.close();
            });
            server.start();
        }

        /** The transport the sweep's reads go through; a test that watches the routing replaces it. */
        HttpTransport transport = TestTransports.direct();

        BulkOperations bulk() {
            lol.trq.alts.account.AccountEndpoints endpoints = new lol.trq.alts.account.AccountEndpoints("http://"
                    + java.net.InetAddress.getLoopbackAddress().getHostAddress() + ":"
                    + server.getAddress().getPort());
            AltAccountService unused = new AltAccountService() {
                @Override
                public CompletableFuture<AccountStatus> check(AltAccount account) {
                    throw new AssertionError("an entitlement sweep must not check accounts");
                }

                @Override
                public CompletableFuture<AccountStatus> refresh(AltAccount account) {
                    throw new AssertionError("an entitlement sweep must not renew accounts");
                }
            };
            return new BulkOperationsImpl(
                    store,
                    new UnusedLoginService(),
                    unused,
                    account -> lol.trq.alts.internal.account.AccountAccess.bridge()
                            .services(transport, account.accessToken(), account.uuid(), endpoints)
                            .entitlements(),
                    transport.executor());
        }

        @Override
        public void close() {
            server.stop(0);
        }
    }

    private static AltAccount owner(int index, String token) {
        return AltAccount.of(
                "00000000-0000-4000-8000-00000000000" + index, "Alt" + index, token, AccountType.MICROSOFT);
    }

    @Test
    void theEntitlementSweepReportsWhatEachAccountOwns() throws Exception {
        try (EntitlementServer server = new EntitlementServer()) {
            List<AltAccount> swept = List.of(owner(0, "t0-java"), owner(1, "t1-pass"), owner(2, "t2-none"));

            BulkReport report = server.bulk()
                    .entitlementsAll(swept, FAST, BulkProgress.NONE)
                    .report()
                    .get();

            assertTrue(report.complete(), "every account was read");
            assertEquals(3, report.results().size());
            BulkEntryResult outright = report.results().get(0);
            assertEquals("Alt0", outright.label());
            assertTrue(outright.entitlements().ownsJavaOutright());
            assertFalse(outright.entitlements().viaGamePass());
            BulkEntryResult subscription = report.results().get(1);
            assertTrue(subscription.entitlements().ownsJava());
            assertTrue(subscription.entitlements().viaGamePass(), "a lapsing subscription is told apart");
            assertFalse(subscription.entitlements().ownsJavaOutright());
            BulkEntryResult nothing = report.results().get(2);
            assertTrue(nothing.success(), "owning nothing is an answer, not a failure");
            assertTrue(nothing.entitlements().isEmpty());
            assertEquals(swept.get(2), nothing.account());
        }
    }

    @Test
    void anEntitlementSweepRoutesEachRequestForItsOwnAccount() throws Exception {
        try (EntitlementServer server = new EntitlementServer()) {
            List<lol.trq.alts.net.NetworkScope> scopes = new java.util.concurrent.CopyOnWriteArrayList<>();
            server.transport = TestTransports.through(scope -> {
                scopes.add(scope);
                return lol.trq.alts.net.ProxyRoute.direct();
            });
            List<AltAccount> swept = List.of(owner(0, "t0-java"), owner(1, "t1-java"), owner(2, "t2-java"));

            server.bulk()
                    .entitlementsAll(swept, FAST, BulkProgress.NONE)
                    .report()
                    .get();

            assertEquals(3, scopes.size());
            for (AltAccount account : swept) {
                assertTrue(
                        scopes.stream().anyMatch(scope -> account.uuid().equals(scope.accountUuid())),
                        "a request was routed for " + account.username());
            }
        }
    }

    @Test
    void aRefusedTokenFailsItsEntryAndIsNotRetried() throws Exception {
        try (EntitlementServer server = new EntitlementServer()) {
            server.statusFor = token -> new int[] {token.startsWith("dead") ? 401 : 200};

            BulkReport report = server.bulk()
                    .entitlementsAll(
                            List.of(owner(0, "t0-java"), owner(1, "dead-java"), owner(2, "t2-java")),
                            FAST,
                            BulkProgress.NONE)
                    .report()
                    .get();

            assertEquals(2, report.succeeded());
            assertFalse(report.stoppedEarly(), "one dead token does not end the sweep");
            BulkEntryResult failed = report.failures().get(0);
            assertEquals(FailureReason.INVALID_TOKEN, failed.reason());
            assertEquals("Alt1", failed.label());
            assertEquals(1, failed.attempts(), "a refused token is not worth a second attempt");
            assertEquals(null, failed.entitlements());
            assertEquals(1, server.tokens.stream().filter("dead-java"::equals).count());
        }
    }

    @Test
    void anAccountWithNoTokenFailsWithoutARequest() throws Exception {
        try (EntitlementServer server = new EntitlementServer()) {
            AltAccount offline =
                    AltAccount.of("00000000-0000-4000-8000-000000000009", "Offline", null, AccountType.OFFLINE);

            BulkReport report = server.bulk()
                    .entitlementsAll(List.of(offline), FAST, BulkProgress.NONE)
                    .report()
                    .get();

            assertEquals(FailureReason.INVALID_TOKEN, report.failures().get(0).reason());
            assertTrue(server.tokens.isEmpty(), "there is nothing to ask the service about");
        }
    }

    @Test
    void aRateLimitedEntitlementSweepStopsAndSaysSo() throws Exception {
        try (EntitlementServer server = new EntitlementServer()) {
            server.statusFor = token -> new int[] {429};
            server.retryAfter = "30";

            BulkReport report = server.bulk()
                    .entitlementsAll(accounts(20), FAST.withConcurrency(1), BulkProgress.NONE)
                    .report()
                    .get();

            assertTrue(report.stoppedEarly(), "a service asking to be left alone must end the sweep");
            assertFalse(report.cancelled());
            assertTrue(report.results().size() < 20);
            assertTrue(server.tokens.size() < 20, "the rest of the list was never sent");
        }
    }

    /** A 429 with no Retry-After is still a stated limit; the absence of a number must not hide it. */
    @Test
    void aRateLimitWithNoStatedWaitStillStopsTheSweep() throws Exception {
        try (EntitlementServer server = new EntitlementServer()) {
            server.statusFor = token -> new int[] {429};

            BulkReport report = server.bulk()
                    .entitlementsAll(accounts(20), FAST.withConcurrency(1), BulkProgress.NONE)
                    .report()
                    .get();

            assertTrue(report.stoppedEarly());
            assertEquals(1, server.tokens.size(), "the first limit ends a one-at-a-time sweep");
            assertEquals(FailureReason.RATE_LIMITED, report.failures().get(0).reason());
        }
    }

    @Test
    void aServerErrorInAnEntitlementSweepIsRetriedUpToTheBudget() throws Exception {
        try (EntitlementServer server = new EntitlementServer()) {
            AtomicInteger calls = new AtomicInteger();
            server.statusFor = token -> new int[] {calls.incrementAndGet() <= 2 ? 503 : 200};

            BulkReport report = server.bulk()
                    .entitlementsAll(List.of(owner(0, "t0-java")), FAST, BulkProgress.NONE)
                    .report()
                    .get();

            assertEquals(1, report.succeeded(), "the entry recovers once the service does");
            assertEquals(3, report.results().get(0).attempts());
            assertTrue(report.results().get(0).entitlements().ownsJavaOutright());
        }
    }

    @Test
    void cancellingAnEntitlementSweepStopsStartingNewEntries() throws Exception {
        try (EntitlementServer server = new EntitlementServer()) {
            BulkOptions slow = new BulkOptions(1, Duration.ofMillis(20), 0, Duration.ZERO, true);

            BulkHandle handle = server.bulk().entitlementsAll(accounts(50), slow, BulkProgress.NONE);
            Thread.sleep(80);
            handle.cancel();
            BulkReport report = handle.report().get();

            assertTrue(report.cancelled());
            assertTrue(report.results().size() < 50, "saw " + report.results().size());
        }
    }

    @Test
    void anEntitlementSweepReportsProgressForEveryEntry() throws Exception {
        try (EntitlementServer server = new EntitlementServer()) {
            AtomicInteger started = new AtomicInteger();
            AtomicInteger completed = new AtomicInteger();
            AtomicInteger finished = new AtomicInteger();

            server.bulk()
                    .entitlementsAll(accounts(6), FAST, new BulkProgress() {
                        @Override
                        public void started(int index, int total, String label) {
                            started.incrementAndGet();
                        }

                        @Override
                        public void completed(int index, int total, BulkEntryResult result) {
                            completed.incrementAndGet();
                        }

                        @Override
                        public void finished(BulkReport report) {
                            finished.incrementAndGet();
                        }
                    })
                    .report()
                    .get();

            assertEquals(6, started.get());
            assertEquals(6, completed.get());
            assertEquals(1, finished.get());
        }
    }

    @Test
    void aResultBuiltTheOldWayCarriesNoEntitlements() {
        BulkEntryResult result = new BulkEntryResult(0, "Alt0", true, account(0), FailureReason.NONE, "ok", 1);

        assertEquals(null, result.entitlements());
        assertEquals(null, BulkEntryResult.success(0, account(0), "ok", 1).entitlements());
    }

    /** Stands in for a login service the account-only runs never reach. */
    private static class UnusedLoginService implements lol.trq.alts.auth.AltLoginService {

        @Override
        public lol.trq.alts.auth.AltLoginService routed(String tag) {
            throw new AssertionError("no run here carries a route tag");
        }

        private static CompletableFuture<lol.trq.alts.auth.AltLoginCallback.LoginResult> unused() {
            throw new AssertionError("the import routes are not exercised by an account run");
        }

        @Override
        public CompletableFuture<lol.trq.alts.auth.AltLoginCallback.LoginResult> loginSession(
                String sessionToken, lol.trq.alts.model.LoginMode mode) {
            return unused();
        }

        @Override
        public CompletableFuture<lol.trq.alts.auth.AltLoginCallback.LoginResult> loginOffline(
                String name, lol.trq.alts.model.LoginMode mode) {
            return unused();
        }

        @Override
        public CompletableFuture<lol.trq.alts.auth.AltLoginCallback.LoginResult> loginMicrosoft(
                lol.trq.alts.model.LoginMode mode) {
            return unused();
        }

        @Override
        public CompletableFuture<lol.trq.alts.auth.AltLoginCallback.LoginResult> loginCookie(
                String cookieData, lol.trq.alts.model.LoginMode mode) {
            return unused();
        }

        @Override
        public CompletableFuture<lol.trq.alts.auth.AltLoginCallback.LoginResult> loginCookieFile(
                java.nio.file.Path file, lol.trq.alts.model.LoginMode mode) {
            return unused();
        }

        @Override
        public CompletableFuture<lol.trq.alts.auth.AltLoginCallback.LoginResult> loginRefreshToken(
                String refreshToken, lol.trq.alts.model.LoginMode mode) {
            return unused();
        }

        @Override
        public CompletableFuture<lol.trq.alts.auth.AltLoginCallback.LoginResult> loginAccount(AltAccount account) {
            return unused();
        }
    }
}

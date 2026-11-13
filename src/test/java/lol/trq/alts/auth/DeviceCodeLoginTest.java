package lol.trq.alts.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import lol.trq.alts.AltsFailure;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.auth.MicrosoftAuthUtil.DeviceCodeTiming;
import lol.trq.alts.model.AccountType;
import lol.trq.alts.model.AltAccount;
import lol.trq.alts.model.LoginMode;
import lol.trq.alts.model.SessionData;
import lol.trq.alts.net.HttpTransport;
import lol.trq.alts.net.NetworkScope;
import lol.trq.alts.net.ProxyRoute;
import lol.trq.alts.net.TestTransports;
import lol.trq.alts.spi.DeviceCodePrompt;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The device-code route: the host is handed a code to show, and the library polls the token endpoint
 * until the user has dealt with it. The service advertises its timings in seconds, so the tests shrink
 * the second rather than wait out real ones; the advertised interval of one "second" lasts
 * {@link #SECOND_MILLIS} here.
 */
@org.junit.jupiter.api.Timeout(value = 60, unit = java.util.concurrent.TimeUnit.SECONDS)
class DeviceCodeLoginTest {

    private static final long SECOND_MILLIS = 20L;
    private static final long SLOW_DOWN_MILLIS = 150L;

    @TempDir
    Path vaultDir;

    private AccountStoreTestSupport localStore;

    private AuthChainServer chain;
    private final AtomicReference<SessionData> injected = new AtomicReference<>();
    private final AtomicInteger prompts = new AtomicInteger();
    private final AtomicReference<String> shownCode = new AtomicReference<>();
    private final AtomicReference<String> shownUri = new AtomicReference<>();
    private final AtomicReference<Instant> shownExpiry = new AtomicReference<>();

    private final DeviceCodePrompt prompt = (userCode, verificationUri, expiresAt) -> {
        prompts.incrementAndGet();
        shownCode.set(userCode);
        shownUri.set(verificationUri);
        shownExpiry.set(expiresAt);
    };

    @BeforeEach
    void setUp() throws IOException {
        localStore = AccountStoreTestSupport.openIn(vaultDir);
        chain = new AuthChainServer();
    }

    @AfterEach
    void tearDown() {
        localStore.close();
        chain.close();
    }

    private AltLoginServiceImpl service() {
        AltLoginServiceImpl service =
                new AltLoginServiceImpl(localStore.store(), injected::set, chain.config(), TestTransports.direct());
        service.deviceCodeTiming = new DeviceCodeTiming(SECOND_MILLIS, SLOW_DOWN_MILLIS);
        return service;
    }

    private LoginResult login(LoginMode mode) throws Exception {
        return service().loginDeviceCode(prompt, mode).get(10, TimeUnit.SECONDS);
    }

    @Test
    void anApprovedCodeLogsInAndStoresTheRefreshTokenLikeTheBrowserRoute() throws Exception {
        chain.deviceTokenSuccess();

        LoginResult result = login(LoginMode.ADD);

        assertTrue(result.success(), result.message());
        assertEquals("Alex", result.account().username());
        assertEquals(AccountType.MICROSOFT, result.account().type());
        assertEquals("Alex", injected.get().username());

        AltAccount persisted = localStore.reloadFromDiskAndFind(AuthChainServer.UUID);
        assertEquals("ms-refresh", persisted.refreshToken(), "the refresh token is what makes the account renewable");
        assertEquals("mc-access", persisted.accessToken());
    }

    @Test
    void theHostIsShownTheCodeAndTheRealVerificationAddress() throws Exception {
        chain.deviceTokenSuccess();

        login(LoginMode.DIRECT);

        assertEquals(1, prompts.get());
        assertEquals("ABCD-EFGH", shownCode.get());
        assertEquals("https://verify.example/device", shownUri.get(), "the address is passed through untouched");
        assertTrue(shownExpiry.get().isAfter(Instant.now()), "the expiry is an instant still ahead");
    }

    @Test
    void theRequestsCarryTheGrantTheProtocolNames() throws Exception {
        chain.deviceTokenSuccess();

        login(LoginMode.DIRECT);

        Map<String, String> request = chain.lastForm("/devicecode");
        assertEquals("test-client-id", request.get("client_id"));
        assertEquals(MicrosoftAuthConfig.DEFAULT_SCOPE, request.get("scope"));

        Map<String, String> poll = chain.lastForm("/devicetoken");
        assertEquals("urn:ietf:params:oauth:grant-type:device_code", poll.get("grant_type"));
        assertEquals("test-client-id", poll.get("client_id"));
        assertEquals("secret-device-code", poll.get("device_code"));
    }

    @Test
    void aPendingAuthorizationIsPolledUntilItIsApproved() throws Exception {
        chain.deviceTokenError("authorization_pending");
        chain.deviceTokenError("authorization_pending");
        chain.deviceTokenSuccess();

        LoginResult result = login(LoginMode.DIRECT);

        assertTrue(result.success(), result.message());
        assertEquals(3, chain.deviceTokenPolls());
        assertEquals(1, prompts.get(), "the code is shown once, not once per poll");
    }

    @Test
    void slowDownLengthensTheIntervalForEveryLaterPoll() throws Exception {
        chain.deviceTokenError("slow_down");
        chain.deviceTokenError("authorization_pending");
        chain.deviceTokenSuccess();

        LoginResult result = login(LoginMode.DIRECT);

        assertTrue(result.success(), result.message());
        assertEquals(3, chain.deviceTokenPolls());
        // A delay only ever runs long, so the floor is exact: the interval plus the slow-down increment.
        assertTrue(
                chain.millisBetweenPolls(1, 2) >= SECOND_MILLIS + SLOW_DOWN_MILLIS,
                "the poll after slow_down waited " + chain.millisBetweenPolls(1, 2) + "ms");
        assertTrue(
                chain.millisBetweenPolls(2, 3) >= SECOND_MILLIS + SLOW_DOWN_MILLIS,
                "the longer interval is kept, not applied once: " + chain.millisBetweenPolls(2, 3) + "ms");
    }

    @Test
    void aDeclinedCodeFailsAsDeclined() throws Exception {
        chain.deviceTokenError("authorization_pending");
        chain.deviceTokenError("authorization_declined");

        LoginResult result = login(LoginMode.ADD);

        assertFalse(result.success());
        assertEquals(Kind.DECLINED, result.failure().map(AltsFailure::kind).orElse(null));
        assertNull(injected.get(), "a declined sign-in installs nothing");
        assertEquals(2, chain.deviceTokenPolls(), "a refusal ends the polling");
    }

    @Test
    void anExpiredCodeFailsAsTimedOut() throws Exception {
        chain.deviceTokenError("expired_token");

        LoginResult result = login(LoginMode.DIRECT);

        assertFalse(result.success());
        assertEquals(Kind.TIMED_OUT, result.failure().map(AltsFailure::kind).orElse(null));
    }

    @Test
    void pollingStopsAtTheAdvertisedExpiryEvenIfTheServiceNeverSaysSo() throws Exception {
        chain.body(
                "/devicecode",
                "{\"device_code\":\"secret-device-code\",\"user_code\":\"ABCD-EFGH\","
                        + "\"verification_uri\":\"https://verify.example/device\",\"expires_in\":5,\"interval\":1}");
        chain.deviceTokenError("authorization_pending");

        LoginResult result = login(LoginMode.DIRECT);

        assertFalse(result.success());
        assertEquals(Kind.TIMED_OUT, result.failure().map(AltsFailure::kind).orElse(null));
        assertTrue(chain.deviceTokenPolls() <= 6, "no poll is sent after the code lapsed");
    }

    @Test
    void anAdvertisedIntervalCannotParkTheLogin() throws Exception {
        chain.body(
                "/devicecode",
                "{\"device_code\":\"secret-device-code\",\"user_code\":\"ABCD-EFGH\","
                        + "\"verification_uri\":\"https://verify.example/device\",\"expires_in\":900,"
                        + "\"interval\":9223372036854775807}");
        chain.deviceTokenSuccess();

        LoginResult result = login(LoginMode.DIRECT);

        assertTrue(result.success(), "the first poll must still happen within the longest interval allowed");
    }

    @Test
    void anAdvertisedLifetimeIsHeldToHalfAnHour() throws Exception {
        chain.body(
                "/devicecode",
                "{\"device_code\":\"secret-device-code\",\"user_code\":\"ABCD-EFGH\","
                        + "\"verification_uri\":\"https://verify.example/device\","
                        + "\"expires_in\":9223372036854775807,\"interval\":1}");
        chain.deviceTokenSuccess();
        Instant before = Instant.now();

        LoginResult result = login(LoginMode.DIRECT);

        assertTrue(result.success(), result.message());
        Instant latest = before.plusMillis(DeviceCodeTiming.MAX_LIFETIME_SECONDS * SECOND_MILLIS + 10_000L);
        assertTrue(shownExpiry.get().isAfter(before), "the expiry shown must not have overflowed into the past");
        assertTrue(shownExpiry.get().isBefore(latest), "nor may it run past the longest lifetime allowed");
    }

    @Test
    void advertisedTimingsAreClampedAndDefaulted() {
        assertEquals(DeviceCodeTiming.DEFAULT_INTERVAL_SECONDS, DeviceCodeTiming.intervalSeconds(0));
        assertEquals(DeviceCodeTiming.DEFAULT_INTERVAL_SECONDS, DeviceCodeTiming.intervalSeconds(-5));
        assertEquals(1, DeviceCodeTiming.intervalSeconds(1));
        assertEquals(5, DeviceCodeTiming.intervalSeconds(5));
        assertEquals(60, DeviceCodeTiming.intervalSeconds(61));
        assertEquals(60, DeviceCodeTiming.intervalSeconds(Long.MAX_VALUE));

        assertEquals(DeviceCodeTiming.DEFAULT_LIFETIME_SECONDS, DeviceCodeTiming.lifetimeSeconds(0));
        assertEquals(300, DeviceCodeTiming.lifetimeSeconds(300));
        assertEquals(1800, DeviceCodeTiming.lifetimeSeconds(1801));
        assertEquals(1800, DeviceCodeTiming.lifetimeSeconds(Long.MAX_VALUE));
    }

    @Test
    void anUnrecognisedCodeIsARejectedCredential() throws Exception {
        chain.deviceTokenError("bad_verification_code");

        LoginResult result = login(LoginMode.DIRECT);

        assertFalse(result.success());
        assertEquals(Kind.UNAUTHORIZED, result.failure().map(AltsFailure::kind).orElse(null));
    }

    @Test
    void cancellingTheLoginStopsThePolling() throws Exception {
        chain.deviceTokenError("authorization_pending");

        CompletableFuture<LoginResult> login = service().loginDeviceCode(prompt, LoginMode.DIRECT);
        waitUntil(() -> chain.deviceTokenPolls() >= 2);

        assertTrue(login.cancel(true));
        assertThrows(CancellationException.class, login::join);

        // Let a poll that was already on the wire land, then watch for several intervals.
        Thread.sleep(SECOND_MILLIS * 5);
        int afterCancel = chain.deviceTokenPolls();
        Thread.sleep(SECOND_MILLIS * 15);

        assertEquals(afterCancel, chain.deviceTokenPolls(), "a cancelled login must not keep polling");
        assertNull(injected.get());
    }

    @Test
    void aServiceThatRefusesToIssueACodeNeverPromptsTheHost() throws Exception {
        chain.fail("/devicecode", 429);

        LoginResult result = login(LoginMode.DIRECT);

        assertFalse(result.success());
        assertEquals(Kind.RATE_LIMITED, result.failure().map(AltsFailure::kind).orElse(null));
        assertEquals(0, prompts.get());
        assertEquals(0, chain.deviceTokenPolls());
    }

    @Test
    void aMissingConfigurationOrPromptIsReportedRatherThanThrown() throws Exception {
        LoginResult unconfigured = new AltLoginServiceImpl(
                        localStore.store(), injected::set, null, TestTransports.direct())
                .loginDeviceCode(prompt, LoginMode.DIRECT)
                .get();
        LoginResult noPrompt = service().loginDeviceCode(null, LoginMode.DIRECT).get();

        assertEquals(
                Kind.NOT_CONFIGURED,
                unconfigured.failure().map(AltsFailure::kind).orElse(null));
        assertEquals(
                Kind.INVALID_INPUT,
                noPrompt.failure().map(AltsFailure::kind).orElse(null),
                "a missing prompt is the caller's argument, not the host's configuration");
    }

    @Test
    void theFailureMessageNeverCarriesTheDeviceCode() throws Exception {
        chain.deviceTokenError("authorization_declined");

        LoginResult result = login(LoginMode.DIRECT);

        assertFalse(result.message().contains("secret-device-code"), result.message());
        assertFalse(result.message().contains("ABCD-EFGH"), result.message());
    }

    /**
     * A host's executor can be shut down while the runtime is still open. The next poll is then refused,
     * and the login must fail rather than wait for a poll that will never run.
     */
    @Test
    void aLoginWhoseExecutorIsShutDownBetweenPollsFails() throws Exception {
        chain.deviceTokenError("authorization_pending");
        ExecutorService host = Executors.newSingleThreadExecutor();
        HttpTransport transport = TestTransports.on(null, host);

        CompletableFuture<LoginResult> login = registering(transport).loginDeviceCode(prompt, LoginMode.DIRECT);
        waitUntil(() -> chain.deviceTokenPolls() >= 1);
        host.shutdown();

        assertFalse(login.get(10, TimeUnit.SECONDS).success(), "the login ended rather than hung");
        assertNull(injected.get());
    }

    /**
     * A device-code login registers its wait and each poll with the transport so close() can end them.
     * Once the login ends on its own, whichever way, nothing of it may stay registered.
     */
    @Test
    void aSucceededDeviceCodeLoginLeavesNothingRegistered() throws Exception {
        chain.deviceTokenError("authorization_pending");
        chain.deviceTokenError("authorization_pending");
        chain.deviceTokenSuccess();
        HttpTransport transport = TestTransports.direct();

        assertTrue(registering(transport)
                .loginDeviceCode(prompt, LoginMode.DIRECT)
                .get(10, TimeUnit.SECONDS)
                .success());

        // Unregistering is a dependent of the same future the result hangs off, and the JDK runs
        // dependents in no promised order, so it is waited for rather than read at once.
        waitUntil(() -> TestTransports.closerCount(transport) == 0);
    }

    @Test
    void aDeclinedDeviceCodeLoginLeavesNothingRegistered() throws Exception {
        chain.deviceTokenError("authorization_pending");
        chain.deviceTokenError("authorization_declined");
        HttpTransport transport = TestTransports.direct();

        assertFalse(registering(transport)
                .loginDeviceCode(prompt, LoginMode.DIRECT)
                .get(10, TimeUnit.SECONDS)
                .success());

        // Unregistering is a dependent of the same future the result hangs off, and the JDK runs
        // dependents in no promised order, so it is waited for rather than read at once.
        waitUntil(() -> TestTransports.closerCount(transport) == 0);
    }

    @Test
    void aCancelledDeviceCodeLoginLeavesNothingRegistered() throws Exception {
        chain.deviceTokenError("authorization_pending");
        HttpTransport transport = TestTransports.direct();
        CompletableFuture<LoginResult> login = registering(transport).loginDeviceCode(prompt, LoginMode.DIRECT);
        waitUntil(() -> chain.deviceTokenPolls() >= 2);
        assertTrue(TestTransports.closerCount(transport) > 0, "a pending login is registered");

        login.cancel(true);

        // The poll already scheduled fires, sees the login cancelled, and schedules nothing more.
        waitUntil(() -> TestTransports.closerCount(transport) == 0);
    }

    /** A device-code login service over {@code transport}, so the test can count what it registers. */
    private AltLoginServiceImpl registering(HttpTransport transport) {
        AltLoginServiceImpl service =
                new AltLoginServiceImpl(localStore.store(), injected::set, chain.config(), transport);
        service.deviceCodeTiming = new DeviceCodeTiming(SECOND_MILLIS, SLOW_DOWN_MILLIS);
        return service;
    }

    /**
     * A runtime closed while the user is still entering the code ends the login at once. Its own
     * executor refuses the next poll, and a wait the JDK's delayer could not hand over would otherwise
     * leave the future pending for good.
     */
    @Test
    void aLoginInFlightWhenTheRuntimeClosesResolves() throws Exception {
        chain.deviceTokenError("authorization_pending");
        ExecutorService owned =
                Executors.newThreadPerTaskExecutor(Thread.ofVirtual().factory());
        HttpTransport transport = TestTransports.on(null, owned);
        AltLoginServiceImpl service =
                new AltLoginServiceImpl(localStore.store(), injected::set, chain.config(), transport);
        // Real seconds, so the next poll is seconds away when the runtime closes.
        service.deviceCodeTiming = new DeviceCodeTiming(1000L, 5000L);

        CompletableFuture<LoginResult> login = service.loginDeviceCode(prompt, LoginMode.DIRECT);
        waitUntil(() -> prompts.get() == 1);
        transport.close();
        owned.shutdown();

        LoginResult result = login.get(2, TimeUnit.SECONDS);
        assertFalse(result.success(), "a closed runtime does not finish the sign-in");
        int polls = chain.deviceTokenPolls();
        Thread.sleep(300);
        assertEquals(polls, chain.deviceTokenPolls(), "and nothing polls after it closed");
        assertNull(injected.get());
    }

    @Test
    void aRoutedDeviceCodeLoginCarriesItsTagOnTheRequestAndEveryPoll() throws Exception {
        chain.deviceTokenError("authorization_pending");
        chain.deviceTokenError("authorization_pending");
        chain.deviceTokenSuccess();
        List<NetworkScope> scopes = new CopyOnWriteArrayList<>();
        AltLoginServiceImpl service = new AltLoginServiceImpl(
                localStore.store(), injected::set, chain.config(), TestTransports.through(scope -> {
                    scopes.add(scope);
                    return ProxyRoute.direct();
                }));
        service.deviceCodeTiming = new DeviceCodeTiming(SECOND_MILLIS, SLOW_DOWN_MILLIS);

        LoginResult result = service.routed("pool-7")
                .loginDeviceCode(prompt, LoginMode.DIRECT)
                .get(10, TimeUnit.SECONDS);

        assertTrue(result.success(), result.message());
        assertEquals(3, chain.deviceTokenPolls());
        // The code request, three polls, Xbox Live, XSTS, the Minecraft login and the profile.
        assertEquals(8, scopes.size(), scopes.toString());
        for (NetworkScope scope : scopes) {
            assertEquals(Optional.of("pool-7"), scope.routeTag(), "a request left without the tag: " + scope);
        }
    }

    private static void waitUntil(java.util.function.BooleanSupplier condition) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError("condition was not met in time");
            }
            Thread.sleep(5);
        }
    }
}

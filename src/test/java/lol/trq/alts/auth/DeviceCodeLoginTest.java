package lol.trq.alts.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import lol.trq.alts.auth.AltLoginCallback.FailureReason;
import lol.trq.alts.auth.AltLoginCallback.LoginResult;
import lol.trq.alts.auth.MicrosoftAuthUtil.DeviceCodeTiming;
import lol.trq.alts.model.AccountType;
import lol.trq.alts.model.AltAccount;
import lol.trq.alts.model.LoginMode;
import lol.trq.alts.model.SessionData;
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
class DeviceCodeLoginTest {

    private static final long SECOND_MILLIS = 20L;
    private static final long SLOW_DOWN_MILLIS = 150L;

    @TempDir
    Path vaultDir;

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
        AltStoreTestSupport.bindTo(vaultDir);
        chain = new AuthChainServer();
    }

    @AfterEach
    void tearDown() {
        chain.close();
    }

    private AltLoginServiceImpl service() {
        AltLoginServiceImpl service = new AltLoginServiceImpl(injected::set, chain.config());
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

        AltAccount persisted = AltStoreTestSupport.reloadFromDiskAndFind(AuthChainServer.UUID);
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
        assertEquals(FailureReason.DECLINED, result.reason());
        assertNull(injected.get(), "a declined sign-in installs nothing");
        assertEquals(2, chain.deviceTokenPolls(), "a refusal ends the polling");
    }

    @Test
    void anExpiredCodeFailsAsTimedOut() throws Exception {
        chain.deviceTokenError("expired_token");

        LoginResult result = login(LoginMode.DIRECT);

        assertFalse(result.success());
        assertEquals(FailureReason.TIMED_OUT, result.reason());
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
        assertEquals(FailureReason.TIMED_OUT, result.reason());
        assertTrue(chain.deviceTokenPolls() <= 6, "no poll is sent after the code lapsed");
    }

    @Test
    void anUnrecognisedCodeIsARejectedCredential() throws Exception {
        chain.deviceTokenError("bad_verification_code");

        LoginResult result = login(LoginMode.DIRECT);

        assertFalse(result.success());
        assertEquals(FailureReason.INVALID_TOKEN, result.reason());
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
        assertEquals(FailureReason.RATE_LIMITED, result.reason());
        assertEquals(0, prompts.get());
        assertEquals(0, chain.deviceTokenPolls());
    }

    @Test
    void aMissingConfigurationOrPromptIsReportedRatherThanThrown() throws Exception {
        LoginResult unconfigured = new AltLoginServiceImpl(injected::set, null)
                .loginDeviceCode(prompt, LoginMode.DIRECT)
                .get();
        LoginResult noPrompt = service().loginDeviceCode(null, LoginMode.DIRECT).get();

        assertEquals(FailureReason.NOT_CONFIGURED, unconfigured.reason());
        assertEquals(FailureReason.NOT_CONFIGURED, noPrompt.reason());
    }

    @Test
    void theFailureMessageNeverCarriesTheDeviceCode() throws Exception {
        chain.deviceTokenError("authorization_declined");

        LoginResult result = login(LoginMode.DIRECT);

        assertFalse(result.message().contains("secret-device-code"), result.message());
        assertFalse(result.message().contains("ABCD-EFGH"), result.message());
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

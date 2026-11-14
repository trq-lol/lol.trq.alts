package lol.trq.alts.internal.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import lol.trq.alts.AltsFailure;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.auth.LoginResult;
import lol.trq.alts.auth.MicrosoftAuthConfig;
import lol.trq.alts.auth.XstsError;
import lol.trq.alts.internal.net.TestTransports;
import lol.trq.alts.model.LoginMode;
import lol.trq.alts.model.SessionData;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The corners of the login surface where a result used to be wrong rather than missing: a failure
 * reported under the wrong reason, and a "never throws" route that threw.
 */
class LoginHardeningTest {

    private static final long NOW = 1_800_000_000_000L;

    @TempDir
    Path vaultDir;

    private AccountStoreTestSupport localStore;

    private AuthChainServer chain;
    private final AtomicReference<SessionData> injected = new AtomicReference<>();

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
        return new AltLoginServiceImpl(
                localStore.store(),
                injected::set,
                chain.config(),
                TestTransports.direct(),
                Clock.fixed(Instant.ofEpochMilli(NOW), ZoneOffset.UTC));
    }

    @Test
    void loggingIntoNoAccountFailsInsteadOfThrowing() throws Exception {
        LoginResult result = service().loginAccount(null).get(10, TimeUnit.SECONDS);

        assertFalse(result.success());
        assertNull(injected.get());
    }

    @Test
    void unreadableCookieTextIsARejectedCredential() throws Exception {
        LoginResult result =
                service().loginCookie("nothing useful here", LoginMode.DIRECT).get(10, TimeUnit.SECONDS);

        assertFalse(result.success());
        assertEquals(Kind.UNAUTHORIZED, result.failure().map(AltsFailure::kind).orElse(null));
    }

    @Test
    void aMissingCookieFileIsReportedWithoutItsDirectory() throws Exception {
        Path missing = vaultDir.resolve("exports").resolve("cookies.txt");

        LoginResult result =
                service().loginCookieFile(missing, LoginMode.DIRECT).get(10, TimeUnit.SECONDS);

        assertFalse(result.success());
        assertEquals(Kind.UNAUTHORIZED, result.failure().map(AltsFailure::kind).orElse(null));
        assertFalse(result.message().contains(vaultDir.toString()), "an absolute path leaked: " + result.message());
    }

    /** An offline name that is no name is input the caller gave, refused before anything happens. */
    @Test
    void anOfflineNameThatIsNoNameIsInvalidInput() throws Exception {
        for (String name : new String[] {"", "!!!", "a_name_far_longer_than_sixteen"}) {
            LoginResult result = service().loginOffline(name, LoginMode.DIRECT).get(10, TimeUnit.SECONDS);
            assertEquals(Kind.INVALID_INPUT, result.failure().orElseThrow().kind(), name);
        }
    }

    /**
     * The browser sign-in's callback listener gives up with the JDK's TimeoutException, wrapped by the
     * stage it completes. That is the user not finishing the sign-in, not an outage.
     */
    @Test
    void aSignInThatWasNeverFinishedIsTimedOut() {
        LoginResult result = AltLoginServiceImpl.classifiedFailure(
                "Microsoft Auth",
                new java.util.concurrent.CompletionException(new java.util.concurrent.TimeoutException()));

        assertEquals(Kind.TIMED_OUT, result.failure().orElseThrow().kind());
    }

    @Test
    void aResultCarriesAnXboxCauseOnlyWhenThereWasOne() {
        LoginResult plain = LoginResult.failure(Kind.UNAUTHORIZED, "refused");
        LoginResult xbox = LoginResult.failure(AltsFailure.xboxDenied("denied", XstsError.CHILD_ACCOUNT));

        assertNull(plain.failure().flatMap(AltsFailure::xstsError).orElse(null));
        assertEquals(
                XstsError.CHILD_ACCOUNT,
                xbox.failure().flatMap(AltsFailure::xstsError).orElse(null));
    }

    @Test
    void theDeviceCodeEndpointsDefaultAndSurviveTheOtherCopyMethods() {
        MicrosoftAuthConfig defaults = MicrosoftAuthConfig.of("app");
        assertEquals(MicrosoftAuthConfig.DEFAULT_DEVICE_CODE_URL, defaults.deviceCodeUrl());
        assertEquals(MicrosoftAuthConfig.DEFAULT_DEVICE_TOKEN_URL, defaults.deviceTokenUrl());

        MicrosoftAuthConfig custom = defaults.withDeviceCodeEndpoints("https://id.example/code", null)
                .withScope("custom")
                .withClientId("other")
                .withRedirectPath("/cb")
                .withEndpoints(null, null, null, null, null, null);
        assertEquals("https://id.example/code", custom.deviceCodeUrl());
        assertEquals(MicrosoftAuthConfig.DEFAULT_DEVICE_TOKEN_URL, custom.deviceTokenUrl());

        MicrosoftAuthConfig positional =
                new MicrosoftAuthConfig("app", null, null, null, null, null, null, null, null, null, null);
        assertEquals(defaults, positional, "the eleven-argument constructor still exists and defaults the rest");
        assertEquals(
                MicrosoftAuthConfig.DEFAULT_DEVICE_CODE_URL,
                MicrosoftAuthConfig.legacyMsa("app").deviceCodeUrl());
    }

    @Test
    void uuidsAndTokenPayloadsAreReadOneWay() {
        assertEquals(AuthChainServer.UUID, AuthFormats.dashedUuid(AuthChainServer.UNDASHED_UUID));
        assertEquals(AuthChainServer.UUID, AuthFormats.dashedUuid(AuthChainServer.UUID));

        String payload = "{\"exp\":1800003600,\"note\":\"??>>\"}";
        String urlSafe =
                Base64.getUrlEncoder().withoutPadding().encodeToString(payload.getBytes(StandardCharsets.UTF_8));
        String standardPadded = Base64.getEncoder().encodeToString(payload.getBytes(StandardCharsets.UTF_8));

        assertEquals(payload, AuthFormats.jwtPayload("h." + urlSafe + ".s"));
        assertEquals(payload, AuthFormats.jwtPayload("h." + standardPadded + ".s"));
        assertEquals(1_800_003_600_000L, TokenExpiry.jwtExpiryMillis("eyJ." + standardPadded + ".s"));
    }
}

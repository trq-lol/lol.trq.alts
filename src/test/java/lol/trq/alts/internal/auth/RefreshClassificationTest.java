package lol.trq.alts.internal.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import lol.trq.alts.AltsFailure;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.auth.AccountStatus;
import lol.trq.alts.auth.LoginResult;
import lol.trq.alts.auth.MicrosoftAuthConfig;
import lol.trq.alts.internal.net.TestTransports;
import lol.trq.alts.model.AccountType;
import lol.trq.alts.model.AltAccount;
import lol.trq.alts.model.LoginMode;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Redeeming a refresh token is only the first step of a renewal. Whichever later step fails, the reason
 * reported is that step's own, on the import route and on the stored-account route alike: a host told
 * "network" retries, and retrying an account Xbox Live or Minecraft services turned away spends a token
 * rotation each time for nothing.
 */
@org.junit.jupiter.api.Timeout(value = 60, unit = java.util.concurrent.TimeUnit.SECONDS)
class RefreshClassificationTest {

    private static final long NOW = 1_800_000_000_000L;
    private static final String UUID = "00000000-0000-4000-8000-0000000000f1";

    @TempDir
    Path vaultDir;

    private AccountStoreTestSupport localStore;

    private HttpServer server;
    private MicrosoftAuthConfig config;

    @BeforeEach
    void setUp() throws IOException {
        localStore = AccountStoreTestSupport.openIn(vaultDir);
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        answer("/token", 200, "{\"access_token\":\"ms-access\",\"refresh_token\":\"rotated\",\"expires_in\":3600}");
        answer("/xbl", 200, "{\"Token\":\"xbl\"}");
        answer("/xsts", 200, "{\"Token\":\"xsts\",\"DisplayClaims\":{\"xui\":[{\"uhs\":\"hash\"}]}}");
        answer("/mclogin", 200, "{\"access_token\":\"mc-access\",\"expires_in\":86400}");
        answer("/mcprofile", 200, "{\"id\":\"000000000000400080000000000000f1\",\"name\":\"Alex\"}");
        server.start();

        String base = "http://" + InetAddress.getLoopbackAddress().getHostAddress() + ":"
                + server.getAddress().getPort();
        config = MicrosoftAuthConfig.of("test-client-id")
                .withEndpoints(
                        base + "/authorize",
                        base + "/token",
                        base + "/xbl",
                        base + "/xsts",
                        base + "/mclogin",
                        base + "/mcprofile");
    }

    @AfterEach
    void tearDown() {
        localStore.close();
        server.stop(0);
    }

    private void answer(String path, int status, String body) {
        try {
            server.removeContext(path);
        } catch (IllegalArgumentException notRegisteredYet) {
            // First registration.
        }
        server.createContext(path, exchange -> respond(exchange, status, body));
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    private LoginResult imported() throws Exception {
        return new AltLoginServiceImpl(localStore.store(), session -> {}, config, TestTransports.direct())
                .loginRefreshToken("M.C123_imported", LoginMode.DIRECT)
                .get();
    }

    private AccountStatus renewed() throws Exception {
        AltAccount account = AltAccount.of(UUID, "Alex", "stored-access", AccountType.MICROSOFT)
                .withTokens("stored-access", "stored-refresh", NOW - 1);
        localStore.seed(account);
        return new AltAccountServiceImpl(
                        localStore.store(),
                        config,
                        TestTransports.direct(),
                        Clock.fixed(Instant.ofEpochMilli(NOW), ZoneOffset.UTC))
                .refresh(account)
                .get();
    }

    private void assertBothRoutesReport(Kind expected) throws Exception {
        LoginResult login = imported();
        assertFalse(login.success());
        assertEquals(expected, login.failure().map(AltsFailure::kind).orElse(null), "the import route");

        AccountStatus status = renewed();
        assertFalse(status.usable());
        assertEquals(expected, status.failure().map(AltsFailure::kind).orElse(null), "the stored-account route");
        assertEquals(
                "rotated",
                localStore.find(UUID).refreshToken(),
                "a failure after the token was accepted keeps the credential, the rotated one it was issued");
    }

    @Test
    void anXboxLiveRefusalIsReportedAsOne() throws Exception {
        answer("/xsts", 401, "{\"XErr\":2148916233}");

        assertBothRoutesReport(Kind.XBOX_DENIED);
    }

    @Test
    void anAccountWithNoProfileIsReportedAsNotEntitled() throws Exception {
        answer("/mcprofile", 404, "{}");

        assertBothRoutesReport(Kind.NOT_ENTITLED);
    }

    @Test
    void aThrottleAfterRedemptionIsReportedAsARateLimit() throws Exception {
        answer("/xbl", 429, "{}");

        assertBothRoutesReport(Kind.RATE_LIMITED);
    }

    /**
     * Minecraft services answers {@code login_with_xbox} with a {@code 403} when the host's client
     * registration is not allowed to use it, whoever signs in: the host's configuration is what has to
     * change, so it is reported as {@code NOT_CONFIGURED}, never as a refused credential.
     */
    @Test
    void aForbiddenMinecraftServicesLoginIsReportedAsNotConfigured() throws Exception {
        answer("/mclogin", 403, "{}");

        assertBothRoutesReport(Kind.NOT_CONFIGURED);
    }

    @Test
    void aRefusalFromMinecraftServicesIsReportedAsARefusal() throws Exception {
        answer("/mclogin", 401, "{}");

        assertBothRoutesReport(Kind.UNAUTHORIZED);
    }

    @Test
    void anOutageAfterRedemptionIsStillAnOutage() throws Exception {
        answer("/mclogin", 503, "{}");

        assertBothRoutesReport(Kind.NETWORK);
    }

    @Test
    void aSuccessfulAnswerWithNoAccessTokenIsAFailedStepNotAnOutage() throws Exception {
        answer("/token", 200, "{\"refresh_token\":\"rotated\"}");

        LoginResult login = imported();
        assertFalse(login.success());
        assertEquals(
                Kind.PROTOCOL,
                login.failure().map(AltsFailure::kind).orElse(null),
                "the service answered; calling that an outage sends the host into a retry loop");
        assertNotEquals(
                Kind.REAUTH_REQUIRED,
                login.failure().map(AltsFailure::kind).orElse(null),
                "and nothing said the token is spent");

        AccountStatus status = renewed();
        assertFalse(status.usable());
        assertEquals(Kind.PROTOCOL, status.failure().map(AltsFailure::kind).orElse(null));
        assertEquals("stored-refresh", localStore.find(UUID).refreshToken());
    }

    @Test
    void aNullAccessTokenIsTheSameFailedStep() throws Exception {
        answer("/token", 200, "{\"access_token\":null,\"refresh_token\":\"rotated\"}");

        assertEquals(Kind.PROTOCOL, imported().failure().map(AltsFailure::kind).orElse(null));
        assertEquals(Kind.PROTOCOL, renewed().failure().map(AltsFailure::kind).orElse(null));
    }

    @Test
    void aNullRotatedTokenKeepsTheOneThatWasRedeemed() throws Exception {
        answer("/token", 200, "{\"access_token\":\"ms-access\",\"refresh_token\":null}");

        AccountStatus status = renewed();

        assertTrue(status.usable(), "the access token was issued, so the renewal worked");
        assertEquals(
                "stored-refresh",
                localStore.find(UUID).refreshToken(),
                "no new refresh token was issued, so the one just redeemed is still the credential");
    }
}

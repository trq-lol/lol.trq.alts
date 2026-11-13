package lol.trq.alts.auth;

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
import lol.trq.alts.auth.AltLoginCallback.FailureReason;
import lol.trq.alts.auth.AltLoginCallback.LoginResult;
import lol.trq.alts.model.AccountType;
import lol.trq.alts.model.AltAccount;
import lol.trq.alts.model.LoginMode;
import lol.trq.alts.net.TestTransports;
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

    private void assertBothRoutesReport(FailureReason expected) throws Exception {
        LoginResult login = imported();
        assertFalse(login.success());
        assertEquals(expected, login.reason(), "the import route");

        AccountStatus status = renewed();
        assertFalse(status.usable());
        assertEquals(expected, status.reason(), "the stored-account route");
        assertEquals(
                "stored-refresh",
                localStore.find(UUID).refreshToken(),
                "a failure after the token was accepted must not cost the stored credential");
    }

    @Test
    void anXboxLiveRefusalIsReportedAsOne() throws Exception {
        answer("/xsts", 401, "{\"XErr\":2148916233}");

        assertBothRoutesReport(FailureReason.XBOX_DENIED);
    }

    @Test
    void anAccountWithNoProfileIsReportedAsNotEntitled() throws Exception {
        answer("/mcprofile", 404, "{}");

        assertBothRoutesReport(FailureReason.NOT_ENTITLED);
    }

    @Test
    void aThrottleAfterRedemptionIsReportedAsARateLimit() throws Exception {
        answer("/xbl", 429, "{}");

        assertBothRoutesReport(FailureReason.RATE_LIMITED);
    }

    @Test
    void aRefusalFromMinecraftServicesIsReportedAsARefusal() throws Exception {
        answer("/mclogin", 403, "{}");

        assertBothRoutesReport(FailureReason.INVALID_TOKEN);
    }

    @Test
    void anOutageAfterRedemptionIsStillAnOutage() throws Exception {
        answer("/mclogin", 503, "{}");

        assertBothRoutesReport(FailureReason.NETWORK);
    }

    @Test
    void aSuccessfulAnswerWithNoAccessTokenIsAFailedStepNotAnOutage() throws Exception {
        answer("/token", 200, "{\"refresh_token\":\"rotated\"}");

        LoginResult login = imported();
        assertFalse(login.success());
        assertNotEquals(
                FailureReason.NETWORK,
                login.reason(),
                "the service answered; calling that an outage sends the host into a retry loop");
        assertNotEquals(FailureReason.REAUTH_REQUIRED, login.reason(), "and nothing said the token is spent");

        AccountStatus status = renewed();
        assertFalse(status.usable());
        assertNotEquals(FailureReason.NETWORK, status.reason());
        assertEquals("stored-refresh", localStore.find(UUID).refreshToken());
    }

    @Test
    void aNullAccessTokenIsTheSameFailedStep() throws Exception {
        answer("/token", 200, "{\"access_token\":null,\"refresh_token\":\"rotated\"}");

        assertNotEquals(FailureReason.NETWORK, imported().reason());
        assertNotEquals(FailureReason.NETWORK, renewed().reason());
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

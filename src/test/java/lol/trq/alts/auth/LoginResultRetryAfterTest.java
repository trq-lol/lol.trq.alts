package lol.trq.alts.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import lol.trq.alts.auth.AltLoginCallback.FailureReason;
import lol.trq.alts.auth.AltLoginCallback.LoginResult;
import lol.trq.alts.model.LoginMode;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * A throttled login says how long to wait when the service did. A host importing a list of credentials
 * needs the number, not just the fact: without it the only choices are to give up or to guess.
 */
class LoginResultRetryAfterTest {

    @TempDir
    Path vaultDir;

    private HttpServer server;
    private MicrosoftAuthConfig config;
    private final Map<String, Integer> statuses = new ConcurrentHashMap<>();
    private final Map<String, String> waits = new ConcurrentHashMap<>();

    @BeforeEach
    void setUp() throws IOException {
        AltStoreTestSupport.bindTo(vaultDir);
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        Map<String, String> bodies = Map.of(
                "/token", "{\"access_token\":\"ms-access\",\"refresh_token\":\"rotated\",\"expires_in\":3600}",
                "/xbl", "{\"Token\":\"xbl\"}",
                "/xsts", "{\"Token\":\"xsts\",\"DisplayClaims\":{\"xui\":[{\"uhs\":\"hash\"}]}}",
                "/mclogin", "{\"access_token\":\"mc-access\",\"expires_in\":86400}",
                "/mcprofile", "{\"id\":\"000000000000400080000000000000f1\",\"name\":\"Alex\"}");
        bodies.forEach((path, body) -> server.createContext(path, exchange -> {
            int status = statuses.getOrDefault(path, 200);
            if (waits.containsKey(path)) {
                exchange.getResponseHeaders().add("Retry-After", waits.get(path));
            }
            byte[] bytes = (status == 200 ? body : "{}").getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        }));
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
        server.stop(0);
    }

    private void throttle(String path, String wait) {
        statuses.put(path, 429);
        if (wait != null) {
            waits.put(path, wait);
        }
    }

    private LoginResult importRefreshToken() throws Exception {
        return new AltLoginServiceImpl(session -> {}, config)
                .loginRefreshToken("M.C123_imported", LoginMode.DIRECT)
                .get();
    }

    @Test
    void aThrottledRefreshTokenImportCarriesTheStatedWait() throws Exception {
        throttle("/token", "12");

        LoginResult result = importRefreshToken();

        assertTrue(result.rateLimited());
        assertEquals(Duration.ofSeconds(12), result.retryAfter());
    }

    @Test
    void aThrottleAfterTheTokenWasRedeemedCarriesItsWaitToo() throws Exception {
        throttle("/xbl", "7");

        LoginResult result = importRefreshToken();

        assertTrue(result.rateLimited());
        assertEquals(Duration.ofSeconds(7), result.retryAfter());
    }

    @Test
    void aThrottledSessionTokenImportCarriesTheStatedWait() throws Exception {
        throttle("/mcprofile", "30");

        LoginResult result = new AltLoginServiceImpl(session -> {}, config)
                .loginSession("not-a-jwt-so-the-profile-is-asked", LoginMode.DIRECT)
                .get();

        assertTrue(result.rateLimited());
        assertEquals(Duration.ofSeconds(30), result.retryAfter());
    }

    @Test
    void aThrottleThatNamesNoWaitIsStillARateLimit() throws Exception {
        throttle("/token", null);

        LoginResult result = importRefreshToken();

        assertTrue(result.rateLimited(), "the reason is what says to stop; the wait is extra");
        assertNull(result.retryAfter());
    }

    @Test
    void aResultThatIsNotAThrottleCarriesNoWait() throws Exception {
        statuses.put("/mclogin", 403);

        LoginResult refused = importRefreshToken();

        assertFalse(refused.rateLimited());
        assertNull(refused.retryAfter());
        assertNull(LoginResult.failure("refused", FailureReason.INVALID_TOKEN).retryAfter());
        assertNull(new LoginResult(false, "four arguments", null, FailureReason.UNKNOWN).retryAfter());
        assertNull(new LoginResult(false, "five arguments", null, FailureReason.XBOX_DENIED, XstsError.CHILD_ACCOUNT)
                .retryAfter());
        assertEquals(
                Duration.ofSeconds(3),
                LoginResult.failure("slow down", FailureReason.RATE_LIMITED, null, Duration.ofSeconds(3))
                        .retryAfter());
    }
}

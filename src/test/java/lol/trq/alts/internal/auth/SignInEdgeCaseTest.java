package lol.trq.alts.internal.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Base64;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.auth.LoginResult;
import lol.trq.alts.auth.MicrosoftAuthConfig;
import lol.trq.alts.auth.XstsError;
import lol.trq.alts.internal.net.HttpTransport;
import lol.trq.alts.internal.net.TestTransports;
import lol.trq.alts.model.LoginMode;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Answers at the edges of the sign-in chain, each classified as what it is: a success that carries
 * nothing usable is a protocol failure, not a refusal of the account; an Xbox Live refusal keeps the
 * reason its code states; a throttle keeps its stated wait on every route; and a sign-in that could not
 * be installed is not saved.
 */
@org.junit.jupiter.api.Timeout(value = 60, unit = TimeUnit.SECONDS)
class SignInEdgeCaseTest {

    @TempDir
    Path dir;

    private AccountStoreTestSupport local;
    private AuthChainServer chain;
    private final HttpTransport http = TestTransports.direct();

    @BeforeEach
    void setUp() throws Exception {
        local = AccountStoreTestSupport.openIn(dir);
        chain = new AuthChainServer();
    }

    @AfterEach
    void tearDown() {
        local.close();
        chain.close();
        http.close();
    }

    private AltsFailure renewalFailure() {
        ExecutionException thrown = assertThrows(
                ExecutionException.class,
                () -> new MicrosoftAuthUtil(http)
                        .authenticateWithRefreshToken(chain.config(), "stored-refresh")
                        .get(10, TimeUnit.SECONDS));
        return assertInstanceOf(AltsException.class, thrown.getCause()).failure();
    }

    @Test
    void anXstsSuccessWithNoBodyIsAProtocolFailureNotAnXboxRefusal() {
        chain.body("/xsts", "not json at all");

        AltsFailure failure = renewalFailure();

        assertEquals(Kind.PROTOCOL, failure.kind());
        assertTrue(failure.xstsError().isEmpty());
    }

    @Test
    void anXstsSuccessWithAnUnusableBodyIsAProtocolFailure() {
        chain.body("/xsts", "{\"Token\":\"xsts\"}");

        assertEquals(Kind.PROTOCOL, renewalFailure().kind());
    }

    @Test
    void theFurtherXstsCodesAreDecodedAndStayXboxDenied() {
        for (long code : new long[] {2148916227L, 2148916229L, 2148916234L}) {
            chain.fail("/xsts", 401, "{\"XErr\":" + code + "}");

            AltsFailure failure = renewalFailure();

            assertEquals(Kind.XBOX_DENIED, failure.kind(), String.valueOf(code));
            XstsError decoded = failure.xstsError().orElseThrow();
            assertFalse(decoded == XstsError.UNKNOWN, code + " is a stated reason, not an unknown one");
            assertEquals(code, decoded.code());
        }
    }

    @Test
    void aProfileNamingNullForItsNameOrIdIsAProtocolFailure() throws Exception {
        AltLoginServiceImpl logins = new AltLoginServiceImpl(local.store(), session -> {}, chain.config(), http);
        for (String profile : new String[] {
            "{\"id\":null,\"name\":\"Alex\"}", "{\"id\":\"" + AuthChainServer.UNDASHED_UUID + "\",\"name\":null}"
        }) {
            chain.body("/mcprofile", profile);

            LoginResult session = logins.loginSession("not-a-jwt-session-token", LoginMode.DIRECT)
                    .get(10, TimeUnit.SECONDS);
            LoginResult refreshed =
                    logins.loginRefreshToken("M.refresh", LoginMode.DIRECT).get(10, TimeUnit.SECONDS);

            assertEquals(Optional.of(Kind.PROTOCOL), session.failure().map(AltsFailure::kind), profile);
            assertEquals(Optional.of(Kind.PROTOCOL), refreshed.failure().map(AltsFailure::kind), profile);
        }
    }

    @Test
    void aThrottledProfileHopOnTheCookieRouteKeepsItsStatedWait() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/mclogin", exchange -> {
            byte[] bytes = "{\"access_token\":\"mc-access\"}".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        server.createContext("/mcprofile", exchange -> {
            exchange.getResponseHeaders().set("Retry-After", "7");
            byte[] bytes = "{}".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(429, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        server.start();
        try {
            String base = "http://" + InetAddress.getLoopbackAddress().getHostAddress() + ":"
                    + server.getAddress().getPort();
            MicrosoftAuthConfig config = MicrosoftAuthConfig.of("test-client")
                    .withEndpoints(
                            base + "/authorize",
                            base + "/token",
                            base + "/xbl",
                            base + "/xsts",
                            base + "/mclogin",
                            base + "/mcprofile");
            String bundle = "[{\"Item1\":\"rp://api.minecraftservices.com/\",\"Item2\":{\"Token\":\"xsts-token\","
                    + "\"DisplayClaims\":{\"xui\":[{\"uhs\":\"hash\"}]}}}]";
            String landing = "https://www.minecraft.net/en-us/login#state=login&accessToken="
                    + Base64.getEncoder().encodeToString(bundle.getBytes(StandardCharsets.UTF_8));

            AltsException thrown = assertThrows(
                    AltsException.class, () -> new CookieAuthUtil(http).completeFromLanding(landing, config, null));

            assertEquals(Kind.RATE_LIMITED, thrown.failure().kind());
            assertEquals(Optional.of(Duration.ofSeconds(7)), thrown.failure().retryAfter());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void aThrottledRedirectHopOnTheCookieRouteKeepsItsStatedWait() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/hop", exchange -> {
            exchange.getResponseHeaders().set("Retry-After", "9");
            exchange.sendResponseHeaders(429, -1);
            exchange.close();
        });
        server.start();
        try {
            String hop = "http://" + InetAddress.getLoopbackAddress().getHostAddress() + ":"
                    + server.getAddress().getPort() + "/hop";

            AltsException thrown =
                    assertThrows(AltsException.class, () -> new CookieAuthUtil(http).followRedirect(hop, null, null));

            assertEquals(Kind.RATE_LIMITED, thrown.failure().kind());
            assertEquals(Optional.of(Duration.ofSeconds(9)), thrown.failure().retryAfter());
        } finally {
            server.stop(0);
        }
    }
}

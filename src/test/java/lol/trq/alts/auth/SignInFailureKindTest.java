package lol.trq.alts.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import com.sun.net.httpserver.HttpServer;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import lol.trq.alts.AltsFailure;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.internal.net.TestTransports;
import lol.trq.alts.model.AccountType;
import lol.trq.alts.model.AltAccount;
import lol.trq.alts.model.LoginMode;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The freeze's per-service classification test for sign-in and account checks: each failing answer a
 * loopback service can give surfaces as one expected {@link Kind}, with the stated wait where there was
 * one, and with no transport text, token, response text or path in the message.
 */
class SignInFailureKindTest {

    private static final String SESSION_TOKEN = "eyJhbGciOiJub25lIn0.eyJzZWNyZXQiOiJ0b2tlbiJ9.secret-signature";
    private static final String REFRESH_TOKEN = "M.secret-refresh-token";
    private static final String HOSTILE_BODY = "{\"error\":\"invalid_request\",\"errorMessage\":\"echo " + SESSION_TOKEN
            + " " + REFRESH_TOKEN + " at D:/data/someone/secret-file\"}";

    @TempDir
    Path dir;

    private AccountStoreTestSupport localStore;
    private HttpServer server;
    private volatile int status;
    private volatile String body;
    private volatile String retryAfter;
    private String base;

    @BeforeEach
    void setUp() throws Exception {
        localStore = AccountStoreTestSupport.openIn(dir);
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", exchange -> {
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            if (retryAfter != null) {
                exchange.getResponseHeaders().set("Retry-After", retryAfter);
            }
            exchange.sendResponseHeaders(status, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        server.start();
        base = "http://" + InetAddress.getLoopbackAddress().getHostAddress() + ":"
                + server.getAddress().getPort();
    }

    @AfterEach
    void tearDown() {
        localStore.close();
        server.stop(0);
    }

    private static MicrosoftAuthConfig config(String base) {
        return MicrosoftAuthConfig.of("test-client")
                .withEndpoints(
                        base + "/authorize",
                        base + "/token",
                        base + "/xbl",
                        base + "/xsts",
                        base + "/mclogin",
                        base + "/mcprofile");
    }

    private AltLoginServiceImpl service(String base) {
        return new AltLoginServiceImpl(localStore.store(), session -> {}, config(base), TestTransports.direct());
    }

    private void answer(int status, String body, String retryAfter) {
        this.status = status;
        this.body = body;
        this.retryAfter = retryAfter;
    }

    private void assertClean(AltsFailure failure) {
        String message = failure.message();
        for (String forbidden : new String[] {
            "secret", "eyJ", "M.", "someone", dir.toString(), "Exception", "java.", "127.0.0.1", "errorMessage"
        }) {
            assertFalse(message.contains(forbidden), "the message carries '" + forbidden + "': " + message);
        }
    }

    /** A session sign-in and a check both ask the profile endpoint; both must classify alike. */
    private void assertProfileAnswer(Kind kind, Optional<Duration> wait) throws Exception {
        LoginResult login =
                service(base).loginSession(SESSION_TOKEN, LoginMode.DIRECT).get(10, TimeUnit.SECONDS);
        AltsFailure loginFailure = login.failure().orElseThrow();
        assertEquals(kind, loginFailure.kind(), "session sign-in");
        assertEquals(wait, loginFailure.retryAfter(), "session sign-in");
        assertClean(loginFailure);

        AltAccount stored =
                AltAccount.of("069a79f4-44e9-4726-a5be-fca90e38aaf5", "Alex", SESSION_TOKEN, AccountType.SESSION);
        AccountStatus checked = new AltAccountServiceImpl(localStore.store(), config(base), TestTransports.direct())
                .check(stored)
                .get(10, TimeUnit.SECONDS);
        AltsFailure checkFailure = checked.failure().orElseThrow();
        assertEquals(kind, checkFailure.kind(), "check");
        assertEquals(wait, checkFailure.retryAfter(), "check");
        assertClean(checkFailure);
    }

    private AltsFailure refreshAnswer() throws Exception {
        LoginResult login =
                service(base).loginRefreshToken(REFRESH_TOKEN, LoginMode.DIRECT).get(10, TimeUnit.SECONDS);
        AltsFailure failure = login.failure().orElseThrow();
        assertClean(failure);
        return failure;
    }

    @Test
    void aRefusedSessionTokenIsUnauthorized() throws Exception {
        answer(401, HOSTILE_BODY, null);
        assertProfileAnswer(Kind.UNAUTHORIZED, Optional.empty());
        answer(403, HOSTILE_BODY, null);
        assertProfileAnswer(Kind.UNAUTHORIZED, Optional.empty());
    }

    @Test
    void anAccountWithNoProfileIsNotEntitled() throws Exception {
        answer(404, HOSTILE_BODY, null);
        assertProfileAnswer(Kind.NOT_ENTITLED, Optional.empty());
    }

    @Test
    void aThrottleIsRateLimitedWithItsWaitWhenStated() throws Exception {
        answer(429, HOSTILE_BODY, "30");
        assertProfileAnswer(Kind.RATE_LIMITED, Optional.of(Duration.ofSeconds(30)));
        answer(429, HOSTILE_BODY, null);
        assertProfileAnswer(Kind.RATE_LIMITED, Optional.empty());
    }

    @Test
    void aServerErrorIsNetwork() throws Exception {
        answer(503, HOSTILE_BODY, null);
        assertProfileAnswer(Kind.NETWORK, Optional.empty());
    }

    @Test
    void aSuccessThatIsNotAProfileIsProtocol() throws Exception {
        answer(200, "<html>" + SESSION_TOKEN + "</html>", null);
        assertProfileAnswer(Kind.PROTOCOL, Optional.empty());
    }

    @Test
    void aRefusedConnectionIsNetwork() throws Exception {
        int port;
        try (ServerSocket closed = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            port = closed.getLocalPort();
        }
        base = "http://" + InetAddress.getLoopbackAddress().getHostAddress() + ":" + port;
        assertProfileAnswer(Kind.NETWORK, Optional.empty());
        assertEquals(Kind.NETWORK, refreshAnswer().kind());
    }

    @Test
    void eachRefreshTokenAnswerHasItsKind() throws Exception {
        answer(400, "{\"error\":\"invalid_grant\",\"error_description\":\"" + REFRESH_TOKEN + "\"}", null);
        assertEquals(Kind.REAUTH_REQUIRED, refreshAnswer().kind());

        answer(401, HOSTILE_BODY, null);
        assertEquals(Kind.UNAUTHORIZED, refreshAnswer().kind());

        answer(404, HOSTILE_BODY, null);
        assertEquals(Kind.UNAUTHORIZED, refreshAnswer().kind());

        answer(429, HOSTILE_BODY, "12");
        AltsFailure limited = refreshAnswer();
        assertEquals(Kind.RATE_LIMITED, limited.kind());
        assertEquals(Optional.of(Duration.ofSeconds(12)), limited.retryAfter());

        answer(429, HOSTILE_BODY, null);
        assertEquals(Optional.empty(), refreshAnswer().retryAfter());

        answer(502, HOSTILE_BODY, null);
        assertEquals(Kind.NETWORK, refreshAnswer().kind());

        answer(200, "not json " + REFRESH_TOKEN, null);
        assertEquals(Kind.PROTOCOL, refreshAnswer().kind());
    }
}

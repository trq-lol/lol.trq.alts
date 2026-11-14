package lol.trq.alts.internal.net;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsServer;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Where a redirect is allowed to take a request. The binary fetch is the one call that follows them, and
 * a redirect is the server choosing the next destination — so what travels there, and over what, has to
 * be decided by the client rather than inherited from the first hop.
 */
class HttpUtilRedirectTest {

    private HttpTransport http;

    private static final byte[] IMAGE = "not-really-a-png".getBytes(StandardCharsets.UTF_8);

    private static LoopbackTls tls;

    private HttpServer first;
    private HttpServer elsewhere;
    private HttpsServer secure;
    private final AtomicInteger elsewhereHits = new AtomicInteger();
    private final AtomicInteger loopHits = new AtomicInteger();
    private final AtomicReference<Headers> headersSeenElsewhere = new AtomicReference<>();
    private final AtomicReference<Headers> headersSeenAfterSameOriginRedirect = new AtomicReference<>();

    @BeforeAll
    static void generateCertificate() throws Exception {
        tls = LoopbackTls.generate();
    }

    @AfterAll
    static void discardCertificate() throws IOException {
        tls.close();
    }

    @BeforeEach
    void setUp() throws IOException {
        elsewhere = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        elsewhere.createContext("/image", exchange -> {
            elsewhereHits.incrementAndGet();
            headersSeenElsewhere.set(exchange.getRequestHeaders());
            respond(exchange, IMAGE);
        });
        elsewhere.start();

        first = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        first.createContext("/away", exchange -> redirect(exchange, base(elsewhere) + "/image"));
        first.createContext("/nearby", exchange -> redirect(exchange, "/here"));
        first.createContext("/here", exchange -> {
            headersSeenAfterSameOriginRedirect.set(exchange.getRequestHeaders());
            respond(exchange, IMAGE);
        });
        first.createContext("/loop", exchange -> {
            loopHits.incrementAndGet();
            redirect(exchange, "/loop");
        });
        first.createContext("/upgrade", exchange -> redirect(exchange, secureBase() + "/image"));
        first.createContext("/nowhere", exchange -> redirect(exchange, "ftp://files.example/image"));
        first.start();

        secure = tls.newServer();
        secure.createContext("/downgrade", exchange -> redirect(exchange, base(elsewhere) + "/image"));
        secure.createContext("/image", exchange -> respond(exchange, IMAGE));
        secure.start();
        http = TestTransports.trusting(null, tls.trustingFactory());
    }

    @AfterEach
    void tearDown() {
        first.stop(0);
        elsewhere.stop(0);
        secure.stop(0);
    }

    private static String base(HttpServer server) {
        return "http://" + InetAddress.getLoopbackAddress().getHostAddress() + ":"
                + server.getAddress().getPort();
    }

    private String secureBase() {
        return "https://" + InetAddress.getLoopbackAddress().getHostAddress() + ":"
                + secure.getAddress().getPort();
    }

    private static void redirect(HttpExchange exchange, String location) throws IOException {
        exchange.getResponseHeaders().add("Location", location);
        exchange.sendResponseHeaders(302, -1);
        exchange.close();
    }

    private static void respond(HttpExchange exchange, byte[] body) throws IOException {
        exchange.sendResponseHeaders(200, body.length);
        exchange.getResponseBody().write(body);
        exchange.close();
    }

    @Test
    void aFetchWithoutACredentialFollowsARedirectToAnotherOrigin() throws Exception {
        byte[] body = http.getBytes(base(first) + "/away", null, 1024, null);

        assertArrayEquals(IMAGE, body, "image hosts redirect; the fetch has to arrive");
        assertEquals(1, elsewhereHits.get());
    }

    @Test
    void aCallerThatPinnedItsHostIsNotRedirectedOffIt() throws Exception {
        URI pinned = URI.create(base(first));

        HttpTransport.BytesResponse away = http.getBytesForStatus(
                base(first) + "/away", null, 1024, null, hop -> HttpTransport.sameOrigin(pinned, hop));

        assertEquals(302, away.status(), "the caller sees the redirect instead of having it chased");
        assertNull(away.body());
        assertEquals(0, elsewhereHits.get(), "the host the caller did not choose must never be contacted");

        HttpTransport.BytesResponse nearby = http.getBytesForStatus(
                base(first) + "/nearby", null, 1024, null, hop -> HttpTransport.sameOrigin(pinned, hop));

        assertArrayEquals(IMAGE, nearby.body(), "a redirect that stays where the caller allowed is still followed");
    }

    @Test
    void anAuthorizationHeaderIsNeverCarriedToAnotherHost() throws Exception {
        Map<String, String> headers = Map.of("authorization", "Bearer secret-token");

        HttpTransport.BytesResponse response = http.getBytesForStatus(base(first) + "/away", headers, 1024, null);

        assertEquals(302, response.status(), "the caller sees the redirect instead of having it chased");
        assertNull(response.body());
        assertEquals(0, elsewhereHits.get(), "a request carrying a bearer token must not leave its host");
    }

    @Test
    void aCookieIsDroppedWhenARedirectLeavesTheOrigin() throws Exception {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Cookie", "session=secret");
        headers.put("X-Trace", "kept");

        http.getBytes(base(first) + "/away", headers, 1024, null);

        Headers seen = headersSeenElsewhere.get();
        assertFalse(seen.containsKey("Cookie"), "a cookie belongs to the origin that set it");
        assertFalse(seen.containsKey("Authorization"));
        assertEquals("kept", seen.getFirst("X-Trace"), "a header that identifies nobody still travels");
    }

    @Test
    void aCookieSurvivesARedirectWithinTheOrigin() throws Exception {
        byte[] body = http.getBytes(base(first) + "/nearby", Map.of("Cookie", "session=secret"), 1024, null);

        assertArrayEquals(IMAGE, body);
        assertEquals("session=secret", headersSeenAfterSameOriginRedirect.get().getFirst("Cookie"));
    }

    /** Following this would repeat, in the clear, a request the caller made over TLS. */
    @Test
    void aRedirectFromHttpsToHttpIsNotFollowed() throws Exception {
        HttpTransport.BytesResponse response = http.getBytesForStatus(secureBase() + "/downgrade", null, 1024, null);

        assertEquals(302, response.status());
        assertNull(response.body());
        assertEquals(0, elsewhereHits.get(), "the plain-http target must never be contacted");
        assertNull(http.getBytes(secureBase() + "/downgrade", null, 1024, null));
    }

    @Test
    void aRedirectFromHttpToHttpsIsFollowed() throws Exception {
        assertArrayEquals(IMAGE, http.getBytes(base(first) + "/upgrade", null, 1024, null));
    }

    @Test
    void aRedirectLoopEnds() throws Exception {
        HttpTransport.BytesResponse response = http.getBytesForStatus(base(first) + "/loop", null, 1024, null);

        assertEquals(302, response.status());
        assertEquals(6, loopHits.get(), "the first request and five redirects, then no more");
    }

    @Test
    void aRedirectToSomethingThatIsNotHttpIsNotFollowed() throws Exception {
        assertEquals(
                302,
                http.getBytesForStatus(base(first) + "/nowhere", null, 1024, null)
                        .status());
    }

    @Test
    void redirectTargetsResolveAgainstTheUrlThatSentThem() {
        URI from = URI.create("https://textures.example/skins/a.png");

        assertEquals(URI.create("https://textures.example/skins/b.png"), HttpTransport.redirectTarget(from, "b.png"));
        assertEquals(
                URI.create("https://cdn.example/b.png"),
                HttpTransport.redirectTarget(from, "https://cdn.example/b.png"));
        assertNull(HttpTransport.redirectTarget(from, "http://textures.example/skins/a.png"), "a downgrade");
        assertNull(HttpTransport.redirectTarget(from, "HTTP://textures.example/skins/a.png"), "however it is spelled");
        assertNull(HttpTransport.redirectTarget(from, "//"), "no host");
        assertNull(HttpTransport.redirectTarget(from, "https://bad host/"), "malformed");
        assertNull(HttpTransport.redirectTarget(from, null));
        assertNull(HttpTransport.redirectTarget(from, " "));
    }

    @Test
    void anOriginIsSchemeHostAndPort() {
        URI origin = URI.create("https://textures.example/a");

        assertTrue(HttpTransport.sameOrigin(origin, URI.create("https://TEXTURES.example:443/b")));
        assertFalse(HttpTransport.sameOrigin(origin, URI.create("https://textures.example:8443/a")));
        assertFalse(HttpTransport.sameOrigin(origin, URI.create("https://cdn.example/a")));
        assertFalse(HttpTransport.sameOrigin(origin, URI.create("http://textures.example/a")));
    }
}

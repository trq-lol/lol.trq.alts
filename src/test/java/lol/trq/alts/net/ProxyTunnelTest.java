package lol.trq.alts.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpsServer;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * An HTTPS request through an authenticating HTTP proxy — which is every request this library makes for
 * a host that proxies, since every endpoint it calls is HTTPS.
 *
 * <p>Two things have to hold at once and neither JDK HTTP stack gives both: the proxy must see the
 * credential on the {@code CONNECT}, or it refuses the tunnel; and the origin must never see it, or a
 * paid proxy's password is handed to the service on every call. The origin here speaks real TLS behind a
 * real tunnel, so what it records is what a service would have received.
 */
class ProxyTunnelTest {

    private HttpTransport http;

    /** Builds the transport a runtime with {@code provider} would hold, trusting the loopback origin. */
    private void bind(lol.trq.alts.spi.ProxyProvider provider) {
        http = TestTransports.trusting(provider, tls.trustingFactory());
    }

    private static final String BODY = "{\"id\":\"00000000000040008000000000000001\",\"name\":\"Alex\"}";
    private static final String CREDENTIAL = "Basic dXNlcjpwYXNz";
    private static final NetworkScope PROFILE = NetworkScope.of(NetworkScope.Purpose.PROFILE);

    private static LoopbackTls tls;

    private HttpsServer origin;
    private ConnectProxy proxy;
    private final AtomicInteger originHits = new AtomicInteger();
    private final List<String> headerNamesSeenByOrigin = Collections.synchronizedList(new ArrayList<>());

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
        origin = tls.newServer();
        origin.createContext("/profile", exchange -> {
            originHits.incrementAndGet();
            exchange.getRequestHeaders()
                    .keySet()
                    .forEach(name -> headerNamesSeenByOrigin.add(name.toLowerCase(Locale.ROOT)));
            byte[] bytes = BODY.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        origin.createContext("/refused", exchange -> {
            byte[] bytes = "{\"error\":\"nope\"}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("X-Marker", "seen");
            exchange.sendResponseHeaders(403, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        origin.start();
    }

    @AfterEach
    void tearDown() throws IOException {
        if (http != null) {
            http.close();
        }
        origin.stop(0);
        if (proxy != null) {
            proxy.close();
        }
    }

    private static String loopback() {
        return InetAddress.getLoopbackAddress().getHostAddress();
    }

    private String originUrl() {
        return "https://" + loopback() + ":" + origin.getAddress().getPort() + "/profile";
    }

    private ProxyRoute throughProxy() {
        return ProxyRoute.http(loopback(), proxy.port());
    }

    /**
     * A kept-alive tunnel is a live connection to the proxy, held open under one route's identity. Closing
     * the transport must close it, and refuse what comes after rather than open a new one.
     */
    @Test
    void closingTheTransportClosesItsPooledTunnels() throws Exception {
        proxy = new ConnectProxy(CREDENTIAL);
        bind(scope -> throughProxy().withCredentials("user", "pass".toCharArray()));
        http.get(originUrl(), null, PROFILE);
        http.get(originUrl(), null, PROFILE);
        assertEquals(1, proxy.requestLines().size(), "the second request reused the pooled tunnel");
        assertEquals(0, proxy.tunnelsClosedByClient(), "and the tunnel is still open");

        http.close();

        for (int i = 0; i < 200 && proxy.tunnelsClosedByClient() == 0; i++) {
            Thread.sleep(10);
        }
        assertEquals(1, proxy.tunnelsClosedByClient(), "the proxy saw the pooled tunnel closed");
        assertThrows(IOException.class, () -> http.get(originUrl(), null, PROFILE));
        assertEquals(1, proxy.requestLines().size(), "a closed transport opens no new tunnel");
    }

    /**
     * A request that resolved its route just before the transport closed must not open a tunnel after
     * it: close() has already gone through the tunnels, and would never close that one. The provider
     * closes the transport between the two steps, which makes the race deterministic.
     */
    @Test
    void aTunnelIsRefusedOnceTheTransportHasClosed() throws Exception {
        proxy = new ConnectProxy(null);
        HttpTransport[] self = new HttpTransport[1];
        bind(scope -> {
            self[0].close();
            return throughProxy();
        });
        self[0] = http;

        assertThrows(IOException.class, () -> http.get(originUrl(), null, PROFILE));

        assertEquals(0, proxy.requestLines().size(), "no CONNECT was sent after close");
        assertEquals(0, http.tunnelFactoryCount(), "and no tunnel factory outlives the close");
    }

    /**
     * Two runtimes that happen to name the same proxy and credential still keep their tunnels apart: the
     * pool is the transport's, so each opens its own, and closing one runtime's leaves the other's
     * working.
     */
    @Test
    void twoTransportsOnOneRouteNeverShareATunnel() throws Exception {
        proxy = new ConnectProxy(CREDENTIAL);
        bind(scope -> throughProxy().withCredentials("user", "pass".toCharArray()));
        HttpTransport first = http;
        HttpTransport second = TestTransports.trusting(
                scope -> throughProxy().withCredentials("user", "pass".toCharArray()), tls.trustingFactory());
        try {
            first.get(originUrl(), null, PROFILE);
            second.get(originUrl(), null, PROFILE);
            assertEquals(2, proxy.requestLines().size(), "each transport opened its own tunnel");

            first.close();
            for (int i = 0; i < 200 && proxy.tunnelsClosedByClient() == 0; i++) {
                Thread.sleep(10);
            }
            assertEquals(1, proxy.tunnelsClosedByClient(), "closing one closed only its own tunnel");

            assertNotNull(second.get(originUrl(), null, PROFILE), "the other's tunnel still works");
            assertEquals(2, proxy.requestLines().size(), "and it was reused rather than reopened");
            assertEquals(1, proxy.tunnelsClosedByClient());
        } finally {
            second.close();
        }
    }

    @Test
    void anHttpsRequestThroughAnAuthenticatingProxySucceeds() throws Exception {
        proxy = new ConnectProxy(CREDENTIAL);
        bind(scope -> throughProxy().withCredentials("user", "pass".toCharArray()));

        JsonObject response = http.get(originUrl(), null, PROFILE);

        assertNotNull(response, "a proxy that requires a credential must be given one");
        assertEquals("Alex", response.get("name").getAsString());
        assertEquals(1, originHits.get());
    }

    @Test
    void theProxySeesTheCredentialOnTheConnect() throws Exception {
        proxy = new ConnectProxy(CREDENTIAL);
        bind(scope -> throughProxy().withCredentials("user", "pass".toCharArray()));

        http.get(originUrl(), null, PROFILE);

        assertEquals(
                List.of("CONNECT " + loopback() + ":" + origin.getAddress().getPort() + " HTTP/1.1"),
                proxy.requestLines());
        assertEquals(List.of(CREDENTIAL), proxy.authorizations());
    }

    @Test
    void theOriginNeverReceivesTheProxyCredential() throws Exception {
        proxy = new ConnectProxy(CREDENTIAL);
        bind(scope -> throughProxy().withCredentials("user", "pass".toCharArray()));

        http.get(originUrl(), null, PROFILE);
        http.postJsonForStatus(originUrl(), null, "{}");
        http.getBytes(originUrl(), null, 1 << 20, PROFILE);

        assertEquals(3, originHits.get());
        assertFalse(
                headerNamesSeenByOrigin.contains("proxy-authorization"),
                "the proxy password must stay on the proxy leg, never inside the tunnel");
    }

    @Test
    void aWrongCredentialFailsTheRequestRatherThanGoingDirect() throws Exception {
        proxy = new ConnectProxy(CREDENTIAL);
        bind(scope -> throughProxy().withCredentials("user", "wrong".toCharArray()));

        assertThrows(IOException.class, () -> http.get(originUrl(), null, PROFILE));

        assertEquals(1, proxy.requestLines().size(), "the tunnel was attempted through the proxy");
        assertEquals(0, originHits.get(), "a refused tunnel must never fall back to the real address");
    }

    @Test
    void aMissingCredentialFailsClosedToo() throws Exception {
        proxy = new ConnectProxy(CREDENTIAL);
        bind(scope -> throughProxy());

        assertThrows(IOException.class, () -> http.get(originUrl(), null, PROFILE));

        assertEquals(0, originHits.get());
    }

    @Test
    void anUnauthenticatedProxyTunnelsWithoutACredential() throws Exception {
        proxy = new ConnectProxy(null);
        bind(scope -> throughProxy());

        assertNotNull(http.get(originUrl(), null, PROFILE));

        assertEquals(List.of(""), proxy.authorizations());
        assertEquals(1, originHits.get());
    }

    /** The certificate names the loopback IP only, so asking for the origin by another name must fail. */
    @Test
    void hostnameVerificationStillRunsInsideTheTunnel() throws Exception {
        proxy = new ConnectProxy(null);
        bind(scope -> throughProxy());
        String byAnotherName = "https://localhost:" + origin.getAddress().getPort() + "/profile";

        assertThrows(SSLException.class, () -> http.get(byAnotherName, null, PROFILE));

        assertEquals(
                List.of("CONNECT localhost:" + origin.getAddress().getPort() + " HTTP/1.1"),
                proxy.requestLines(),
                "the tunnel was opened, naming the host as written so the proxy is the one to resolve it");
        assertEquals(0, originHits.get(), "but no request may be sent to a peer that failed verification");
    }

    /** Whatever answers on the proxy port, anything short of a 2xx to the CONNECT ends the request there. */
    @Test
    void aProxyThatDoesNotSpeakHttpFailsTheRequest() throws Exception {
        try (ServerSocket impostor = new ServerSocket(0, 0, InetAddress.getLoopbackAddress())) {
            Thread.ofPlatform().daemon().start(() -> {
                try (Socket client = impostor.accept()) {
                    client.getOutputStream().write("SSH-2.0-not-a-proxy\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1));
                    client.getOutputStream().flush();
                    client.getInputStream().readAllBytes();
                } catch (IOException closing) {
                    // The client hanging up is the expected ending.
                }
            });
            bind(scope -> ProxyRoute.http(loopback(), impostor.getLocalPort()));

            assertThrows(IOException.class, () -> http.get(originUrl(), null, PROFILE));
        }

        assertEquals(0, originHits.get());
    }

    @Test
    void onlyAThreeDigitStatusIsAStatus() throws Exception {
        assertEquals(200, ProxyTunnelSocketFactory.statusOf("HTTP/1.1 200 Connection established"));
        assertEquals(407, ProxyTunnelSocketFactory.statusOf("HTTP/1.0 407"));

        for (String line : new String[] {
            "HTTP/1.1 +200 OK",
            "HTTP/1.1 -200 OK",
            "HTTP/1.1 2000 OK",
            "HTTP/1.1 20 OK",
            "HTTP/1.1 0200 OK",
            "HTTP/1.1 \u0662\u0660\u0660 OK",
            "HTTP/1.1  200 OK",
            "HTTP/1.1 2e2 OK",
        }) {
            assertThrows(
                    IOException.class,
                    () -> ProxyTunnelSocketFactory.statusOf(line),
                    "a tunnel must not be treated as open on a status line that is not one: " + line);
        }
    }

    @Test
    void theTunnelHandshakeAsAWholeIsHeldToOneDeadline() throws Exception {
        int budgetMillis = 2_000;
        try (ServerSocket slow = new ServerSocket(0, 0, InetAddress.getLoopbackAddress())) {
            Thread.ofPlatform().daemon().start(() -> {
                try (Socket client = slow.accept()) {
                    // Most of the budget passes, one byte arrives, and then nothing ever does.
                    Thread.sleep(budgetMillis * 7L / 10);
                    client.getOutputStream().write('H');
                    client.getOutputStream().flush();
                    client.getInputStream().readAllBytes();
                } catch (IOException | InterruptedException closing) {
                    // The client hanging up is the expected ending.
                }
            });
            ProxyTunnelSocketFactory factory =
                    new ProxyTunnelSocketFactory(loopback(), slow.getLocalPort(), null, () -> null);

            long started = System.nanoTime();
            try (Socket tunnel = factory.createSocket()) {
                assertThrows(
                        IOException.class,
                        () -> tunnel.connect(InetSocketAddress.createUnresolved("origin.example", 443), budgetMillis));
            }
            long elapsedMillis = (System.nanoTime() - started) / 1_000_000L;

            assertTrue(
                    elapsedMillis < budgetMillis * 14L / 10,
                    "a byte arriving late must not buy the proxy a second full timeout; took " + elapsedMillis + " ms");
        }
    }

    @Test
    void theTunnelAuthorityIsWrittenSafely() throws Exception {
        assertEquals("login.example:443", ProxyTunnelSocketFactory.authority("login.example", 443));
        assertEquals("[2001:db8::1]:443", ProxyTunnelSocketFactory.authority("2001:db8::1", 443));
        assertEquals("[2001:db8::1]:443", ProxyTunnelSocketFactory.authority("[2001:db8::1]", 443));
        assertThrows(
                IOException.class,
                () -> ProxyTunnelSocketFactory.authority("login.example\r\nProxy-Authorization: x", 443),
                "a host must never be able to add a line to the CONNECT");
        assertThrows(IOException.class, () -> ProxyTunnelSocketFactory.authority("", 443));
    }

    /** Without a substituted factory the JVM's default trust applies, and it has never heard of this certificate. */
    @Test
    void defaultTrustStillAppliesInsideTheTunnel() throws Exception {
        proxy = new ConnectProxy(null);
        http = TestTransports.through(scope -> throughProxy());

        assertThrows(SSLException.class, () -> http.get(originUrl(), null, PROFILE));

        assertEquals(0, originHits.get());
    }

    /**
     * Rotating gateways pin an exit address to the username. Were the second account's request to ride
     * the first account's tunnel, it would leave from the first account's address.
     */
    @Test
    void twoUsernamesOnOneGatewayNeverShareATunnel() throws Exception {
        proxy = new ConnectProxy(null);
        ProxyRoute first = throughProxy().withCredentials("session-a", "pass".toCharArray());
        ProxyRoute second = throughProxy().withCredentials("session-b", "pass".toCharArray());
        bind(scope -> "a".equals(scope.accountUsername()) ? first : second);

        http.get(originUrl(), null, NetworkScope.forAccount(NetworkScope.Purpose.PROFILE, null, "a"));
        http.get(originUrl(), null, NetworkScope.forAccount(NetworkScope.Purpose.PROFILE, null, "b"));

        assertEquals(
                List.of(first.authorizationHeader(), second.authorizationHeader()),
                proxy.authorizations(),
                "each identity must open its own tunnel, authenticated as itself");
    }

    /**
     * The other half of keying reuse by identity: the same identity does reuse. A login chain makes
     * several calls to each host, and a tunnel plus a TLS handshake per call is what closing the
     * connection after every response used to cost.
     */
    @Test
    void oneIdentityReusesItsTunnelAcrossRequests() throws Exception {
        proxy = new ConnectProxy(null);
        ProxyRoute route = throughProxy().withCredentials("session-a", "pass".toCharArray());
        bind(scope -> route);
        String refused = originUrl().replace("/profile", "/refused");

        http.get(originUrl(), null, PROFILE);
        http.getBytes(originUrl(), null, 1 << 20, PROFILE);
        assertEquals("seen", http.getHeader(refused, null, "X-Marker", PROFILE).value());
        assertEquals(403, http.getForStatus(refused, null, PROFILE).status());
        http.get(refused, null, PROFILE);
        http.get(originUrl(), null, PROFILE);

        assertEquals(3, originHits.get());
        assertEquals(
                1,
                proxy.requestLines().size(),
                "six requests as one identity to one origin need one tunnel: " + proxy.requestLines());
    }

    @Test
    void aChangedPasswordIsADifferentIdentity() throws Exception {
        proxy = new ConnectProxy(null);
        ProxyRoute before = throughProxy().withCredentials("user", "old".toCharArray());
        ProxyRoute after = throughProxy().withCredentials("user", "new".toCharArray());
        AtomicInteger calls = new AtomicInteger();
        bind(scope -> calls.getAndIncrement() == 0 ? before : after);

        http.get(originUrl(), null, PROFILE);
        http.get(originUrl(), null, PROFILE);

        assertEquals(List.of(before.authorizationHeader(), after.authorizationHeader()), proxy.authorizations());
    }

    @Test
    void theIdentityCacheIsBounded() throws Exception {
        proxy = new ConnectProxy(null);
        AtomicInteger next = new AtomicInteger();
        bind(scope -> throughProxy().withCredentials("session-" + next.getAndIncrement(), new char[] {'p'}));

        int requests = HttpTransport.MAX_TUNNEL_FACTORIES + 8;
        for (int i = 0; i < requests; i++) {
            http.get(originUrl(), null, PROFILE);
        }

        assertEquals(requests, originHits.get());
        assertTrue(
                http.tunnelFactoryCount() <= HttpTransport.MAX_TUNNEL_FACTORIES,
                "a host rotating identities must not grow the cache without limit: " + http.tunnelFactoryCount());
    }

    @Test
    void aDirectHttpsRequestIsUnaffected() throws Exception {
        proxy = new ConnectProxy(null);
        bind(scope -> ProxyRoute.direct());

        assertNotNull(http.get(originUrl(), null, PROFILE));

        assertEquals(0, proxy.requestLines().size());
        assertEquals(1, originHits.get());
    }
}

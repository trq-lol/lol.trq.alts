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
        origin.start();
        HttpUtil.tlsSocketFactoryForTests(tls.trustingFactory());
    }

    @AfterEach
    void tearDown() throws IOException {
        HttpUtil.resetForTests();
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

    @Test
    void anHttpsRequestThroughAnAuthenticatingProxySucceeds() throws Exception {
        proxy = new ConnectProxy(CREDENTIAL);
        HttpUtil.bind(scope -> throughProxy().withCredentials("user", "pass".toCharArray()));

        JsonObject response = HttpUtil.get(originUrl(), null, PROFILE);

        assertNotNull(response, "a proxy that requires a credential must be given one");
        assertEquals("Alex", response.get("name").getAsString());
        assertEquals(1, originHits.get());
    }

    @Test
    void theProxySeesTheCredentialOnTheConnect() throws Exception {
        proxy = new ConnectProxy(CREDENTIAL);
        HttpUtil.bind(scope -> throughProxy().withCredentials("user", "pass".toCharArray()));

        HttpUtil.get(originUrl(), null, PROFILE);

        assertEquals(
                List.of("CONNECT " + loopback() + ":" + origin.getAddress().getPort() + " HTTP/1.1"),
                proxy.requestLines());
        assertEquals(List.of(CREDENTIAL), proxy.authorizations());
    }

    @Test
    void theOriginNeverReceivesTheProxyCredential() throws Exception {
        proxy = new ConnectProxy(CREDENTIAL);
        HttpUtil.bind(scope -> throughProxy().withCredentials("user", "pass".toCharArray()));

        HttpUtil.get(originUrl(), null, PROFILE);
        HttpUtil.postJsonForStatus(originUrl(), null, "{}");
        HttpUtil.getBytes(originUrl(), null, 1 << 20, PROFILE);

        assertEquals(3, originHits.get());
        assertFalse(
                headerNamesSeenByOrigin.contains("proxy-authorization"),
                "the proxy password must stay on the proxy leg, never inside the tunnel");
    }

    @Test
    void aWrongCredentialFailsTheRequestRatherThanGoingDirect() throws Exception {
        proxy = new ConnectProxy(CREDENTIAL);
        HttpUtil.bind(scope -> throughProxy().withCredentials("user", "wrong".toCharArray()));

        assertThrows(IOException.class, () -> HttpUtil.get(originUrl(), null, PROFILE));

        assertEquals(1, proxy.requestLines().size(), "the tunnel was attempted through the proxy");
        assertEquals(0, originHits.get(), "a refused tunnel must never fall back to the real address");
    }

    @Test
    void aMissingCredentialFailsClosedToo() throws Exception {
        proxy = new ConnectProxy(CREDENTIAL);
        HttpUtil.bind(scope -> throughProxy());

        assertThrows(IOException.class, () -> HttpUtil.get(originUrl(), null, PROFILE));

        assertEquals(0, originHits.get());
    }

    @Test
    void anUnauthenticatedProxyTunnelsWithoutACredential() throws Exception {
        proxy = new ConnectProxy(null);
        HttpUtil.bind(scope -> throughProxy());

        assertNotNull(HttpUtil.get(originUrl(), null, PROFILE));

        assertEquals(List.of(""), proxy.authorizations());
        assertEquals(1, originHits.get());
    }

    /** The certificate names the loopback IP only, so asking for the origin by another name must fail. */
    @Test
    void hostnameVerificationStillRunsInsideTheTunnel() throws Exception {
        proxy = new ConnectProxy(null);
        HttpUtil.bind(scope -> throughProxy());
        String byAnotherName = "https://localhost:" + origin.getAddress().getPort() + "/profile";

        assertThrows(SSLException.class, () -> HttpUtil.get(byAnotherName, null, PROFILE));

        assertEquals(1, proxy.requestLines().size(), "the tunnel itself was opened");
        assertEquals(0, originHits.get(), "but no request may be sent to a peer that failed verification");
    }

    /** Without the test seam the JVM's default trust applies, and it has never heard of this certificate. */
    @Test
    void defaultTrustStillAppliesInsideTheTunnel() throws Exception {
        proxy = new ConnectProxy(null);
        HttpUtil.bind(scope -> throughProxy());
        HttpUtil.tlsSocketFactoryForTests(null);

        assertThrows(SSLException.class, () -> HttpUtil.get(originUrl(), null, PROFILE));

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
        HttpUtil.bind(scope -> "a".equals(scope.accountUsername()) ? first : second);

        HttpUtil.get(originUrl(), null, NetworkScope.forAccount(NetworkScope.Purpose.PROFILE, null, "a"));
        HttpUtil.get(originUrl(), null, NetworkScope.forAccount(NetworkScope.Purpose.PROFILE, null, "b"));

        assertEquals(
                List.of(first.authorizationHeader(), second.authorizationHeader()),
                proxy.authorizations(),
                "each identity must open its own tunnel, authenticated as itself");
    }

    @Test
    void aChangedPasswordIsADifferentIdentity() throws Exception {
        proxy = new ConnectProxy(null);
        ProxyRoute before = throughProxy().withCredentials("user", "old".toCharArray());
        ProxyRoute after = throughProxy().withCredentials("user", "new".toCharArray());
        AtomicInteger calls = new AtomicInteger();
        HttpUtil.bind(scope -> calls.getAndIncrement() == 0 ? before : after);

        HttpUtil.get(originUrl(), null, PROFILE);
        HttpUtil.get(originUrl(), null, PROFILE);

        assertEquals(List.of(before.authorizationHeader(), after.authorizationHeader()), proxy.authorizations());
    }

    @Test
    void theIdentityCacheIsBounded() throws Exception {
        proxy = new ConnectProxy(null);
        AtomicInteger next = new AtomicInteger();
        HttpUtil.bind(scope -> throughProxy().withCredentials("session-" + next.getAndIncrement(), new char[] {'p'}));

        int requests = HttpUtil.MAX_TUNNEL_FACTORIES + 8;
        for (int i = 0; i < requests; i++) {
            HttpUtil.get(originUrl(), null, PROFILE);
        }

        assertEquals(requests, originHits.get());
        assertTrue(
                HttpUtil.tunnelFactoryCount() <= HttpUtil.MAX_TUNNEL_FACTORIES,
                "a host rotating identities must not grow the cache without limit: " + HttpUtil.tunnelFactoryCount());
    }

    @Test
    void aDirectHttpsRequestIsUnaffected() throws Exception {
        proxy = new ConnectProxy(null);
        HttpUtil.bind(scope -> ProxyRoute.direct());

        assertNotNull(HttpUtil.get(originUrl(), null, PROFILE));

        assertEquals(0, proxy.requestLines().size());
        assertEquals(1, originHits.get());
    }
}

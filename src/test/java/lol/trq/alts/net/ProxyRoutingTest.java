package lol.trq.alts.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Where a request actually goes. The seam is only worth having if the request leaves through the route
 * the host named — and if a provider that cannot name one stops the request rather than quietly sending
 * it out of the machine's own address, which is the disclosure the whole feature exists to prevent.
 */
class ProxyRoutingTest {

    private HttpTransport http = TestTransports.direct();

    /** Replaces the transport with one routed by {@code provider}, as a runtime built with it would hold. */
    private void bind(lol.trq.alts.spi.ProxyProvider provider) {
        http = TestTransports.through(provider);
    }

    private static final String BODY = "{\"id\":\"00000000000040008000000000000001\",\"name\":\"Alex\"}";

    private HttpServer origin;
    private RecordingProxy proxy;
    private final AtomicInteger originHits = new AtomicInteger();

    @BeforeEach
    void setUp() throws IOException {
        origin = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        origin.createContext("/profile", exchange -> {
            originHits.incrementAndGet();
            byte[] bytes = BODY.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        origin.start();
        proxy = new RecordingProxy();
    }

    @AfterEach
    void tearDown() throws IOException {
        if (origin != null) {
            origin.stop(0);
        }
        if (proxy != null) {
            proxy.close();
        }
    }

    private String originUrl() {
        return "http://" + InetAddress.getLoopbackAddress().getHostAddress() + ":"
                + origin.getAddress().getPort() + "/profile";
    }

    private ProxyRoute throughProxy() {
        return ProxyRoute.http(InetAddress.getLoopbackAddress().getHostAddress(), proxy.port());
    }

    @Test
    void aRequestLeavesThroughTheRouteTheHostNamed() throws Exception {
        bind(scope -> throughProxy());

        http.get(originUrl(), null, NetworkScope.of(NetworkScope.Purpose.PROFILE));

        assertEquals(1, proxy.requestLines().size(), "the proxy must have seen the request");
        assertTrue(
                proxy.requestLines().get(0).contains(originUrl()),
                "a proxied request carries the absolute target: "
                        + proxy.requestLines().get(0));
        assertEquals(0, originHits.get(), "the request must not also have gone direct");
    }

    @Test
    void anExplicitlyDirectRouteBypassesTheProxy() throws Exception {
        bind(scope -> ProxyRoute.direct());

        http.get(originUrl(), null, NetworkScope.of(NetworkScope.Purpose.PROFILE));

        assertEquals(1, originHits.get());
        assertEquals(0, proxy.requestLines().size());
    }

    @Test
    void credentialsRideOnTheConnectionRatherThanOnAGlobalAuthenticator() throws Exception {
        bind(scope -> throughProxy().withCredentials("user", "pass".toCharArray()));

        http.get(originUrl(), null, NetworkScope.of(NetworkScope.Purpose.PROFILE));

        assertEquals("Basic dXNlcjpwYXNz", proxy.authorizations().get(0));
    }

    /**
     * The JDK pools a plain-HTTP proxy connection by proxy address alone, so a kept-alive one would carry
     * the next request, under another credential, through whatever session the gateway pinned to it. On
     * that path the transport closes every connection after its request, and a caller's own
     * {@code Connection} header cannot turn pooling back on.
     */
    @Test
    void anAuthenticatedPlainHttpProxyConnectionIsNeverReused() throws Exception {
        try (KeepAliveProxy keepAlive = new KeepAliveProxy()) {
            bind(scope -> ProxyRoute.http(InetAddress.getLoopbackAddress().getHostAddress(), keepAlive.port())
                    .withCredentials("user", "pass".toCharArray()));
            java.util.Map<String, String> keepItAlive = java.util.Map.of("Connection", "keep-alive");

            http.get(originUrl(), null, NetworkScope.of(NetworkScope.Purpose.PROFILE));
            http.get(originUrl(), keepItAlive, NetworkScope.of(NetworkScope.Purpose.PROFILE));
            http.getForStatus(originUrl(), keepItAlive, NetworkScope.of(NetworkScope.Purpose.PROFILE));

            assertEquals(3, keepAlive.heads().size(), keepAlive.heads().toString());
            assertEquals(3, keepAlive.connections(), "each request opened its own connection: " + keepAlive.heads());
            for (String head : keepAlive.heads()) {
                assertTrue(
                        head.toLowerCase(Locale.ROOT).contains("\r\nconnection: close\r\n"),
                        "every request asked for its connection to be closed: " + head);
            }
        }
    }

    @Test
    void eachScopeIsRoutedOnItsOwn() throws Exception {
        bind(scope -> scope.purpose() == NetworkScope.Purpose.PROFILE ? throughProxy() : ProxyRoute.direct());

        http.get(originUrl(), null, NetworkScope.of(NetworkScope.Purpose.PROFILE));
        http.getBytes(originUrl(), null, 1 << 20, NetworkScope.of(NetworkScope.Purpose.AVATAR));

        assertEquals(1, proxy.requestLines().size(), "the profile lookup went through the proxy");
        assertEquals(1, originHits.get(), "the avatar fetch went direct");
    }

    /**
     * The intuitive fallback — proxy unavailable, so connect directly — is the one behaviour that must
     * never happen. It discloses the machine's own address at exactly the moment the host believed every
     * request was covered, and unlike a failed request that cannot be undone.
     */
    @Test
    void aProviderThatThrowsFailsTheRequestRatherThanGoingDirect() {
        bind(scope -> {
            throw new IllegalStateException("no proxies left in the pool");
        });

        assertThrows(
                IOException.class, () -> http.get(originUrl(), null, NetworkScope.of(NetworkScope.Purpose.PROFILE)));
        assertEquals(0, originHits.get(), "a failed resolution must never fall back to the real address");
    }

    @Test
    void aProviderThatNamesNoRouteFailsTheRequestToo() {
        bind(scope -> null);

        assertThrows(
                IOException.class, () -> http.get(originUrl(), null, NetworkScope.of(NetworkScope.Purpose.PROFILE)));
        assertEquals(0, originHits.get());
    }

    @Test
    void withoutAProviderEverythingIsDirect() throws Exception {
        http.get(originUrl(), null, NetworkScope.of(NetworkScope.Purpose.PROFILE));

        assertEquals(1, originHits.get());
        assertEquals(0, proxy.requestLines().size());
    }

    /**
     * Each transport has its own provider, fixed when it is built. One built without a provider is
     * direct, whatever another transport in the process was given, and never borrows its routes.
     */
    @Test
    void aTransportWithoutAProviderNeverUsesAnotherTransportsProvider() throws Exception {
        bind(scope -> throughProxy());
        HttpTransport proxied = http;
        HttpTransport direct = TestTransports.direct();

        direct.get(originUrl(), null, NetworkScope.of(NetworkScope.Purpose.PROFILE));
        proxied.get(originUrl(), null, NetworkScope.of(NetworkScope.Purpose.PROFILE));

        assertEquals(1, originHits.get(), "the transport with no provider went direct");
        assertEquals(1, proxy.requestLines().size(), "the proxied one went through its own provider");
    }

    /**
     * The JDK reads SOCKS credentials from process-global state, so honouring them would mean installing
     * a default authenticator into the host's JVM. Connecting unauthenticated instead would send the
     * request from an address the host did not choose, which is the same disclosure by another route.
     */
    @Test
    void authenticatedSocks5IsRefusedRatherThanSilentlyDowngraded() {
        assertThrows(
                UnsupportedOperationException.class,
                () -> ProxyRoute.socks5("127.0.0.1", 1080).withCredentials("user", "pass".toCharArray()));
    }

    @Test
    void aRouteDescribesItselfWithoutItsPassword() {
        ProxyRoute route = ProxyRoute.http("proxy.example", 8080).withCredentials("user", "hunter2".toCharArray());

        assertTrue(route.toString().contains("proxy.example:8080"));
        assertTrue(route.toString().contains("authenticated"));
        assertTrue(
                route.toString().indexOf("hunter2") < 0,
                "a host logging the route it chose must not log the credential: " + route);
    }

    @Test
    void aRouteDescribesItselfWithoutItsUsernameEither() {
        ProxyRoute route =
                ProxyRoute.http("proxy.example", 8080).withCredentials("customer-1234-session-abcd", new char[] {'p'});

        assertTrue(
                route.toString().indexOf("customer-1234-session-abcd") < 0,
                "a gateway username carries the session and the customer: " + route);
    }

    @Test
    void thePasswordHandedOutIsACopy() {
        char[] supplied = "hunter2".toCharArray();
        ProxyRoute route = ProxyRoute.http("proxy.example", 8080).withCredentials("user", supplied);
        String before = route.authorizationHeader();

        Arrays.fill(route.password(), 'x');
        Arrays.fill(supplied, 'y');

        assertEquals(before, route.authorizationHeader(), "neither array may reach the stored credential");
        assertEquals("hunter2", new String(route.password()));
    }

    @Test
    void aPasswordPassedStraightToTheConstructorIsCopiedToo() {
        char[] supplied = "hunter2".toCharArray();
        ProxyRoute route = new ProxyRoute(ProxyRoute.Kind.HTTP, "proxy.example", 8080, "user", supplied);

        Arrays.fill(supplied, 'y');

        assertEquals("hunter2", new String(route.password()));
    }

    @Test
    void routesCompareByCredentialContents() {
        ProxyRoute first = ProxyRoute.http("proxy.example", 8080).withCredentials("user", "pass".toCharArray());
        ProxyRoute same = ProxyRoute.http("proxy.example", 8080).withCredentials("user", "pass".toCharArray());
        ProxyRoute other = ProxyRoute.http("proxy.example", 8080).withCredentials("user", "word".toCharArray());

        assertEquals(first, same);
        assertEquals(first.hashCode(), same.hashCode());
        assertNotEquals(first, other, "a different password is a different route");
    }

    @Test
    void anEndpointIdentifiesTheAddressNotTheCredential() {
        ProxyRoute bare = ProxyRoute.http("proxy.example", 8080);
        ProxyRoute authenticated = bare.withCredentials("user", "pass".toCharArray());

        assertEquals(bare.endpoint(), authenticated.endpoint(), "what a service rate-limits is the address");
        assertNotNull(ProxyRoute.direct().endpoint());
    }

    /** A stand-in HTTP proxy that records what reached it and answers everything itself. */
    private static final class RecordingProxy implements AutoCloseable {

        private final ServerSocket socket;
        private final List<String> requestLines = Collections.synchronizedList(new ArrayList<>());
        private final List<String> authorizations = Collections.synchronizedList(new ArrayList<>());

        RecordingProxy() throws IOException {
            socket = new ServerSocket(0, 0, InetAddress.getLoopbackAddress());
            Thread thread = new Thread(this::serve, "recording-proxy");
            thread.setDaemon(true);
            thread.start();
        }

        int port() {
            return socket.getLocalPort();
        }

        List<String> requestLines() {
            return requestLines;
        }

        List<String> authorizations() {
            return authorizations;
        }

        private void serve() {
            while (!socket.isClosed()) {
                try (Socket client = socket.accept()) {
                    BufferedReader in = new BufferedReader(
                            new InputStreamReader(client.getInputStream(), StandardCharsets.ISO_8859_1));
                    String requestLine = in.readLine();
                    if (requestLine == null) {
                        continue;
                    }
                    requestLines.add(requestLine);

                    String authorization = "";
                    String header;
                    while ((header = in.readLine()) != null && !header.isEmpty()) {
                        if (header.toLowerCase(Locale.ROOT).startsWith("proxy-authorization:")) {
                            authorization =
                                    header.substring(header.indexOf(':') + 1).trim();
                        }
                    }
                    authorizations.add(authorization);

                    byte[] body = BODY.getBytes(StandardCharsets.UTF_8);
                    OutputStream out = client.getOutputStream();
                    out.write(("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + body.length
                                    + "\r\nConnection: close\r\n\r\n")
                            .getBytes(StandardCharsets.ISO_8859_1));
                    out.write(body);
                    out.flush();
                } catch (IOException closing) {
                    return;
                }
            }
        }

        @Override
        public void close() throws IOException {
            socket.close();
        }
    }
}

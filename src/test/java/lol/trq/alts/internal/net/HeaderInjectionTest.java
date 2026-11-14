package lol.trq.alts.internal.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.sun.net.httpserver.HttpServer;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A request header's value is usually a credential. A header the request cannot carry must be refused
 * without that value ending up in the failure, because the failure is what gets shown and logged.
 */
class HeaderInjectionTest {

    private final HttpTransport http = TestTransports.direct();

    private static final String SECRET = "eyJhbGciOiJIUzI1NiJ9.secret-part-one";
    private static final String SECRET_TAIL = "secret-part-two";

    private HttpServer server;
    private final AtomicInteger requests = new AtomicInteger();

    @BeforeEach
    void start() throws Exception {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", exchange -> {
            requests.incrementAndGet();
            exchange.sendResponseHeaders(204, -1);
            exchange.close();
        });
        server.start();
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    private String url() {
        return "http://" + InetAddress.getLoopbackAddress().getHostAddress() + ":"
                + server.getAddress().getPort() + "/";
    }

    private static void assertSilentAbout(Throwable failure) {
        for (Throwable link = failure; link != null; link = link.getCause()) {
            String text = link.getMessage() + " " + link;
            assertFalse(text.contains("secret-part"), "a failure must not quote the header it refused: " + link);
        }
    }

    @Test
    void aHeaderValueWithALineBreakIsRefusedWithoutBeingQuoted() {
        for (String breaker : new String[] {"\n", "\r\n", "\r", "\u0000", "\n "}) {
            Map<String, String> headers = Map.of("Authorization", "Bearer " + SECRET + breaker + SECRET_TAIL);

            Exception failure = assertThrows(Exception.class, () -> http.getForStatus(url(), headers, null));

            assertSilentAbout(failure);
        }
        assertEquals(0, requests.get(), "nothing may be sent with a header that could be split in two");
    }

    @Test
    void everyRequestShapeRefusesIt() {
        Map<String, String> headers = Map.of("Authorization", "Bearer " + SECRET + "\n" + SECRET_TAIL);

        assertSilentAbout(assertThrows(Exception.class, () -> http.get(url(), headers, null)));
        assertSilentAbout(assertThrows(Exception.class, () -> http.postJson(url(), headers, "{}", null)));
        assertSilentAbout(assertThrows(Exception.class, () -> http.postFormForStatus(url(), headers, "a=b", null)));
        assertSilentAbout(assertThrows(Exception.class, () -> http.getBytes(url(), headers, 1024, null)));
        assertSilentAbout(assertThrows(Exception.class, () -> http.getHeader(url(), headers, "Location", null)));
        assertSilentAbout(
                assertThrows(Exception.class, () -> http.sendForStatus("PUT", url(), null, headers, null, null)));
        assertEquals(0, requests.get());
    }

    @Test
    void aHeaderNameWithALineBreakIsRefusedToo() {
        Map<String, String> headers = Map.of("X-secret-part\nInjected", "value");

        assertSilentAbout(assertThrows(Exception.class, () -> http.getForStatus(url(), headers, null)));
        assertEquals(0, requests.get());
    }

    /**
     * The proxy credential is the route's to place. A caller that names it itself would put it on a
     * connection the JDK sends straight to the origin, so it is refused on every request shape, in any
     * capitalisation, before anything is sent.
     */
    @Test
    void aCallerSetProxyCredentialIsRefusedOnEveryRequestShape() {
        for (String name : new String[] {"Proxy-Authorization", "proxy-authorization", "PROXY-AUTHORIZATION"}) {
            Map<String, String> headers = Map.of(name, "Basic " + SECRET);

            assertSilentAbout(assertThrows(IllegalArgumentException.class, () -> http.get(url(), headers, null)));
            assertSilentAbout(
                    assertThrows(IllegalArgumentException.class, () -> http.postJson(url(), headers, "{}", null)));
            assertSilentAbout(assertThrows(
                    IllegalArgumentException.class, () -> http.postFormForStatus(url(), headers, "a=b", null)));
            assertSilentAbout(
                    assertThrows(IllegalArgumentException.class, () -> http.getBytes(url(), headers, 1024, null)));
            assertSilentAbout(assertThrows(
                    IllegalArgumentException.class, () -> http.getHeader(url(), headers, "Location", null)));
            assertSilentAbout(assertThrows(
                    IllegalArgumentException.class, () -> http.sendForStatus("PUT", url(), null, headers, null, null)));
        }
        assertEquals(0, requests.get(), "nothing was sent with a caller-set proxy credential");
    }

    @Test
    void anOrdinaryHeaderStillGoesThrough() throws Exception {
        HttpTransport.HttpResponse response =
                http.getForStatus(url(), Map.of("Authorization", "Bearer " + SECRET), null);

        assertEquals(204, response.status());
    }
}

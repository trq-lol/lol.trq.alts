package lol.trq.alts.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class HttpUtilStatusTest {

    private final HttpTransport http = TestTransports.direct();

    private HttpServer server;

    private volatile String retryAfter;

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    private String startServer(int status, String body) throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/token", exchange -> {
            exchange.getRequestBody().readAllBytes();
            if (retryAfter != null) {
                exchange.getResponseHeaders().add("Retry-After", retryAfter);
            }
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        server.start();
        return "http://" + InetAddress.getLoopbackAddress().getHostAddress() + ":"
                + server.getAddress().getPort() + "/token";
    }

    @Test
    void reportsSuccessStatusAndBody() throws Exception {
        String url = startServer(200, "{\"access_token\":\"a\"}");

        HttpTransport.HttpResponse response = http.postFormForStatus(url, null, "grant_type=refresh_token");

        assertEquals(200, response.status());
        assertTrue(response.successful());
        assertNotNull(response.body());
        assertEquals("a", response.body().get("access_token").getAsString());
    }

    @Test
    void reportsClientErrorStatusAndParsesErrorBody() throws Exception {
        String url = startServer(400, "{\"error\":\"invalid_grant\"}");

        HttpTransport.HttpResponse response = http.postFormForStatus(url, null, "grant_type=refresh_token");

        assertEquals(400, response.status());
        assertFalse(response.successful());
        assertNotNull(response.body(), "the error body must survive so the caller can classify the failure");
        assertEquals("invalid_grant", response.body().get("error").getAsString());
    }

    @Test
    void reportsServerErrorStatus() throws Exception {
        String url = startServer(503, "unavailable");

        HttpTransport.HttpResponse response = http.postFormForStatus(url, null, "grant_type=refresh_token");

        assertEquals(503, response.status());
        assertFalse(response.successful());
        assertNull(response.body(), "a non-JSON error body parses to null rather than throwing");
    }

    /** The batch endpoints answer with a top-level array, which the object-only reader reports as no body. */
    @Test
    void anArrayBodyIsReadByTheElementMethodAndInvisibleToTheObjectOne() throws Exception {
        String url = startServer(200, "[{\"id\":\"1\"},{\"id\":\"2\"}]");

        HttpTransport.JsonResponse element =
                http.postJsonForElement(url, null, "[\"a\",\"b\"]", NetworkScope.of(NetworkScope.Purpose.PROFILE));
        HttpTransport.HttpResponse object = http.postJsonForStatus(url, null, "[\"a\",\"b\"]", null);

        assertTrue(element.successful());
        assertTrue(element.body().isJsonArray());
        assertEquals(2, element.body().getAsJsonArray().size());
        assertNull(object.body(), "the object reader keeps reporting an array as no body");
    }

    @Test
    void theElementMethodCarriesAnErrorStatusItsBodyAndTheStatedWait() throws Exception {
        retryAfter = "21";
        String url = startServer(429, "{\"error\":\"TooManyRequests\"}");

        HttpTransport.JsonResponse response = http.postJsonForElement(url, null, "[]", null);

        assertEquals(429, response.status());
        assertTrue(response.rateLimited());
        assertFalse(response.successful());
        assertEquals(java.time.Duration.ofSeconds(21), response.retryAfter());
        assertEquals(
                "TooManyRequests",
                response.body().getAsJsonObject().get("error").getAsString());
    }

    @Test
    void theElementMethodReportsANonJsonOrEmptyBodyAsNull() throws Exception {
        String url = startServer(503, "unavailable");
        assertNull(http.postJsonForElement(url, null, "[]", null).body());
        server.stop(0);

        url = startServer(200, "null");
        assertNull(http.postJsonForElement(url, null, "[]", null).body(), "a JSON null is no body");
    }

    /** The new method is one more way out of the library, so it must fail closed like the rest. */
    @Test
    void theElementMethodFailsClosedWhenTheProxyProviderDoes() throws Exception {
        java.util.concurrent.atomic.AtomicInteger hits = new java.util.concurrent.atomic.AtomicInteger();
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/token", exchange -> {
            hits.incrementAndGet();
            exchange.sendResponseHeaders(204, -1);
            exchange.close();
        });
        server.start();
        String url = "http://" + InetAddress.getLoopbackAddress().getHostAddress() + ":"
                + server.getAddress().getPort() + "/token";
        HttpTransport http = TestTransports.through(scope -> null);

        assertThrows(
                IOException.class,
                () -> http.postJsonForElement(url, null, "[]", NetworkScope.of(NetworkScope.Purpose.PROFILE)));
        assertEquals(0, hits.get(), "a provider with no answer must not become a direct connection");
    }

    @Test
    void theElementMethodRefusesABodyPastTheCap() throws Exception {
        String url = startServer(200, "[\"" + "x".repeat(HttpTransport.MAX_TEXT_BODY_BYTES) + "\"]");

        assertThrows(IOException.class, () -> http.postJsonForElement(url, null, "[]", null));
    }

    /**
     * A token endpoint answers with the tokens, and a sign-in redirect carries them in its address. A
     * host that logs the response it got must not have written a credential by doing so.
     */
    @Test
    void aResponsePrintsItsStatusButNeverItsBodyOrHeaderValue() throws Exception {
        String url = startServer(200, "{\"access_token\":\"SECRET-TOKEN\"}");

        String object = http.postJsonForStatus(url, null, "{}", null).toString();
        String element = http.postJsonForElement(url, null, "{}", null).toString();
        String header =
                new HttpTransport.HeaderResponse(302, "https://login.example/#accessToken=SECRET-TOKEN").toString();

        assertFalse(object.contains("SECRET-TOKEN"), object);
        assertFalse(element.contains("SECRET-TOKEN"), element);
        assertFalse(header.contains("SECRET-TOKEN"), header);
        assertTrue(object.contains("200") && element.contains("200") && header.contains("302"));
    }
}

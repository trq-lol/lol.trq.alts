package lol.trq.alts.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * How much of a response is read. A JSON body from these services is a few kilobytes, so one that runs
 * to megabytes is a broken or hostile peer — plausibly a proxy the host does not control — and reading
 * it whole is how a single response exhausts the heap.
 */
class HttpUtilBodyLimitTest {

    private HttpServer server;

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    /** Starts a server answering {@code /body} with a JSON object padded to exactly {@code size} bytes. */
    private String startServer(int status, int size) throws IOException {
        String prefix = "{\"pad\":\"";
        String suffix = "\"}";
        byte[] bytes = (prefix + "x".repeat(size - prefix.length() - suffix.length()) + suffix)
                .getBytes(StandardCharsets.UTF_8);
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/body", exchange -> {
            exchange.getRequestBody().readAllBytes();
            exchange.sendResponseHeaders(status, bytes.length);
            try {
                exchange.getResponseBody().write(bytes);
            } catch (IOException clientGaveUp) {
                // Expected once the client stops reading at its limit.
            }
            exchange.close();
        });
        server.start();
        return "http://" + InetAddress.getLoopbackAddress().getHostAddress() + ":"
                + server.getAddress().getPort() + "/body";
    }

    @Test
    void aBodyAtTheLimitIsRead() throws Exception {
        String url = startServer(200, HttpUtil.MAX_TEXT_BODY_BYTES);

        JsonObject response = HttpUtil.get(url, null);

        assertNotNull(response);
        assertEquals(
                HttpUtil.MAX_TEXT_BODY_BYTES - 10,
                response.get("pad").getAsString().length());
    }

    @Test
    void aJsonBodyPastTheLimitFailsTheRequest() throws Exception {
        String url = startServer(200, HttpUtil.MAX_TEXT_BODY_BYTES + 1);

        assertThrows(IOException.class, () -> HttpUtil.get(url, null));
        assertThrows(IOException.class, () -> HttpUtil.postJson(url, null, "{}"));
    }

    @Test
    void aStatusResponsePastTheLimitFailsTheRequestRatherThanReportingAnEmptyBody() throws Exception {
        String url = startServer(200, HttpUtil.MAX_TEXT_BODY_BYTES + 1);

        assertThrows(IOException.class, () -> HttpUtil.postFormForStatus(url, null, "a=b"));
    }

    @Test
    void anErrorBodyPastTheLimitFailsTheRequestToo() throws Exception {
        String url = startServer(400, HttpUtil.MAX_TEXT_BODY_BYTES + 1);

        assertThrows(IOException.class, () -> HttpUtil.postFormForStatus(url, null, "a=b"));
    }

    @Test
    void anOversizedErrorBodyNobodyReadsDoesNotFailTheRequest() throws Exception {
        String url = startServer(500, 4 * HttpUtil.MAX_TEXT_BODY_BYTES);

        assertNull(HttpUtil.get(url, null), "a rejection stays a rejection however large its body");
    }

    @Test
    void theBinaryCapIsTheCallersOwn() throws Exception {
        String url = startServer(200, 2 * HttpUtil.MAX_TEXT_BODY_BYTES);

        assertNotNull(HttpUtil.getBytes(url, null, 4L * HttpUtil.MAX_TEXT_BODY_BYTES, null));
        assertNull(HttpUtil.getBytes(url, null, 1024, null), "a body past the caller's cap is not returned");
    }
}

package lol.trq.alts.internal.net;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import lol.trq.alts.net.NetworkScope;
import org.junit.jupiter.api.Test;

/** {@link HttpTransport#exchange}: the raw body of any status, under the caller's cap. */
class HttpTransportExchangeTest {

    @Test
    void readsAnErrorBodyRefusesOnePastTheCapAndANonPositiveCap() throws Exception {
        byte[] body = "{\"error\":\"x\"}".getBytes(StandardCharsets.UTF_8);
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", ex -> {
            ex.sendResponseHeaders(403, body.length);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(body);
            }
        });
        server.start();
        ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
        try (HttpTransport t = new HttpTransport(null, executor)) {
            String url = "http://127.0.0.1:" + server.getAddress().getPort() + "/";
            NetworkScope scope = NetworkScope.of(NetworkScope.Purpose.VAULT);
            HttpTransport.RawResponse r = t.exchange("GET", url, null, null, null, body.length, scope);
            assertEquals(403, r.status());
            assertArrayEquals(body, r.body());
            assertThrows(IOException.class, () -> t.exchange("GET", url, null, null, null, body.length - 1, scope));
            assertThrows(IllegalArgumentException.class, () -> t.exchange("GET", url, null, null, null, 0, scope));
        } finally {
            server.stop(0);
            executor.shutdownNow();
        }
    }
}

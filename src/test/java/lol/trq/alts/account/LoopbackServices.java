package lol.trq.alts.account;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import lol.trq.alts.net.TestTransports;

/**
 * A loopback stand-in for the Minecraft services, shared by the account tests: it answers every request
 * with whatever the test last canned, and remembers what it was asked so the test can assert on the
 * method, the path as it arrived on the wire, the headers that matter, and the body.
 */
final class LoopbackServices implements AutoCloseable {

    /** One request as the server saw it. */
    record Request(String method, String rawPath, String authorization, String contentType, byte[] body) {

        String bodyText() {
            return new String(body, StandardCharsets.UTF_8);
        }
    }

    private final HttpServer server;
    private final List<Request> requests = new CopyOnWriteArrayList<>();

    private volatile int status = 200;
    private volatile String body = "{}";
    private volatile String retryAfter;

    LoopbackServices() throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", exchange -> {
            requests.add(new Request(
                    exchange.getRequestMethod(),
                    exchange.getRequestURI().getRawPath(),
                    exchange.getRequestHeaders().getFirst("Authorization"),
                    exchange.getRequestHeaders().getFirst("Content-Type"),
                    exchange.getRequestBody().readAllBytes()));
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            if (retryAfter != null) {
                exchange.getResponseHeaders().add("Retry-After", retryAfter);
            }
            exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
            if (bytes.length > 0) {
                exchange.getResponseBody().write(bytes);
            }
            exchange.close();
        });
        server.start();
    }

    /** The base URL to hand to {@link AccountEndpoints}. */
    String base() {
        return "http://" + InetAddress.getLoopbackAddress().getHostAddress() + ":"
                + server.getAddress().getPort();
    }

    AccountEndpoints endpoints() {
        return new AccountEndpoints(base());
    }

    /** Services for a test account over this server. */
    AccountServices services() {
        return AccountServices.create(
                TestTransports.direct(), "test-token", "11111111-2222-3333-4444-555555555555", endpoints());
    }

    /** Sets what every following request is answered with. */
    void canned(int newStatus, String newBody) {
        status = newStatus;
        body = newBody;
        retryAfter = null;
    }

    /** Sets a rate-limit answer carrying a {@code Retry-After} of the given seconds. */
    void rateLimited(int seconds) {
        status = 429;
        body = "{\"path\":\"/\",\"error\":\"TOO_MANY_REQUESTS\",\"errorMessage\":\"Too many requests\"}";
        retryAfter = Integer.toString(seconds);
    }

    List<Request> requests() {
        return requests;
    }

    Request last() {
        return requests.get(requests.size() - 1);
    }

    @Override
    public void close() {
        server.stop(0);
    }
}

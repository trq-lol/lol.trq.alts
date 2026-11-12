package lol.trq.alts.auth;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A loopback stand-in for every service the Microsoft sign-in chain talks to, so a login route can be
 * run end to end without the internet. Each endpoint answers a canned success until a test overrides
 * its status or body, and the device-code token endpoint plays back a scripted sequence of answers.
 */
final class AuthChainServer implements AutoCloseable {

    static final String UNDASHED_UUID = "00000000000040008000000000000001";
    static final String UUID = "00000000-0000-4000-8000-000000000001";

    private final HttpServer server;
    private final Map<String, Integer> statuses = new ConcurrentHashMap<>();
    private final Map<String, String> bodies = new ConcurrentHashMap<>();
    private final Map<String, String> lastRequestBodies = new ConcurrentHashMap<>();
    private final Deque<String[]> deviceTokenScript = new ArrayDeque<>();
    private final List<Long> deviceTokenPollNanos = Collections.synchronizedList(new ArrayList<>());
    private final AtomicInteger profileCalls = new AtomicInteger();

    AuthChainServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        bodies.put("/token", "{\"access_token\":\"ms-access\",\"refresh_token\":\"ms-refresh\",\"expires_in\":3600}");
        bodies.put(
                "/devicecode",
                "{\"device_code\":\"secret-device-code\",\"user_code\":\"ABCD-EFGH\","
                        + "\"verification_uri\":\"https://verify.example/device\",\"expires_in\":900,\"interval\":1,"
                        + "\"message\":\"enter ABCD-EFGH\"}");
        bodies.put("/xbl", "{\"Token\":\"xbl\"}");
        bodies.put("/xsts", "{\"Token\":\"xsts\",\"DisplayClaims\":{\"xui\":[{\"uhs\":\"hash\"}]}}");
        bodies.put("/mclogin", "{\"access_token\":\"mc-access\",\"expires_in\":86400}");
        bodies.put("/mcprofile", "{\"id\":\"" + UNDASHED_UUID + "\",\"name\":\"Alex\"}");

        for (String path : List.of("/token", "/devicecode", "/xbl", "/xsts", "/mclogin")) {
            server.createContext(path, exchange -> answer(exchange, path));
        }
        server.createContext("/mcprofile", exchange -> {
            profileCalls.incrementAndGet();
            answer(exchange, "/mcprofile");
        });
        server.createContext("/devicetoken", this::answerDeviceToken);
        server.start();
    }

    private void answer(HttpExchange exchange, String path) throws IOException {
        lastRequestBodies.put(path, new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
        int status = statuses.getOrDefault(path, 200);
        respond(exchange, status, status == 200 || bodies.containsKey(path + "!") ? body(path) : "{}");
    }

    private String body(String path) {
        return bodies.getOrDefault(path + "!", bodies.get(path));
    }

    private void answerDeviceToken(HttpExchange exchange) throws IOException {
        lastRequestBodies.put(
                "/devicetoken", new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
        deviceTokenPollNanos.add(System.nanoTime());
        String[] next;
        synchronized (deviceTokenScript) {
            // The last scripted answer repeats, so "pending forever" is a one-entry script.
            next = deviceTokenScript.size() > 1 ? deviceTokenScript.poll() : deviceTokenScript.peek();
        }
        if (next == null) {
            respond(exchange, 200, bodies.get("/token"));
        } else {
            respond(exchange, Integer.parseInt(next[0]), next[1]);
        }
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    /** Makes an endpoint answer {@code status} with an empty JSON object. */
    void fail(String path, int status) {
        statuses.put(path, status);
    }

    /** Makes an endpoint answer {@code status} with the given body. */
    void fail(String path, int status, String body) {
        statuses.put(path, status);
        bodies.put(path + "!", body);
    }

    /** Replaces an endpoint's success body. */
    void body(String path, String body) {
        bodies.put(path, body);
    }

    /** Queues a device-token answer carrying an OAuth error code. */
    void deviceTokenError(String error) {
        deviceTokenAnswer(400, "{\"error\":\"" + error + "\"}");
    }

    /** Queues the device-token success answer. */
    void deviceTokenSuccess() {
        deviceTokenAnswer(200, bodies.get("/token"));
    }

    void deviceTokenAnswer(int status, String body) {
        synchronized (deviceTokenScript) {
            deviceTokenScript.add(new String[] {String.valueOf(status), body});
        }
    }

    int deviceTokenPolls() {
        return deviceTokenPollNanos.size();
    }

    /** {@return the gap in milliseconds between two polls, counted from one} */
    long millisBetweenPolls(int earlier, int later) {
        return (deviceTokenPollNanos.get(later - 1) - deviceTokenPollNanos.get(earlier - 1)) / 1_000_000L;
    }

    int profileCalls() {
        return profileCalls.get();
    }

    /** {@return the decoded form parameters the endpoint last received} */
    Map<String, String> lastForm(String path) {
        Map<String, String> form = new LinkedHashMap<>();
        for (String pair : lastRequestBodies.getOrDefault(path, "").split("&")) {
            int equals = pair.indexOf('=');
            if (equals > 0) {
                form.put(
                        URLDecoder.decode(pair.substring(0, equals), StandardCharsets.UTF_8),
                        URLDecoder.decode(pair.substring(equals + 1), StandardCharsets.UTF_8));
            }
        }
        return form;
    }

    String base() {
        return "http://" + InetAddress.getLoopbackAddress().getHostAddress() + ":"
                + server.getAddress().getPort();
    }

    MicrosoftAuthConfig config() {
        String base = base();
        return MicrosoftAuthConfig.of("test-client-id")
                .withEndpoints(
                        base + "/authorize",
                        base + "/token",
                        base + "/xbl",
                        base + "/xsts",
                        base + "/mclogin",
                        base + "/mcprofile")
                .withDeviceCodeEndpoints(base + "/devicecode", base + "/devicetoken");
    }

    /**
     * Plays the user's browser for the interactive login: reads the redirect and state out of the
     * authorization address and calls the redirect back with a code, as the identity service would.
     */
    static void completeInBrowser(String authorizationUrl) {
        Map<String, String> query = query(authorizationUrl);
        Thread.ofVirtual().start(() -> {
            try {
                get(query.get("redirect_uri") + "?code=auth-code&state=" + query.get("state"));
            } catch (IOException ignored) {
                // The test asserts on the login's outcome, which is where a failed callback shows.
            }
        });
    }

    static Map<String, String> query(String url) {
        Map<String, String> query = new LinkedHashMap<>();
        for (String pair : url.substring(url.indexOf('?') + 1).split("&")) {
            int equals = pair.indexOf('=');
            query.put(
                    URLDecoder.decode(pair.substring(0, equals), StandardCharsets.UTF_8),
                    URLDecoder.decode(pair.substring(equals + 1), StandardCharsets.UTF_8));
        }
        return query;
    }

    /** {@return the status a plain GET to {@code url} is answered with} */
    static int get(String url) throws IOException {
        HttpURLConnection connection =
                (HttpURLConnection) URI.create(url).toURL().openConnection();
        connection.setConnectTimeout(5_000);
        connection.setReadTimeout(5_000);
        try {
            return connection.getResponseCode();
        } finally {
            connection.disconnect();
        }
    }

    @Override
    public void close() {
        server.stop(0);
    }
}

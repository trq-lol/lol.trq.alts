package lol.trq.alts.net;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import lol.trq.alts.auth.AltLoginCallback.FailureReason;
import lol.trq.alts.auth.MicrosoftAuthConfig;
import lol.trq.alts.auth.MicrosoftAuthUtil;

/**
 * A temporary local HTTP server that captures the authorization code returned by Microsoft's OAuth2
 * redirect. Listens on the loopback addresses only and shuts itself down as soon as the code future
 * completes, however it completes: with the code, with a failure, on the timeout, or by cancellation.
 *
 * <p>The redirect names {@code localhost}, and which address that is belongs to the user's system: some
 * resolve it to {@code ::1} first. So the server listens on both {@code 127.0.0.1} and {@code ::1}, on
 * the same port, wherever both exist. A system without one of them is served on the other.
 * The client id, scope, authorize endpoint, and callback path all come from the host-supplied
 * {@link MicrosoftAuthConfig}.
 *
 * <p>Any page open in the user's browser can send a request to a loopback port, so a request is only
 * allowed to decide the outcome when it carries the {@code state} this login generated. Everything else
 * is answered {@code 400} and ignored, and the server keeps waiting for the real redirect.
 *
 * @author trq
 * @since 0.1.0
 */
public class MicrosoftCallbackServer {

    /** Ports to attempt binding, in order of preference. */
    private static final int[] PORTS = {59125, 25585, 25575, 25565, 0};

    /** How many times an ephemeral port is drawn before giving up on finding one free on every address. */
    private static final int EPHEMERAL_ATTEMPTS = 8;

    /** How long the user has to finish signing in before the login is abandoned. */
    private static final long TIMEOUT_MINUTES = 5;

    private final String expectedState;
    private final MicrosoftAuthConfig config;
    private final String codeChallenge;
    private final Consumer<String> browser;
    private final CompletableFuture<String> codeFuture = new CompletableFuture<>();
    private final Executor executor;
    private volatile List<HttpServer> servers = List.of();
    private int boundPort;

    /**
     * Initializes a new callback server whose authorization request carries a PKCE challenge.
     *
     * @param state the state string generated during auth initiation, verified against CSRF
     * @param config the host's Microsoft authentication configuration (client id, scope, endpoints)
     * @param codeChallenge the {@code S256} PKCE challenge to send, or {@code null} to send none
     * @param browser what opens the authorization address for the user
     * @param executor the executor the server is stopped on once the code arrives
     * @since 1.0.0
     */
    public MicrosoftCallbackServer(
            String state,
            MicrosoftAuthConfig config,
            String codeChallenge,
            Consumer<String> browser,
            Executor executor) {
        this.executor = Objects.requireNonNull(executor, "executor");
        this.expectedState = Objects.requireNonNull(state, "state");
        this.config = Objects.requireNonNull(config, "config");
        this.codeChallenge = codeChallenge;
        this.browser = Objects.requireNonNull(browser, "browser");
    }

    /**
     * Binds the server to an available port, starts listening for the redirect, and opens the user's
     * browser to the Microsoft login page.
     *
     * <p>Cancelling the returned future stops the server and releases the port.
     *
     * @return a future that completes with the captured authorization code
     */
    public CompletableFuture<String> start() {
        // Registered before anything can complete the future, and run off the completing thread: the
        // completion usually happens on the server's own dispatcher, which must not be asked to stop
        // itself before it has finished writing the response.
        codeFuture.whenComplete((code, failure) -> {
            try {
                executor.execute(this::stop);
            } catch (RejectedExecutionException closed) {
                // The runtime's executor has shut down: stop here rather than leave the port bound.
                stop();
            }
        });
        try {
            bindToAvailablePort();
            for (HttpServer listener : servers) {
                listener.createContext(config.redirectPath(), this::handleCallback);
                listener.setExecutor(null);
                listener.start();
            }

            // The timer is cancelled as soon as the future completes, so nothing outlives the login.
            codeFuture.orTimeout(TIMEOUT_MINUTES, TimeUnit.MINUTES);
            browser.accept(authorizationUrl());
        } catch (Exception e) {
            codeFuture.completeExceptionally(e);
        }
        return codeFuture;
    }

    /**
     * Builds the address the user signs in at. Only meaningful once the server is bound, since the
     * redirect it names carries the bound port.
     *
     * @return the authorization URL
     * @since 0.12.0
     */
    public String authorizationUrl() {
        StringBuilder url = new StringBuilder(config.authorizeUrl())
                .append("?client_id=")
                .append(encode(config.clientId()))
                .append("&response_type=code&scope=")
                .append(encode(config.scope()))
                .append("&redirect_uri=")
                .append(encode(redirectUri()))
                .append("&prompt=select_account&state=")
                .append(encode(expectedState));
        if (codeChallenge != null) {
            url.append("&code_challenge=").append(encode(codeChallenge)).append("&code_challenge_method=S256");
        }
        return url.toString();
    }

    /**
     * Binds a listener on every loopback address the system has, all on the first port in
     * {@link #PORTS} that is free on each of them. Loopback addresses are named explicitly so the
     * listener is never reachable from another machine.
     *
     * <p>A port is taken only when every available loopback address could be bound to it. Settling for
     * one would leave the other to whatever else is listening there, and the browser, not the library,
     * chooses which one {@code localhost} means.
     *
     * @throws IOException if no port could be bound on the loopback addresses
     */
    private void bindToAvailablePort() throws IOException {
        List<InetAddress> loopbacks = availableLoopbacks();
        if (loopbacks.isEmpty()) {
            throw new IOException("No loopback address available");
        }
        for (int port : PORTS) {
            int attempts = port == 0 ? EPHEMERAL_ATTEMPTS : 1;
            for (int attempt = 0; attempt < attempts; attempt++) {
                List<HttpServer> bound = bindAll(loopbacks, port);
                if (bound != null) {
                    boundPort = bound.get(0).getAddress().getPort();
                    servers = bound;
                    return;
                }
            }
        }
        throw new IOException("No ports available");
    }

    /**
     * Binds one listener per address, all on the same port.
     *
     * @param addresses the loopback addresses to listen on
     * @param port the port to bind, or 0 to let the first address draw one for all of them
     * @return the bound listeners, or null when the port was not free on every address
     * @throws IOException if a listener cannot be created at all
     */
    private static List<HttpServer> bindAll(List<InetAddress> addresses, int port) throws IOException {
        List<HttpServer> bound = new ArrayList<>(addresses.size());
        int chosen = port;
        for (InetAddress address : addresses) {
            HttpServer listener = HttpServer.create();
            try {
                listener.bind(new InetSocketAddress(address, chosen), 0);
            } catch (IOException taken) {
                for (HttpServer earlier : bound) {
                    earlier.stop(0);
                }
                return null;
            }
            bound.add(listener);
            chosen = listener.getAddress().getPort();
        }
        return List.copyOf(bound);
    }

    /**
     * Returns the loopback addresses this system can listen on: {@code 127.0.0.1}, {@code ::1}, or both.
     * An address family the system does not have is simply left out.
     *
     * @return the usable loopback addresses, IPv4 first
     */
    private static List<InetAddress> availableLoopbacks() {
        List<InetAddress> usable = new ArrayList<>(2);
        byte[][] candidates = {{127, 0, 0, 1}, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}};
        for (byte[] raw : candidates) {
            try {
                InetAddress address = InetAddress.getByAddress(raw);
                try (ServerSocket probe = new ServerSocket()) {
                    probe.bind(new InetSocketAddress(address, 0));
                }
                usable.add(address);
            } catch (IOException | RuntimeException unavailable) {
                // No such address family here; the other one carries the redirect.
            }
        }
        return usable;
    }

    /**
     * Handles a request to the callback path. Only a request carrying this login's {@code state} may
     * complete the future; anything else is refused and ignored.
     *
     * @param exchange the HTTP exchange object
     * @throws IOException if stream writing fails
     */
    private void handleCallback(HttpExchange exchange) throws IOException {
        // Security check: only allow requests originating from the local machine
        if (!exchange.getRemoteAddress().getAddress().isLoopbackAddress()) {
            exchange.close();
            return;
        }

        Map<String, String> params = parseQuery(exchange.getRequestURI().getRawQuery());

        // Without the state this is not the redirect this login asked for. It must not be allowed to
        // fail the login either: any web page can send a request here, and one that could end a pending
        // sign-in just by guessing the port would be a denial of service against it.
        if (!stateMatches(params.get("state"))) {
            sendResponse(exchange, 400, "Authentication Failed.");
            return;
        }

        if (params.containsKey("error")) {
            // A stated refusal, vouched for by the state. The error text itself is kept out of the
            // message: it is service-supplied and of no use to a host branching on the reason.
            boolean declined = "access_denied".equals(params.get("error"));
            sendResponse(exchange, 400, "Authentication Failed.");
            codeFuture.completeExceptionally(new MicrosoftAuthUtil.AuthFlowException(
                    declined ? "Sign-in was declined" : "Authorization was refused",
                    declined ? FailureReason.DECLINED : FailureReason.UNKNOWN));
            return;
        }

        String code = params.get("code");
        if (code == null || code.isEmpty()) {
            sendResponse(exchange, 400, "Authentication Failed.");
            return;
        }

        sendResponse(exchange, 200, "Authentication Successful. You may close this tab.");
        codeFuture.complete(code);
    }

    /**
     * Compares a received state against the expected one in constant time.
     *
     * @param received the state the request carried, or {@code null}
     * @return true if it is this login's state
     */
    private boolean stateMatches(String received) {
        return received != null
                && MessageDigest.isEqual(
                        received.getBytes(StandardCharsets.UTF_8), expectedState.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Splits a raw query string into decoded parameters. Each name is matched whole, so
     * {@code error_code=} is never mistaken for {@code code=}, and each value is decoded exactly once,
     * which is what makes the code the credential the token endpoint expects. The first occurrence of a
     * repeated name wins.
     *
     * <p>Package-private so the parsing can be tested without a server.
     *
     * @param rawQuery the undecoded query string, or {@code null}
     * @return the decoded parameters, empty when there is no query
     */
    static Map<String, String> parseQuery(String rawQuery) {
        Map<String, String> params = new LinkedHashMap<>();
        if (rawQuery == null || rawQuery.isEmpty()) {
            return params;
        }
        for (String pair : rawQuery.split("&")) {
            if (pair.isEmpty()) {
                continue;
            }
            int equals = pair.indexOf('=');
            String name = equals == -1 ? pair : pair.substring(0, equals);
            String value = equals == -1 ? "" : pair.substring(equals + 1);
            try {
                params.putIfAbsent(
                        URLDecoder.decode(name, StandardCharsets.UTF_8),
                        URLDecoder.decode(value, StandardCharsets.UTF_8));
            } catch (IllegalArgumentException malformedEscape) {
                // A pair that does not decode is not one the service sent; skip it.
            }
        }
        return params;
    }

    /**
     * Sends a simple HTML response back to the user's browser.
     *
     * @param exchange the HTTP exchange
     * @param status the HTTP status code
     * @param message the message to display in the browser
     * @throws IOException if writing to the response body fails
     */
    private void sendResponse(HttpExchange exchange, int status, String message) throws IOException {
        String html =
                "<!DOCTYPE html><html><body style='font-family:sans-serif;text-align:center;padding-top:50px;'><h1>"
                        + message + "</h1></body></html>";
        byte[] response = html.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "text/html; charset=UTF-8");
        exchange.sendResponseHeaders(status, response.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(response);
        }
        exchange.close();
    }

    /**
     * Returns the full redirect URI used for the OAuth request.
     *
     * @return the absolute loopback URL for the callback
     */
    public String redirectUri() {
        return "http://localhost:" + boundPort + config.redirectPath();
    }

    /** Forcefully stops the HTTP server, releasing its port. Safe to call more than once. */
    public void stop() {
        for (HttpServer running : servers) {
            running.stop(0);
        }
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}

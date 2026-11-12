package lol.trq.alts.net;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URI;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;
import lol.trq.alts.spi.ProxyProvider;

/**
 * Centralized utility for handling HTTP requests to Microsoft, Xbox, and Mojang APIs. Supports JSON
 * and form-encoded payloads with automated header management.
 *
 * <p>Every request the library makes goes through here, which is what lets a host route them: install a
 * {@link ProxyProvider} and each call resolves a {@link ProxyRoute} from its {@link NetworkScope} first.
 * The scope-less overloads are kept for compatibility and resolve as {@link NetworkScope.Purpose#AUTH}.
 *
 * <p>It is also where the transport rules are enforced, once, for every caller:
 *
 * <ul>
 *   <li>Timeouts are finite: ten seconds to connect, thirty to read.
 *   <li>Route resolution fails closed. An installed provider that throws or names no route fails the
 *       request, and a proxy that refuses a tunnel fails it too; nothing falls back to a direct
 *       connection.
 *   <li>A proxy credential is sent to the proxy and nowhere else. An HTTPS target behind an HTTP proxy
 *       is reached through a tunnel the library opens itself, so the credential rides the
 *       {@code CONNECT} and is never inside the TLS stream the origin reads.
 *   <li>A kept-alive connection is only reused by the proxy identity that opened it: proxy host, port,
 *       and credential.
 *   <li>TLS uses the JVM's default trust with hostname verification on, tunnelled or not.
 *   <li>Redirects are not followed, except by the binary fetch, which never carries a credential across
 *       origins and never steps down from {@code https} to {@code http}.
 *   <li>A JSON or text body is read up to one mebibyte; a longer one fails the request.
 * </ul>
 *
 * <p>The methods here block. Run them on {@link IoExecutor#executor()} rather than the common pool.
 *
 * <p>Nothing here changes process-wide JVM state: no system property, default authenticator, default
 * {@code SSLContext}, or proxy selector is installed.
 *
 * @author trq
 * @since 0.1.0
 */
public final class HttpUtil {

    /** How long to wait for the TCP connection before giving the request up. */
    private static final int CONNECT_TIMEOUT_MILLIS = 10_000;

    /** How long to wait for response bytes before giving the request up. */
    private static final int READ_TIMEOUT_MILLIS = 30_000;

    /**
     * Largest JSON or text response body read. Every body these endpoints legitimately send is a few
     * kilobytes; an unbounded read is a memory hazard the moment a response arrives through a proxy the
     * library does not control.
     */
    static final int MAX_TEXT_BODY_BYTES = 1 << 20;

    /** How many redirects one fetch follows before the chain is treated as a loop. */
    private static final int MAX_REDIRECTS = 5;

    /** How much of an unwanted body is drained to keep its connection reusable before giving it up. */
    private static final int MAX_DISCARDED_BYTES = 64 * 1024;

    /** How many proxy identities keep a tunnel factory, and with it a set of reusable connections. */
    static final int MAX_TUNNEL_FACTORIES = 64;

    private static final Map<TunnelIdentity, ProxyTunnelSocketFactory> TUNNEL_FACTORIES =
            new LinkedHashMap<>(16, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<TunnelIdentity, ProxyTunnelSocketFactory> eldest) {
                    return size() > MAX_TUNNEL_FACTORIES;
                }
            };

    private static volatile ProxyProvider proxyProvider;

    private static volatile SSLSocketFactory tlsOverride;

    private HttpUtil() {}

    /**
     * Binds the host's proxy provider. Called by {@code AltsRuntime.Builder#build()}; until one is bound
     * every request is direct.
     *
     * <p>A {@code null} never removes a provider that is already installed. The provider is static, so a
     * second runtime built without one would otherwise turn every request direct behind the back of the
     * host that installed the first — the same silent disclosure that failing closed exists to prevent.
     * A later non-null provider replaces the earlier one.
     *
     * @param provider the host-supplied proxy provider, or null to leave the current one in place
     * @since 0.8.0
     */
    public static void bind(ProxyProvider provider) {
        if (provider != null) {
            proxyProvider = provider;
        }
    }

    /**
     * Removes the installed proxy provider, returning every request to direct. The one deliberate way
     * to do that: {@link #bind(ProxyProvider)} ignores {@code null}. For tests, which share this static
     * across classes and must not leave a provider pointing at a closed socket.
     *
     * @since 0.12.0
     */
    public static void resetForTests() {
        proxyProvider = null;
        tlsSocketFactoryForTests(null);
    }

    /**
     * Resolves the route a request should take.
     *
     * <p>Fails closed once a provider is installed: a provider that throws or returns null fails the
     * request rather than quietly connecting directly, because a silent fallback discloses the host's
     * real address at the moment it believed it was proxied.
     *
     * @param scope what is being fetched; null resolves as {@link NetworkScope.Purpose#AUTH}
     * @return the route to use
     * @throws IOException if an installed provider could not name one
     */
    static ProxyRoute routeFor(NetworkScope scope) throws IOException {
        ProxyProvider provider = proxyProvider;
        if (provider == null) {
            return ProxyRoute.direct();
        }
        NetworkScope effective = scope == null ? NetworkScope.of(NetworkScope.Purpose.AUTH) : scope;
        ProxyRoute route;
        try {
            route = provider.routeFor(effective);
        } catch (RuntimeException failure) {
            throw new IOException("proxy resolution failed for " + effective.purpose(), failure);
        }
        if (route == null) {
            throw new IOException("proxy provider named no route for " + effective.purpose());
        }
        return route;
    }

    /**
     * Applies the connection defaults every request shares. The timeouts are finite because these calls
     * run on a shared thread pool: an endpoint that accepts a connection and then goes silent would
     * otherwise hold a pooled thread for the life of the process and leave the login future to never
     * complete. The JDK's own redirect following is always off, because {@code HttpURLConnection}
     * replays the caller's request properties to the redirect target, which would send an
     * {@code Authorization: Bearer} header to whatever host a {@code 3xx} names. The one call that does
     * follow redirects, {@link #getBytesForStatus(String, Map, long, NetworkScope)}, does so by hand.
     *
     * @param conn the connection to configure
     */
    static void applyDefaults(HttpURLConnection conn) {
        conn.setConnectTimeout(CONNECT_TIMEOUT_MILLIS);
        conn.setReadTimeout(READ_TIMEOUT_MILLIS);
        conn.setInstanceFollowRedirects(false);
    }

    /**
     * Opens a connection over the route the scope resolves to.
     *
     * <p>A direct route opens without naming a proxy, rather than naming {@link java.net.Proxy#NO_PROXY},
     * so the JVM's own proxy configuration keeps working for a host that set one. "Direct" means the
     * library adds no proxy of its own.
     *
     * @param urlString the target URL
     * @param scope what is being fetched, and on whose behalf
     * @return the configured connection
     * @throws IOException if the route cannot be resolved or the connection cannot be opened
     */
    private static HttpURLConnection open(String urlString, NetworkScope scope) throws IOException {
        return open(URI.create(urlString), routeFor(scope));
    }

    /**
     * Opens a connection to a target over an already-resolved route.
     *
     * <p>An HTTPS target behind an HTTP proxy is tunnelled by {@link ProxyTunnelSocketFactory} rather
     * than by the JDK, because the JDK cannot authenticate a {@code CONNECT} per request: it drops a
     * {@code Proxy-Authorization} request property from the {@code CONNECT} and then sends it to the
     * origin inside the tunnel. The connection is opened naming {@link Proxy#NO_PROXY} so that the
     * factory's socket is the only thing deciding where it connects.
     *
     * <p>A plain {@code http} target behind an authenticated proxy does carry the credential as a
     * request header, since there the proxy is the peer that reads it. Such a connection is not kept
     * alive: the JDK pools proxied connections by proxy address alone, and a gateway that pins a session
     * to a connection would hand the next username the previous one's exit address.
     *
     * @param uri the target
     * @param route the route to take
     * @return the configured connection
     * @throws IOException if the target is not HTTP(S) or the connection cannot be opened
     */
    private static HttpURLConnection open(URI uri, ProxyRoute route) throws IOException {
        String scheme = uri.getScheme();
        boolean https = "https".equalsIgnoreCase(scheme);
        if (!https && !"http".equalsIgnoreCase(scheme)) {
            throw new IOException("unsupported URL scheme: " + scheme);
        }
        boolean tunnelled = https && route.kind() == ProxyRoute.Kind.HTTP;
        URLConnection opened;
        if (route.isDirect()) {
            opened = uri.toURL().openConnection();
        } else {
            opened = uri.toURL().openConnection(tunnelled ? Proxy.NO_PROXY : route.toProxy());
        }
        if (!(opened instanceof HttpURLConnection conn)) {
            throw new IOException("the JVM's URL handler for " + scheme + " is not an HTTP connection");
        }
        applyDefaults(conn);

        if (tunnelled) {
            if (!(conn instanceof HttpsURLConnection secure)) {
                // Without the socket-factory hook nothing would carry the request through the proxy.
                throw new IOException("the JVM's https handler cannot be routed through a proxy tunnel");
            }
            secure.setSSLSocketFactory(tunnelFactory(route));
        } else {
            SSLSocketFactory tls = tlsOverride;
            if (tls != null && conn instanceof HttpsURLConnection secure) {
                secure.setSSLSocketFactory(tls);
            }
            String authorization = route.authorizationHeader();
            if (authorization != null) {
                conn.setRequestProperty("Proxy-Authorization", authorization);
                conn.setRequestProperty("Connection", "close");
            }
        }
        return conn;
    }

    /**
     * Returns the tunnel factory for a route, creating it on first use.
     *
     * <p>The factory instance is the reuse boundary: the JDK keys its keep-alive pool on it, so a
     * connection is only ever reused by a request whose route has the same proxy host, port, and
     * credential. Two routes on one gateway that differ only in username — the usual shape of a sticky
     * session — get separate factories and therefore separate tunnels.
     *
     * <p>The cache is bounded and evicts the least recently used identity. An evicted factory's idle
     * connections simply age out of the JDK's pool; a route seen again gets a new factory and a new
     * tunnel, never another identity's.
     *
     * @param route an HTTP proxy route
     * @return the factory owning that identity's tunnels
     */
    private static ProxyTunnelSocketFactory tunnelFactory(ProxyRoute route) {
        TunnelIdentity identity = new TunnelIdentity(
                route.host().toLowerCase(Locale.ROOT), route.port(), route.username(), route.authorizationHeader());
        synchronized (TUNNEL_FACTORIES) {
            return TUNNEL_FACTORIES.computeIfAbsent(
                    identity,
                    key -> new ProxyTunnelSocketFactory(
                            route.host(), key.port(), key.authorization(), HttpUtil::tlsSocketFactory));
        }
    }

    /**
     * Returns the factory that layers TLS: the JVM's default for HTTPS, which is what a direct
     * connection uses, unless a test has substituted its own.
     *
     * @return the TLS socket factory
     */
    private static SSLSocketFactory tlsSocketFactory() {
        SSLSocketFactory tls = tlsOverride;
        return tls != null ? tls : HttpsURLConnection.getDefaultSSLSocketFactory();
    }

    /**
     * Substitutes the factory that layers TLS, so a test can trust a certificate it generated for a
     * loopback origin. Package-private and test-only: production always uses the JVM's default trust,
     * and hostname verification stays on either way.
     *
     * @param factory the factory to use, or null to restore the JVM default
     */
    static void tlsSocketFactoryForTests(SSLSocketFactory factory) {
        tlsOverride = factory;
        synchronized (TUNNEL_FACTORIES) {
            TUNNEL_FACTORIES.clear();
        }
    }

    /**
     * Returns how many route identities currently own a tunnel factory.
     *
     * @return the size of the factory cache
     */
    static int tunnelFactoryCount() {
        synchronized (TUNNEL_FACTORIES) {
            return TUNNEL_FACTORIES.size();
        }
    }

    /**
     * What makes two routes the same for connection reuse: the proxy, and who it is being used as.
     *
     * @param host the proxy host, lower-cased
     * @param port the proxy port
     * @param username the proxy username, or null
     * @param authorization the full credential, so a changed password is a new identity too
     */
    private record TunnelIdentity(String host, int port, String username, String authorization) {}

    /**
     * Sends a POST request with a JSON body.
     *
     * @param urlString the target URL
     * @param headers optional HTTP headers to include in the request
     * @param jsonBody the JSON payload as a string
     * @return the parsed JSON response, or null if the request returned a non-2xx status
     * @throws Exception if a network or protocol error occurs
     */
    public static JsonObject postJson(String urlString, Map<String, String> headers, String jsonBody) throws Exception {
        return postJson(urlString, headers, jsonBody, null);
    }

    /**
     * Sends a POST request with a JSON body over the route the scope resolves to.
     *
     * @param urlString the target URL
     * @param headers optional HTTP headers to include in the request
     * @param jsonBody the JSON payload as a string
     * @param scope what is being fetched, and on whose behalf
     * @return the parsed JSON response, or null if the request returned a non-2xx status
     * @throws Exception if a network or protocol error occurs
     * @since 0.8.0
     */
    public static JsonObject postJson(
            String urlString, Map<String, String> headers, String jsonBody, NetworkScope scope) throws Exception {
        return executeRequest(
                urlString, "POST", "application/json", headers, jsonBody.getBytes(StandardCharsets.UTF_8), scope);
    }

    /**
     * Sends a POST request with an x-www-form-urlencoded body.
     *
     * @param urlString the target URL
     * @param headers optional HTTP headers to include in the request
     * @param formBody the form data payload as a string
     * @return the parsed JSON response, or null if the request failed
     * @throws Exception if a network or protocol error occurs
     */
    public static JsonObject postForm(String urlString, Map<String, String> headers, String formBody) throws Exception {
        return postForm(urlString, headers, formBody, null);
    }

    /**
     * Sends a POST request with an x-www-form-urlencoded body over the route the scope resolves to.
     *
     * @param urlString the target URL
     * @param headers optional HTTP headers to include in the request
     * @param formBody the form data payload as a string
     * @param scope what is being fetched, and on whose behalf
     * @return the parsed JSON response, or null if the request failed
     * @throws Exception if a network or protocol error occurs
     * @since 0.8.0
     */
    public static JsonObject postForm(
            String urlString, Map<String, String> headers, String formBody, NetworkScope scope) throws Exception {
        return executeRequest(
                urlString,
                "POST",
                "application/x-www-form-urlencoded",
                headers,
                formBody.getBytes(StandardCharsets.UTF_8),
                scope);
    }

    /**
     * An HTTP response carrying its status alongside the parsed body, for callers that must
     * distinguish a rejected request from a transient failure.
     *
     * @param status the HTTP status code
     * @param body the parsed JSON body, or {@code null} when the body was absent or not JSON
     * @param retryAfter how long the service asked the caller to wait, or {@code null} when it did not
     * @author trq
     * @since 0.6.0
     */
    public record HttpResponse(int status, JsonObject body, Duration retryAfter) {

        /**
         * Returns whether the status is in the 2xx success range.
         *
         * @return true if the request succeeded
         * @since 0.6.0
         */
        public boolean successful() {
            return status >= 200 && status < 300;
        }

        /**
         * Returns whether the service is asking the caller to slow down.
         *
         * @return true if the status is 429
         * @since 0.8.0
         */
        public boolean rateLimited() {
            return status == 429;
        }
    }

    /**
     * Sends a POST request with an x-www-form-urlencoded body, returning the status alongside the
     * parsed body so the caller can tell a rejection from an outage.
     *
     * @param urlString the target URL
     * @param headers optional HTTP headers to include in the request
     * @param formBody the form data payload as a string
     * @return the status and parsed body; the body is null when absent or not JSON
     * @throws Exception if a network or protocol error occurs
     * @since 0.6.0
     */
    public static HttpResponse postFormForStatus(String urlString, Map<String, String> headers, String formBody)
            throws Exception {
        return postFormForStatus(urlString, headers, formBody, null);
    }

    /**
     * Sends a POST request with an x-www-form-urlencoded body over the route the scope resolves to,
     * returning the status alongside the parsed body.
     *
     * @param urlString the target URL
     * @param headers optional HTTP headers to include in the request
     * @param formBody the form data payload as a string
     * @param scope what is being fetched, and on whose behalf
     * @return the status and parsed body; the body is null when absent or not JSON
     * @throws Exception if a network or protocol error occurs
     * @since 0.8.0
     */
    public static HttpResponse postFormForStatus(
            String urlString, Map<String, String> headers, String formBody, NetworkScope scope) throws Exception {
        return executeForStatus(
                urlString,
                "POST",
                "application/x-www-form-urlencoded",
                headers,
                formBody.getBytes(StandardCharsets.UTF_8),
                scope);
    }

    /**
     * Sends a POST request with a JSON body, returning the status alongside the parsed body, so a caller
     * can read an error body — an XSTS {@code XErr}, say — rather than collapse every failure to null.
     *
     * @param urlString the target URL
     * @param headers optional HTTP headers to include in the request
     * @param jsonBody the JSON payload as a string
     * @return the status and parsed body
     * @throws Exception if a network or protocol error occurs
     * @since 1.0.0
     */
    public static HttpResponse postJsonForStatus(String urlString, Map<String, String> headers, String jsonBody)
            throws Exception {
        return postJsonForStatus(urlString, headers, jsonBody, null);
    }

    /**
     * Sends a POST request with a JSON body over the route the scope resolves to, returning the status
     * alongside the parsed body. The status-carrying counterpart of
     * {@link #postJson(String, Map, String, NetworkScope)}, for a caller that must tell a rate limit or a
     * stated refusal from an outage rather than receive {@code null} for all three.
     *
     * @param urlString the target URL
     * @param headers optional HTTP headers to include in the request
     * @param jsonBody the JSON payload as a string
     * @param scope what is being fetched, and on whose behalf
     * @return the status and parsed body; the body is null when absent or not JSON
     * @throws Exception if a network or protocol error occurs
     * @since 0.12.0
     */
    public static HttpResponse postJsonForStatus(
            String urlString, Map<String, String> headers, String jsonBody, NetworkScope scope) throws Exception {
        return executeForStatus(
                urlString, "POST", "application/json", headers, jsonBody.getBytes(StandardCharsets.UTF_8), scope);
    }

    /**
     * Sends a GET request to the specified URL.
     *
     * @param urlString the target URL
     * @param headers optional HTTP headers to include in the request
     * @return the parsed JSON response, or null if the request failed
     * @throws Exception if a network or protocol error occurs
     */
    public static JsonObject get(String urlString, Map<String, String> headers) throws Exception {
        return get(urlString, headers, null);
    }

    /**
     * Sends a GET request over the route the scope resolves to.
     *
     * @param urlString the target URL
     * @param headers optional HTTP headers to include in the request
     * @param scope what is being fetched, and on whose behalf
     * @return the parsed JSON response, or null if the request failed
     * @throws Exception if a network or protocol error occurs
     * @since 0.8.0
     */
    public static JsonObject get(String urlString, Map<String, String> headers, NetworkScope scope) throws Exception {
        return executeRequest(urlString, "GET", null, headers, null, scope);
    }

    /**
     * Sends a GET request over the route the scope resolves to, returning the status alongside the
     * parsed body.
     *
     * @param urlString the target URL
     * @param headers optional HTTP headers to include in the request
     * @param scope what is being fetched, and on whose behalf
     * @return the status and parsed body; the body is null when absent or not JSON
     * @throws Exception if a network or protocol error occurs
     * @since 0.8.0
     */
    public static HttpResponse getForStatus(String urlString, Map<String, String> headers, NetworkScope scope)
            throws Exception {
        return executeForStatus(urlString, "GET", null, headers, null, scope);
    }

    /**
     * Sends a request with any method, returning the status alongside the parsed body. For the account
     * mutations — a {@code PUT} name change, a {@code DELETE} skin reset — that the JSON-only helpers do
     * not cover, and that need the status and error body rather than a collapsed {@code null}.
     *
     * @param method the HTTP method
     * @param urlString the target URL
     * @param contentType the Content-Type header value, or null when there is no body
     * @param headers optional HTTP headers to include in the request
     * @param body the raw request body, or null
     * @param scope what is being fetched, and on whose behalf
     * @return the status and parsed body; the body is null when absent or not JSON
     * @throws Exception if a network or protocol error occurs
     * @since 1.0.0
     */
    public static HttpResponse sendForStatus(
            String method,
            String urlString,
            String contentType,
            Map<String, String> headers,
            byte[] body,
            NetworkScope scope)
            throws Exception {
        return executeForStatus(urlString, method, contentType, headers, body, scope);
    }

    /**
     * A response reduced to its status and one header, for a caller following a redirect chain by hand.
     *
     * @param status the HTTP status code
     * @param value the requested header's value, or {@code null} when the response did not carry it
     * @author trq
     * @since 0.8.0
     */
    public record HeaderResponse(int status, String value) {

        /**
         * Returns whether the service is asking the caller to slow down, so a throttled step in a chain
         * is not mistaken for a step that simply carried no header.
         *
         * @return true if the status is 429
         * @since 0.12.0
         */
        public boolean rateLimited() {
            return status == 429;
        }
    }

    /**
     * Sends a GET request and reads one response header, discarding the body. For following a redirect
     * chain a step at a time, which the cookie flow does.
     *
     * @param urlString the target URL
     * @param headers optional HTTP headers to include in the request
     * @param headerName the response header to read
     * @param scope what is being fetched, and on whose behalf
     * @return the status and the header's value
     * @throws Exception if a network or protocol error occurs
     * @since 0.8.0
     */
    public static HeaderResponse getHeader(
            String urlString, Map<String, String> headers, String headerName, NetworkScope scope) throws Exception {
        HttpURLConnection conn = open(urlString, scope);
        conn.setRequestMethod("GET");
        applyHeaders(conn, null, headers);
        int status = conn.getResponseCode();
        String value = conn.getHeaderField(headerName);
        discardBody(conn, status);
        return new HeaderResponse(status, value);
    }

    /**
     * Sends a GET request and returns the raw response body, for a resource that is not JSON.
     *
     * <p>The cap binds the read itself. A response arriving over a proxy the library does not control is
     * exactly the case where an unbounded read is a memory hazard.
     *
     * <p>Unlike every other method here this one follows redirects, because the resources it fetches are
     * images and image hosts redirect. It follows them itself, under three rules. A request carrying an
     * {@code Authorization} header is never redirected at all, so a bearer token stays with the host it
     * was sent to. A redirect that leaves the origin drops {@code Cookie} and any other credential
     * header before the next hop. And a redirect from {@code https} to {@code http} is refused, as is a
     * chain longer than five hops. A refused redirect is reported as the redirect itself: {@code null}
     * here, the {@code 3xx} status from {@link #getBytesForStatus(String, Map, long, NetworkScope)}.
     *
     * @param urlString the target URL
     * @param headers optional HTTP headers to include in the request
     * @param maxBytes the largest body to accept
     * @param scope what is being fetched, and on whose behalf
     * @return the body bytes, or null on a non-2xx status or a body past the cap
     * @throws Exception if a network or protocol error occurs
     * @since 0.8.0
     */
    public static byte[] getBytes(String urlString, Map<String, String> headers, long maxBytes, NetworkScope scope)
            throws Exception {
        return getBytesForStatus(urlString, headers, maxBytes, scope).body();
    }

    /**
     * A raw response carrying its status alongside the body, for a caller that must tell a missing
     * resource from a throttled one.
     *
     * @param status the HTTP status code
     * @param body the body bytes, or {@code null} on a non-2xx status or a body past the cap
     * @param retryAfter how long the service asked the caller to wait, or {@code null} when it did not
     * @author trq
     * @since 0.12.0
     */
    public record BytesResponse(int status, byte[] body, Duration retryAfter) {

        /**
         * Returns whether the status is in the 2xx success range.
         *
         * @return true if the request succeeded
         * @since 0.12.0
         */
        public boolean successful() {
            return status >= 200 && status < 300;
        }

        /**
         * Returns whether the service is asking the caller to slow down. True for any 429, whether or
         * not it came with a {@code Retry-After}.
         *
         * @return true if the status is 429
         * @since 0.12.0
         */
        public boolean rateLimited() {
            return status == 429;
        }
    }

    /**
     * Sends a GET request and returns the raw response body alongside the status. The same request as
     * {@link #getBytes(String, Map, long, NetworkScope)}, which collapses every failure to {@code null}
     * and so cannot tell a throttled fetch, which should be retried later, from a missing resource,
     * which should not.
     *
     * @param urlString the target URL
     * @param headers optional HTTP headers to include in the request
     * @param maxBytes the largest body to accept
     * @param scope what is being fetched, and on whose behalf
     * @return the status, and the body when the status is 2xx and the body fits the cap
     * @throws Exception if a network or protocol error occurs
     * @since 0.12.0
     */
    public static BytesResponse getBytesForStatus(
            String urlString, Map<String, String> headers, long maxBytes, NetworkScope scope) throws Exception {
        // Resolved once: every hop of one fetch leaves from the same address.
        ProxyRoute route = routeFor(scope);
        boolean follow = !carriesCredential(headers);
        URI target = URI.create(urlString);
        Map<String, String> sending = headers;

        for (int hop = 0; ; hop++) {
            HttpURLConnection conn = open(target, route);
            conn.setRequestMethod("GET");
            applyHeaders(conn, null, sending);

            int status = conn.getResponseCode();
            Duration retryAfter = retryAfter(conn);
            if (status >= 200 && status < 300) {
                try (InputStream in = conn.getInputStream()) {
                    return new BytesResponse(status, readCapped(in, maxBytes), retryAfter);
                }
            }

            String location = conn.getHeaderField("Location");
            discardBody(conn, status);
            URI next = follow && isRedirect(status) && hop < MAX_REDIRECTS ? redirectTarget(target, location) : null;
            if (next == null) {
                return new BytesResponse(status, null, retryAfter);
            }
            if (!sameOrigin(target, next)) {
                sending = withoutCredentials(sending);
            }
            target = next;
        }
    }

    /**
     * Returns whether a header map carries something a redirect must not be allowed to replay.
     *
     * @param headers the caller's headers, or null
     * @return true if an authorization header is present
     */
    private static boolean carriesCredential(Map<String, String> headers) {
        if (headers == null) {
            return false;
        }
        return headers.keySet().stream().anyMatch(name -> name.equalsIgnoreCase("Authorization"));
    }

    /**
     * Returns whether a status asks the client to fetch the resource from somewhere else.
     *
     * @param status the response status
     * @return true for 301, 302, 303, 307, and 308
     */
    private static boolean isRedirect(int status) {
        return status == 301 || status == 302 || status == 303 || status == 307 || status == 308;
    }

    /**
     * Resolves where a redirect leads, or refuses it.
     *
     * <p>A redirect from {@code https} to {@code http} is refused: following it would repeat, in the
     * clear, a request the caller made over TLS. Anything that is not HTTP at all is refused too. The
     * upgrade from {@code http} to {@code https} is allowed.
     *
     * @param from the URL that answered with the redirect
     * @param location its {@code Location} header, or null
     * @return the URL to fetch next, or null when the redirect must not be followed
     */
    static URI redirectTarget(URI from, String location) {
        if (location == null || location.isBlank()) {
            return null;
        }
        URI next;
        try {
            next = from.resolve(location.trim());
        } catch (IllegalArgumentException malformed) {
            return null;
        }
        String scheme = next.getScheme();
        boolean https = "https".equalsIgnoreCase(scheme);
        if (next.getHost() == null || (!https && !"http".equalsIgnoreCase(scheme))) {
            return null;
        }
        if ("https".equalsIgnoreCase(from.getScheme()) && !https) {
            return null;
        }
        return next;
    }

    /**
     * Returns whether two URLs share a scheme, host, and port.
     *
     * @param first one URL
     * @param second the other
     * @return true if a credential scoped to one is scoped to the other
     */
    static boolean sameOrigin(URI first, URI second) {
        return first.getScheme().equalsIgnoreCase(second.getScheme())
                && first.getHost() != null
                && first.getHost().equalsIgnoreCase(second.getHost())
                && effectivePort(first) == effectivePort(second);
    }

    private static int effectivePort(URI uri) {
        if (uri.getPort() != -1) {
            return uri.getPort();
        }
        return "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
    }

    /**
     * Returns the caller's headers without those that identify it to one particular origin, for a
     * redirect that leaves that origin.
     *
     * @param headers the caller's headers, or null
     * @return the headers safe to send elsewhere, or null when there were none
     */
    static Map<String, String> withoutCredentials(Map<String, String> headers) {
        if (headers == null) {
            return null;
        }
        Map<String, String> kept = new LinkedHashMap<>(headers);
        kept.keySet()
                .removeIf(name -> name.equalsIgnoreCase("Authorization")
                        || name.equalsIgnoreCase("Proxy-Authorization")
                        || name.equalsIgnoreCase("Cookie"));
        return kept;
    }

    /**
     * Reads a stream, giving up rather than allocating past the cap.
     *
     * @param in the stream to read
     * @param maxBytes the largest body to accept
     * @return the bytes read, or null if the body ran past the cap
     * @throws IOException if reading fails
     */
    private static byte[] readCapped(InputStream in, long maxBytes) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        int read;
        while ((read = in.read(chunk)) != -1) {
            if (out.size() + read > maxBytes) {
                return null;
            }
            out.write(chunk, 0, read);
        }
        return out.toByteArray();
    }

    /**
     * Applies the shared and caller-supplied request headers. Caller headers land last, so a caller that
     * needs its own {@code Accept} or {@code User-Agent} — the cookie flow, which must look like a
     * browser — replaces the default rather than fighting it.
     *
     * @param conn the connection to configure
     * @param contentType the Content-Type header value, or null if no body is sent
     * @param headers map of additional headers to apply
     */
    private static void applyHeaders(HttpURLConnection conn, String contentType, Map<String, String> headers) {
        if (contentType != null) {
            conn.setRequestProperty("Content-Type", contentType);
        }
        conn.setRequestProperty("Accept", "application/json");
        conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
        if (headers != null) {
            headers.forEach(conn::setRequestProperty);
        }
    }

    /**
     * Internal method to execute HTTP requests and handle stream lifecycle. Configures common headers
     * such as User-Agent and Accept.
     *
     * @param urlString the target URL
     * @param method the HTTP method (GET, POST, etc.)
     * @param contentType the Content-Type header value, or null if no body is sent
     * @param headers map of additional headers to apply
     * @param body the raw byte array of the request body, or null
     * @param scope what is being fetched, and on whose behalf
     * @return the parsed JsonObject from the response stream, or null if status is not 2xx
     * @throws Exception if connection fails or stream reading is interrupted
     */
    private static JsonObject executeRequest(
            String urlString,
            String method,
            String contentType,
            Map<String, String> headers,
            byte[] body,
            NetworkScope scope)
            throws Exception {
        HttpURLConnection conn = open(urlString, scope);
        conn.setRequestMethod(method);
        applyHeaders(conn, contentType, headers);
        writeBody(conn, body);

        int status = conn.getResponseCode();

        // Validation check for successful response codes (200-299)
        if (status < 200 || status >= 300) {
            discardBody(conn, status);
            return null;
        }

        return JsonParser.parseString(readText(conn.getInputStream())).getAsJsonObject();
    }

    /**
     * Reads a JSON or text body whole, refusing one past {@link #MAX_TEXT_BODY_BYTES}.
     *
     * @param in the body stream; closed on return
     * @return the body decoded as UTF-8
     * @throws IOException if reading fails or the body runs past the limit
     */
    private static String readText(InputStream in) throws IOException {
        try (in) {
            byte[] bytes = readCapped(in, MAX_TEXT_BODY_BYTES);
            if (bytes == null) {
                throw new IOException("response body exceeds the " + MAX_TEXT_BODY_BYTES + " byte limit");
            }
            return new String(bytes, StandardCharsets.UTF_8);
        }
    }

    /**
     * Returns the stream a response's body arrives on, whichever side of 400 its status falls.
     *
     * @param conn the connection
     * @param status the response status
     * @return the body stream, or null when the response has none
     * @throws IOException if the stream cannot be opened
     */
    private static InputStream responseStream(HttpURLConnection conn, int status) throws IOException {
        return status >= 400 ? conn.getErrorStream() : conn.getInputStream();
    }

    /**
     * Consumes and closes a body nobody will read. A body left unread keeps its connection out of the
     * keep-alive pool, so a run of failures — a rate limit, a service having a bad minute — opens a fresh
     * socket, and behind a proxy a fresh tunnel, every time instead of reusing one. The read is bounded:
     * past {@link #MAX_DISCARDED_BYTES} the connection is cheaper to drop than to drain.
     *
     * @param conn the connection whose body to discard
     * @param status the response status
     */
    private static void discardBody(HttpURLConnection conn, int status) {
        try (InputStream body = responseStream(conn, status)) {
            if (body == null) {
                return;
            }
            byte[] chunk = new byte[8192];
            long total = 0;
            int read;
            while (total <= MAX_DISCARDED_BYTES && (read = body.read(chunk)) != -1) {
                total += read;
            }
        } catch (IOException ignored) {
            // Draining is an optimization; failing to do it must never fail the request.
        }
    }

    /**
     * Writes a request body, if there is one.
     *
     * @param conn the connection to write to
     * @param body the body bytes, or null
     * @throws IOException if writing fails
     */
    private static void writeBody(HttpURLConnection conn, byte[] body) throws IOException {
        if (body == null) {
            return;
        }
        conn.setDoOutput(true);
        try (OutputStream os = conn.getOutputStream()) {
            os.write(body);
        }
    }

    private static HttpResponse executeForStatus(
            String urlString,
            String method,
            String contentType,
            Map<String, String> headers,
            byte[] body,
            NetworkScope scope)
            throws Exception {
        HttpURLConnection conn = open(urlString, scope);
        conn.setRequestMethod(method);
        applyHeaders(conn, contentType, headers);
        writeBody(conn, body);

        int status = conn.getResponseCode();
        Duration retryAfter = retryAfter(conn);
        InputStream stream = responseStream(conn, status);
        if (stream == null) {
            return new HttpResponse(status, null, retryAfter);
        }

        String text = readText(stream);
        try {
            JsonElement parsed = JsonParser.parseString(text);
            return new HttpResponse(status, parsed.isJsonObject() ? parsed.getAsJsonObject() : null, retryAfter);
        } catch (RuntimeException parseFailure) {
            return new HttpResponse(status, null, retryAfter);
        }
    }

    /**
     * Reads a response's {@code Retry-After} delay.
     *
     * @param conn the connection to read from
     * @return the delay the service asked for, or null when it asked for none
     */
    private static Duration retryAfter(HttpURLConnection conn) {
        return parseRetryAfter(conn.getHeaderField("Retry-After"), conn.getHeaderField("Date"), Instant.now());
    }

    /**
     * Interprets a {@code Retry-After} value in either form the header allows: a number of seconds, or
     * an HTTP-date naming the moment to come back.
     *
     * <p>A date is measured against the response's own {@code Date} header when there is one, because
     * both were written by the same clock; the local clock is only the fallback. Measured against a
     * local clock that runs a minute fast, "retry in thirty seconds" would read as "retry now". A date
     * already in the past is a delay of zero rather than no delay at all — the service still said to
     * wait, and that it is a rate limit is the part worth keeping.
     *
     * @param retryAfter the {@code Retry-After} header value, or null
     * @param date the response's {@code Date} header value, or null
     * @param now the local time, used when the response carries no usable {@code Date}
     * @return the delay asked for, or null when the header is absent or unreadable
     */
    static Duration parseRetryAfter(String retryAfter, String date, Instant now) {
        if (retryAfter == null || retryAfter.isBlank()) {
            return null;
        }
        String value = retryAfter.trim();
        try {
            long seconds = Long.parseLong(value);
            return seconds >= 0 ? Duration.ofSeconds(seconds) : null;
        } catch (NumberFormatException notSeconds) {
            // Fall through: the other legal form is a date.
        }
        Instant at = parseHttpDate(value);
        if (at == null) {
            return null;
        }
        Instant reference = parseHttpDate(date);
        Duration delay = Duration.between(reference != null ? reference : now, at);
        return delay.isNegative() ? Duration.ZERO : delay;
    }

    /**
     * Parses an HTTP-date in its preferred (RFC 1123) form.
     *
     * @param value the header value, or null
     * @return the instant, or null when the value is absent or not a date
     */
    private static Instant parseHttpDate(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return Instant.from(DateTimeFormatter.RFC_1123_DATE_TIME.parse(value.trim()));
        } catch (DateTimeParseException notADate) {
            return null;
        }
    }
}

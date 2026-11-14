package lol.trq.alts.internal.net;

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
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.function.Predicate;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;
import lol.trq.alts.net.NetworkScope;
import lol.trq.alts.net.ProxyRoute;
import lol.trq.alts.spi.ProxyProvider;

/**
 * The runtime's way out to the network: every request the library makes goes through one instance of
 * this, which the runtime constructs, hands to each service through its constructor, and closes. It
 * holds the host's {@link ProxyProvider}, the proxy tunnel connections, and the executor blocking work
 * runs on; nothing in the library reads a static to reach the network.
 *
 * <p>Each call resolves a {@link ProxyRoute} from its {@link NetworkScope} first. The scope-less
 * overloads resolve as {@link NetworkScope.Purpose#AUTH}.
 *
 * <p>It is also where the transport rules are enforced, once, for every caller:
 *
 * <ul>
 *   <li>Timeouts are finite: ten seconds to connect, thirty to read.
 *   <li>Route resolution fails closed. A provider that throws or names no route fails the request, and
 *       a proxy that refuses a tunnel fails it too; nothing falls back to a direct connection. Without
 *       a provider every request is direct.
 *   <li>A proxy credential is sent to the proxy and nowhere else. An HTTPS target behind an HTTP proxy
 *       is reached through a tunnel the library opens itself, so the credential rides the
 *       {@code CONNECT} and is never inside the TLS stream the origin reads.
 *   <li>A kept-alive connection is only reused by the proxy identity that opened it: proxy host, port,
 *       and credential, within this transport. Two transports never share a tunnel. Connections the
 *       library does not tunnel itself (direct ones, unauthenticated SOCKS, and an unauthenticated
 *       plain-HTTP proxy) are pooled by the JDK, process-wide, keyed by their target and proxy; a
 *       connection reused that way has the same identity, so nothing leaks between routes, but
 *       {@link #close()} cannot close those.
 *   <li>TLS uses the JVM's default trust with hostname verification on, tunnelled or not.
 *   <li>Redirects are not followed, except by the binary fetch, which never carries a credential across
 *       origins and never steps down from {@code https} to {@code http}.
 *   <li>A JSON or text body is read up to one mebibyte; a longer one fails the request.
 *   <li>The JVM's URL-connection caches are off for every connection, so no response, and no token
 *       in one, is offered to a host-installed {@link java.net.ResponseCache}.
 * </ul>
 *
 * <p>Known limit: {@link HttpURLConnection} consults the process-wide
 * {@link java.net.CookieHandler#getDefault()} on every request and offers no per-connection opt-out. A
 * {@code CookieHandler} the host, or anything else in the process, installed therefore sees the URL and
 * response headers of every request made here, the sign-in hops included, and may add cookies to them.
 * The library installs none.
 *
 * <p>The request methods block. Run them on {@link #executor()} rather than the common pool.
 *
 * <p>{@link #close()} closes the pooled tunnel connections the library opened and refuses every later
 * request. Nothing here
 * changes process-wide JVM state: no system property, default authenticator, default {@code SSLContext},
 * or proxy selector is installed.
 *
 * <p>Internal: a host reaches the network through the runtime's services, never through this.
 *
 * @author trq
 * @since 1.0.0
 */
public final class HttpTransport implements AutoCloseable {

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

    /** The whole message of a refused header: it must never quote the header, which may be a token. */
    private static final String UNSAFE_HEADER = "a request header holds a control character";

    /** The whole message of a refused caller-set proxy credential; it quotes nothing. */
    private static final String PROXY_CREDENTIAL_HEADER = "only the transport sets the proxy credential";

    /** How many redirects one fetch follows before the chain is treated as a loop. */
    private static final int MAX_REDIRECTS = 5;

    /** How much of an unwanted body is drained to keep its connection reusable before giving it up. */
    private static final int MAX_DISCARDED_BYTES = 64 * 1024;

    /** How many proxy identities keep a tunnel factory, and with it a set of reusable connections. */
    static final int MAX_TUNNEL_FACTORIES = 64;

    /**
     * The longest stated wait taken at its word. Longer than any real throttle, and short enough that
     * every conversion downstream (to milliseconds, onto an instant) stays in range.
     */
    static final Duration MAX_RETRY_AFTER = Duration.ofDays(1);

    private final ProxyProvider proxyProvider;
    private final Executor executor;
    private final SSLSocketFactory tlsOverride;
    private final Tunnels tunnels;
    private final String routeTag;

    /**
     * Creates a transport.
     *
     * @param proxyProvider the host's proxy provider, or null for direct connections
     * @param executor the executor blocking work runs on
     * @since 1.0.0
     */
    public HttpTransport(ProxyProvider proxyProvider, Executor executor) {
        this(proxyProvider, executor, null);
    }

    /**
     * Creates a transport whose TLS is layered by {@code tls} instead of the JVM's default factory, so a
     * test can trust a certificate it generated for a loopback origin. Package-private: production always
     * uses the JVM's default trust, and hostname verification stays on either way.
     *
     * @param proxyProvider the host's proxy provider, or null for direct connections
     * @param executor the executor blocking work runs on
     * @param tls the TLS socket factory, or null for the JVM default
     */
    HttpTransport(ProxyProvider proxyProvider, Executor executor, SSLSocketFactory tls) {
        this(proxyProvider, Objects.requireNonNull(executor, "executor"), tls, new Tunnels(), null);
    }

    private HttpTransport(
            ProxyProvider proxyProvider, Executor executor, SSLSocketFactory tls, Tunnels tunnels, String routeTag) {
        this.proxyProvider = proxyProvider;
        this.executor = executor;
        this.tlsOverride = tls;
        this.tunnels = tunnels;
        this.routeTag = routeTag;
    }

    /**
     * Returns a view of this transport whose every request carries {@code tag} as its scope's
     * {@link NetworkScope#routeTag()}, so the proxy provider can route a request that has no account yet,
     * such as a new account's first sign-in. The view shares everything else: the provider, the executor,
     * the tunnels, and being closed.
     *
     * @param tag the host's route tag
     * @return the tagged view
     * @throws NullPointerException if {@code tag} is null
     * @throws IllegalArgumentException if {@code tag} is blank
     * @since 1.0.0
     */
    public HttpTransport routed(String tag) {
        Objects.requireNonNull(tag, "tag");
        if (tag.isBlank()) {
            throw new IllegalArgumentException("a route tag must not be blank");
        }
        return new HttpTransport(proxyProvider, executor, tlsOverride, tunnels, tag);
    }

    /**
     * Returns the route tag this view stamps on every request, if it is a tagged view.
     *
     * @return the tag, or empty for an untagged transport
     * @since 1.0.0
     */
    public Optional<String> routeTag() {
        return Optional.ofNullable(routeTag);
    }

    /**
     * Returns the executor blocking library work runs on. Pass it as the executor argument of
     * {@link java.util.concurrent.CompletableFuture#supplyAsync(java.util.function.Supplier, Executor)}
     * and its siblings; the one-argument forms run on the JVM-wide common pool, which the library never
     * uses.
     *
     * @return the executor
     * @since 1.0.0
     */
    public Executor executor() {
        return executor;
    }

    /**
     * Closes every pooled tunnel connection and refuses every request made from now on, on this
     * transport and every view of it. Idempotent. A request already past its route resolution may still
     * complete or fail on its own.
     *
     * @since 1.0.0
     */
    @Override
    public void close() {
        tunnels.close();
    }

    /**
     * Returns whether this transport, or the one it is a view of, has been closed: whether something
     * about to start (a callback listener, a browser) should not.
     *
     * @return true once {@link #close()} has been called
     * @since 1.0.0
     */
    public boolean isClosed() {
        return tunnels.closed;
    }

    /**
     * Registers an action to run when this transport closes, or at once if it already has: the way
     * something waiting on the runtime (a sign-in's callback listener, a scheduled wait) is ended by
     * {@link #close()} rather than left waiting for an event that will not come.
     *
     * @param action what to run; it runs at most once, and a failure it throws is not propagated
     * @return a handle that unregisters the action, for once its wait has ended some other way
     * @since 1.0.0
     */
    public AutoCloseable whenClosed(Runnable action) {
        Objects.requireNonNull(action, "action");
        tunnels.closers.add(action);
        if (tunnels.closed && tunnels.closers.remove(action)) {
            Tunnels.runQuietly(action);
        }
        return () -> tunnels.closers.remove(action);
    }

    /**
     * Runs {@code task} on this transport's executor after {@code delayMillis}, without holding a thread
     * while it waits. If the transport closes first, or the executor refuses the task (a runtime's own
     * executor does once the runtime has closed), {@code refused} is called instead, with an
     * {@link IOException} saying the runtime is closed, and the task never runs. Exactly one of the two
     * happens.
     *
     * <p>Every wait in the library goes through here. The JDK's own delayed executor swallows a
     * rejection, which would leave whatever waits on the task waiting for good.
     *
     * @param delayMillis how long to wait first; zero or less runs it now
     * @param task what to run
     * @param refused what to run instead when the task cannot be run
     * @since 1.0.0
     */
    public void schedule(long delayMillis, Runnable task, Consumer<IOException> refused) {
        Objects.requireNonNull(task, "task");
        Objects.requireNonNull(refused, "refused");
        AtomicBoolean settled = new AtomicBoolean();
        AutoCloseable registration = whenClosed(() -> {
            if (settled.compareAndSet(false, true)) {
                refused.accept(closedFailure(null));
            }
        });
        Runnable fire = () -> {
            if (!settled.compareAndSet(false, true)) {
                return;
            }
            closeQuietly(registration);
            try {
                executor.execute(task);
            } catch (RejectedExecutionException rejection) {
                refused.accept(closedFailure(rejection));
            }
        };
        if (delayMillis <= 0) {
            fire.run();
        } else {
            // The delayer thread only hands the task over; the task itself runs on the executor.
            CompletableFuture.delayedExecutor(delayMillis, TimeUnit.MILLISECONDS, Runnable::run)
                    .execute(fire);
        }
    }

    /**
     * Returns a future that completes after {@code duration}, on this transport's executor, or completes
     * exceptionally with an {@link IOException} as soon as the transport closes or the executor refuses
     * to run it; see {@link #schedule(long, Runnable, Consumer)}.
     *
     * @param duration how long to wait; null or not positive completes at once, and one too long to
     *     count in milliseconds waits {@link Long#MAX_VALUE} of them
     * @return the wait
     * @since 1.0.0
     */
    public CompletableFuture<Void> delay(Duration duration) {
        long millis = saturatedMillis(duration);
        if (millis <= 0L) {
            return CompletableFuture.completedFuture(null);
        }
        CompletableFuture<Void> waited = new CompletableFuture<>();
        schedule(millis, () -> waited.complete(null), waited::completeExceptionally);
        return waited;
    }

    /**
     * Returns a duration in milliseconds, held to {@link Long#MAX_VALUE} where {@link Duration#toMillis()}
     * would overflow.
     *
     * @param duration the duration, or null
     * @return its length in milliseconds; zero for null
     * @since 1.0.0
     */
    public static long saturatedMillis(Duration duration) {
        if (duration == null) {
            return 0L;
        }
        try {
            return duration.toMillis();
        } catch (ArithmeticException tooLong) {
            return duration.isNegative() ? Long.MIN_VALUE : Long.MAX_VALUE;
        }
    }

    /**
     * Returns how many close actions are registered and waiting, on this transport and its views. For
     * tests, which check that a wait that ended some other way leaves nothing registered behind.
     *
     * @return the number of registered close actions
     */
    int closerCount() {
        return tunnels.closers.size();
    }

    private static IOException closedFailure(Throwable cause) {
        return new TransportClosedException(cause);
    }

    private static void closeQuietly(AutoCloseable closeable) {
        try {
            closeable.close();
        } catch (Exception ignored) {
            // Unregistering removes from a set; it does not fail.
        }
    }

    /**
     * Resolves the route a request should take, with this view's route tag stamped on the scope.
     *
     * <p>Fails closed when a provider is set: a provider that throws or returns null fails the request
     * rather than quietly connecting directly, because a silent fallback discloses the host's real
     * address at the moment it believed it was proxied.
     *
     * @param scope what is being fetched; null resolves as {@link NetworkScope.Purpose#AUTH}
     * @return the route to use
     * @throws IOException if the transport is closed or the provider could not name a route
     */
    ProxyRoute routeFor(NetworkScope scope) throws IOException {
        if (tunnels.closed) {
            throw new TransportClosedException(null);
        }
        ProxyProvider provider = proxyProvider;
        if (provider == null) {
            return ProxyRoute.direct();
        }
        NetworkScope effective = scope == null ? NetworkScope.of(NetworkScope.Purpose.AUTH) : scope;
        if (routeTag != null) {
            effective = effective.withRouteTag(routeTag);
        }
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
     * The tunnel factories of one transport and its views, and whether it is closed. The factory
     * instance is the JDK's keep-alive key, so two transports never share one, and a view shares its
     * transport's.
     */
    private static final class Tunnels {

        private final List<ProxyTunnelSocketFactory> retired = new ArrayList<>();
        private final Map<TunnelIdentity, ProxyTunnelSocketFactory> factories = new LinkedHashMap<>(16, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<TunnelIdentity, ProxyTunnelSocketFactory> eldest) {
                if (size() <= MAX_TUNNEL_FACTORIES) {
                    return false;
                }
                // Its idle connections stay in the JDK's pool until they age out, so it is kept
                // where close() can still reach them.
                retired.removeIf(ProxyTunnelSocketFactory::idle);
                retired.add(eldest.getValue());
                return true;
            }
        };
        private final Set<Runnable> closers = ConcurrentHashMap.newKeySet();
        private volatile boolean closed;

        void close() {
            List<ProxyTunnelSocketFactory> open;
            synchronized (factories) {
                // Set under the lock tunnelFactory() takes, so no factory is created after this point.
                closed = true;
                open = new ArrayList<>(factories.values());
                open.addAll(retired);
                factories.clear();
                retired.clear();
            }
            for (ProxyTunnelSocketFactory factory : open) {
                factory.closeAll();
            }
            for (Runnable closer : List.copyOf(closers)) {
                if (closers.remove(closer)) {
                    runQuietly(closer);
                }
            }
        }

        static void runQuietly(Runnable action) {
            try {
                action.run();
            } catch (RuntimeException ignored) {
                // One waiter's failure must not keep the rest of the runtime from closing.
            }
        }
    }

    /**
     * Applies the connection defaults every request shares. The timeouts are finite because these calls
     * run on a shared thread pool: an endpoint that accepts a connection and then goes silent would
     * otherwise hold a pooled thread for the life of the process and leave the login future to never
     * complete. The JDK's own redirect following is always off, because {@code HttpURLConnection}
     * replays the caller's request properties to the redirect target, which would send an
     * {@code Authorization: Bearer} header to whatever host a {@code 3xx} names. The one call that does
     * follow redirects, {@link #getBytesForStatus(String, Map, long, NetworkScope)}, does so by hand.
     * Caches are off: a host may have installed a process-wide {@link java.net.ResponseCache}, and a
     * response here may carry a token.
     *
     * @param conn the connection to configure
     */
    static void applyDefaults(HttpURLConnection conn) {
        conn.setConnectTimeout(CONNECT_TIMEOUT_MILLIS);
        conn.setReadTimeout(READ_TIMEOUT_MILLIS);
        conn.setInstanceFollowRedirects(false);
        conn.setUseCaches(false);
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
    private HttpURLConnection open(String urlString, NetworkScope scope) throws IOException {
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
    private HttpURLConnection open(URI uri, ProxyRoute route) throws IOException {
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
            opened = uri.toURL().openConnection(tunnelled ? Proxy.NO_PROXY : ProxyRoutes.toProxy(route));
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
            String authorization = ProxyRoutes.authorizationHeader(route);
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
     * @throws IOException if the transport has closed
     */
    private ProxyTunnelSocketFactory tunnelFactory(ProxyRoute route) throws IOException {
        TunnelIdentity identity = new TunnelIdentity(
                route.host().toLowerCase(Locale.ROOT),
                route.port(),
                route.username(),
                ProxyRoutes.authorizationHeader(route));
        synchronized (tunnels.factories) {
            // A request that resolved its route just before close() must not open a tunnel after it:
            // close() would never see that tunnel's factory.
            if (tunnels.closed) {
                throw closedFailure(null);
            }
            return tunnels.factories.computeIfAbsent(
                    identity,
                    key -> new ProxyTunnelSocketFactory(
                            route.host(), key.port(), key.authorization(), this::tlsSocketFactory));
        }
    }

    /**
     * Returns the factory that layers TLS: the JVM's default for HTTPS, which is what a direct
     * connection uses, unless this transport was built for a test with its own.
     *
     * @return the TLS socket factory
     */
    private SSLSocketFactory tlsSocketFactory() {
        SSLSocketFactory tls = tlsOverride;
        return tls != null ? tls : HttpsURLConnection.getDefaultSSLSocketFactory();
    }

    /**
     * Returns how many route identities currently own a tunnel factory.
     *
     * @return the size of the factory cache
     */
    int tunnelFactoryCount() {
        synchronized (tunnels.factories) {
            return tunnels.factories.size();
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
    private record TunnelIdentity(String host, int port, String username, String authorization) {

        // The authorization is the proxy credential, and the username often encodes a session.
        @Override
        public String toString() {
            return "TunnelIdentity[" + host + ":" + port + (authorization != null ? ", authenticated" : "") + "]";
        }
    }

    /**
     * Sends a POST request with a JSON body.
     *
     * @param urlString the target URL
     * @param headers optional HTTP headers to include in the request
     * @param jsonBody the JSON payload as a string
     * @return the parsed JSON response, or null if the request returned a non-2xx status
     * @throws Exception if a network or protocol error occurs
     */
    public JsonObject postJson(String urlString, Map<String, String> headers, String jsonBody) throws Exception {
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
    public JsonObject postJson(String urlString, Map<String, String> headers, String jsonBody, NetworkScope scope)
            throws Exception {
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
    public JsonObject postForm(String urlString, Map<String, String> headers, String formBody) throws Exception {
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
    public JsonObject postForm(String urlString, Map<String, String> headers, String formBody, NetworkScope scope)
            throws Exception {
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

        /**
         * Returns a description that leaves the body out. A token endpoint answers with the tokens, so
         * the generated {@code toString} would put a credential into whatever log a caller wrote the
         * response to.
         *
         * @return a loggable description
         * @since 0.12.0
         */
        @Override
        public String toString() {
            return "HttpResponse[status=" + status + ", body=" + (body == null ? "none" : "<redacted>")
                    + ", retryAfter=" + retryAfter + "]";
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
    public HttpResponse postFormForStatus(String urlString, Map<String, String> headers, String formBody)
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
    public HttpResponse postFormForStatus(
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
    public HttpResponse postJsonForStatus(String urlString, Map<String, String> headers, String jsonBody)
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
    public HttpResponse postJsonForStatus(
            String urlString, Map<String, String> headers, String jsonBody, NetworkScope scope) throws Exception {
        return executeForStatus(
                urlString, "POST", "application/json", headers, jsonBody.getBytes(StandardCharsets.UTF_8), scope);
    }

    /**
     * An HTTP response carrying its status alongside the parsed body, whatever JSON shape that body has.
     * {@link HttpResponse} reads object bodies only; this is for the few endpoints that answer with a
     * top-level array.
     *
     * @param status the HTTP status code
     * @param body the parsed JSON body — an object or an array — or {@code null} when the body was
     *     absent or was neither
     * @param retryAfter how long the service asked the caller to wait, or {@code null} when it did not
     * @author trq
     * @since 0.12.0
     */
    public record JsonResponse(int status, JsonElement body, Duration retryAfter) {

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
         * Returns whether the service is asking the caller to slow down.
         *
         * @return true if the status is 429
         * @since 0.12.0
         */
        public boolean rateLimited() {
            return status == 429;
        }

        /**
         * Returns a description that leaves the body out, for the reason {@link HttpResponse#toString()}
         * does.
         *
         * @return a loggable description
         * @since 0.12.0
         */
        @Override
        public String toString() {
            return "JsonResponse[status=" + status + ", body=" + (body == null ? "none" : "<redacted>")
                    + ", retryAfter=" + retryAfter + "]";
        }
    }

    /**
     * Sends a POST request with a JSON body over the route the scope resolves to, returning the status
     * alongside the parsed body in whatever JSON shape it arrived. The counterpart of
     * {@link #postJsonForStatus(String, Map, String, NetworkScope)} for an endpoint that answers with a
     * top-level array, which that method would report as no body at all.
     *
     * <p>Same request path as every other method here: the scope's route, failing closed when the proxy
     * provider does; the same timeouts; no redirects; the same cap on the body read.
     *
     * @param urlString the target URL
     * @param headers optional HTTP headers to include in the request
     * @param jsonBody the JSON payload as a string
     * @param scope what is being fetched, and on whose behalf
     * @return the status and parsed body; the body is null when absent or not JSON
     * @throws Exception if a network or protocol error occurs
     * @since 0.12.0
     */
    public JsonResponse postJsonForElement(
            String urlString, Map<String, String> headers, String jsonBody, NetworkScope scope) throws Exception {
        return executeForElement(
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
    public JsonObject get(String urlString, Map<String, String> headers) throws Exception {
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
    public JsonObject get(String urlString, Map<String, String> headers, NetworkScope scope) throws Exception {
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
    public HttpResponse getForStatus(String urlString, Map<String, String> headers, NetworkScope scope)
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
    public HttpResponse sendForStatus(
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
     * A response as raw bytes, whatever its status, for a protocol that parses its own bodies strictly and
     * reads the error body of a refusal as well as the body of a success.
     *
     * @param status the HTTP status code
     * @param body the body bytes, empty when the response carried none
     * @param retryAfter how long the service asked the caller to wait, or {@code null} when it did not
     * @author trq
     * @since 1.0.0
     */
    public record RawResponse(int status, byte[] body, Duration retryAfter) {

        /**
         * Copies the body.
         *
         * @since 1.0.0
         */
        public RawResponse {
            body = body == null ? new byte[0] : body.clone();
        }

        /**
         * Returns the body.
         *
         * @return a copy of the body bytes
         * @since 1.0.0
         */
        @Override
        public byte[] body() {
            return body.clone();
        }

        /**
         * Returns a description that leaves the body out, for the reason {@link HttpResponse#toString()}
         * does.
         *
         * @return a loggable description
         * @since 1.0.0
         */
        @Override
        public String toString() {
            return "RawResponse[status=" + status + ", body=" + body.length + " bytes, retryAfter=" + retryAfter + "]";
        }
    }

    /**
     * Sends one request and returns the status with the raw body, read up to a cap the caller chooses, for
     * every status: the error body of a {@code 4xx} or {@code 5xx} is read too. The shared vault uses it,
     * because its answers can be larger than the {@value #MAX_TEXT_BODY_BYTES}-byte cap of the JSON
     * helpers and it parses them itself.
     *
     * <p>Same request path as every other method here: the scope's route, failing closed when the proxy
     * provider does; the same timeouts and header checks; no redirects.
     *
     * @param method the HTTP method
     * @param urlString the target URL
     * @param contentType the Content-Type header value, or null when there is no body
     * @param headers optional HTTP headers to include in the request
     * @param body the raw request body, or null
     * @param maxBytes the largest body to read
     * @param scope what is being fetched, and on whose behalf
     * @return the status, the body and any stated wait
     * @throws IllegalArgumentException if {@code maxBytes} is not positive, or a header is refused
     * @throws IOException if the body runs past {@code maxBytes}, or the request fails
     * @throws Exception if a network or protocol error occurs
     * @since 1.0.0
     */
    public RawResponse exchange(
            String method,
            String urlString,
            String contentType,
            Map<String, String> headers,
            byte[] body,
            long maxBytes,
            NetworkScope scope)
            throws Exception {
        if (maxBytes <= 0) {
            throw new IllegalArgumentException("a body cap is positive");
        }
        HttpURLConnection conn = open(urlString, scope);
        conn.setRequestMethod(method);
        applyHeaders(conn, contentType, headers);
        writeBody(conn, body);

        int status = conn.getResponseCode();
        Duration retryAfter = retryAfter(conn);
        InputStream stream = responseStream(conn, status);
        if (stream == null) {
            return new RawResponse(status, null, retryAfter);
        }
        try (stream) {
            byte[] bytes = readCapped(stream, maxBytes);
            if (bytes == null) {
                throw new IOException("response body exceeds the " + maxBytes + " byte limit");
            }
            return new RawResponse(status, bytes, retryAfter);
        }
    }

    /**
     * A response reduced to its status and one header, for a caller following a redirect chain by hand.
     *
     * @param status the HTTP status code
     * @param value the requested header's value, or {@code null} when the response did not carry it
     * @param retryAfter how long the service asked the caller to wait, or {@code null} when it did not;
     *     added in 1.0.0
     * @author trq
     * @since 0.8.0
     */
    public record HeaderResponse(int status, String value, Duration retryAfter) {

        /**
         * Creates a response that stated no wait.
         *
         * @param status the HTTP status code
         * @param value the requested header's value, or {@code null}
         * @since 1.0.0
         */
        public HeaderResponse(int status, String value) {
            this(status, value, null);
        }

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

        /**
         * Returns a description that leaves the header's value out. The header read this way is a
         * redirect's {@code Location}, and a sign-in chain puts codes and tokens in that address.
         *
         * @return a loggable description
         * @since 0.12.0
         */
        @Override
        public String toString() {
            return "HeaderResponse[status=" + status + ", value=" + (value == null ? "none" : "<redacted>") + "]";
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
    public HeaderResponse getHeader(
            String urlString, Map<String, String> headers, String headerName, NetworkScope scope) throws Exception {
        HttpURLConnection conn = open(urlString, scope);
        conn.setRequestMethod("GET");
        applyHeaders(conn, null, headers);
        int status = conn.getResponseCode();
        String value = conn.getHeaderField(headerName);
        Duration wait = retryAfter(conn);
        discardBody(conn, status);
        return new HeaderResponse(status, value, wait);
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
    public byte[] getBytes(String urlString, Map<String, String> headers, long maxBytes, NetworkScope scope)
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
    public BytesResponse getBytesForStatus(
            String urlString, Map<String, String> headers, long maxBytes, NetworkScope scope) throws Exception {
        return getBytesForStatus(urlString, headers, maxBytes, scope, anywhere -> true);
    }

    /**
     * Sends a GET request and returns the raw response body alongside the status, following a redirect
     * only where {@code redirectAllowed} says it may lead. For a caller that chose the first address
     * because of who serves it: without this, the server at that address chooses every address after it.
     *
     * <p>The predicate is asked about each hop's resolved target before that hop is requested, on top of
     * the rules {@link #getBytes(String, Map, long, NetworkScope)} always applies. A hop it refuses is
     * not requested and is reported as the redirect itself, with its {@code 3xx} status and no body. A
     * predicate that refuses everything makes this a fetch that follows no redirect at all.
     *
     * @param urlString the target URL
     * @param headers optional HTTP headers to include in the request
     * @param maxBytes the largest body to accept
     * @param scope what is being fetched, and on whose behalf
     * @param redirectAllowed decides, per hop, whether a redirect to that address may be followed
     * @return the status, and the body when the status is 2xx and the body fits the cap
     * @throws Exception if a network or protocol error occurs
     * @since 0.12.0
     */
    public BytesResponse getBytesForStatus(
            String urlString,
            Map<String, String> headers,
            long maxBytes,
            NetworkScope scope,
            Predicate<URI> redirectAllowed)
            throws Exception {
        Objects.requireNonNull(redirectAllowed, "redirectAllowed");
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
            if (next == null || !redirectAllowed.test(next)) {
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
     * <p>Every caller header is checked here before the JDK sees it. The JDK refuses a value holding a
     * line break by throwing an exception whose message quotes the whole value, and the value is
     * usually {@code Bearer <token>}; that message then travels wherever the failure is reported. A
     * control character anywhere in a name or a value is refused first, with a message that quotes
     * nothing.
     *
     * <p>A header the route set on the connection, {@code Connection: close} on an authenticated
     * plain-HTTP proxy, is set again after the caller's, so no caller header can turn connection reuse
     * back on where reuse would hand one credential's connection to another.
     *
     * <p>A caller header named {@code Proxy-Authorization} is refused too. The proxy credential is the
     * route's, and only {@link #open(URI, ProxyRoute)} decides where it goes: on the {@code CONNECT} of a
     * tunnel, or on a plain request to the proxy itself. Set by a caller on a tunnelled or direct
     * connection, the JDK would send it to the origin.
     *
     * @param conn the connection to configure
     * @param contentType the Content-Type header value, or null if no body is sent
     * @param headers map of additional headers to apply
     * @throws IllegalArgumentException if a header name or value holds a control character, or a header
     *     is named {@code Proxy-Authorization}; the message names neither the header nor its value
     */
    private static void applyHeaders(HttpURLConnection conn, String contentType, Map<String, String> headers) {
        requireHeaderText(contentType);
        if (headers != null) {
            headers.forEach((name, value) -> {
                if (name == null || name.isEmpty()) {
                    throw new IllegalArgumentException(UNSAFE_HEADER);
                }
                requireHeaderText(name);
                requireHeaderText(value);
                if (name.trim().equalsIgnoreCase("Proxy-Authorization")) {
                    throw new IllegalArgumentException(PROXY_CREDENTIAL_HEADER);
                }
            });
        }
        // What the route set on the connection (Connection: close, on an authenticated plain-HTTP proxy) is
        // the route's to decide, so it is put back after the caller's headers rather than left for one of
        // them to replace.
        String routeConnection = conn.getRequestProperty("Connection");
        if (contentType != null) {
            conn.setRequestProperty("Content-Type", contentType);
        }
        conn.setRequestProperty("Accept", "application/json");
        conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
        if (headers != null) {
            headers.forEach(conn::setRequestProperty);
        }
        if (routeConnection != null) {
            conn.setRequestProperty("Connection", routeConnection);
        }
    }

    /**
     * Refuses header text that holds a control character, without repeating the text.
     *
     * @param text a header name or value, or null
     * @throws IllegalArgumentException if the text holds a control character
     */
    private static void requireHeaderText(String text) {
        if (text == null) {
            return;
        }
        for (int index = 0; index < text.length(); index++) {
            char character = text.charAt(index);
            if (character < 0x20 || character == 0x7f) {
                throw new IllegalArgumentException(UNSAFE_HEADER);
            }
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
    private JsonObject executeRequest(
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

    private HttpResponse executeForStatus(
            String urlString,
            String method,
            String contentType,
            Map<String, String> headers,
            byte[] body,
            NetworkScope scope)
            throws Exception {
        JsonResponse response = executeForElement(urlString, method, contentType, headers, body, scope);
        JsonElement parsed = response.body();
        return new HttpResponse(
                response.status(),
                parsed != null && parsed.isJsonObject() ? parsed.getAsJsonObject() : null,
                response.retryAfter());
    }

    /**
     * Sends one request and parses whatever JSON came back. The single implementation behind every
     * status-carrying method, so the route, the timeouts and the body cap cannot differ between them.
     *
     * @param urlString the target URL
     * @param method the HTTP method
     * @param contentType the Content-Type header value, or null when there is no body
     * @param headers optional HTTP headers to include in the request
     * @param body the raw request body, or null
     * @param scope what is being fetched, and on whose behalf
     * @return the status and parsed body; the body is null when absent or not JSON
     * @throws Exception if a network or protocol error occurs
     */
    private JsonResponse executeForElement(
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
            return new JsonResponse(status, null, retryAfter);
        }

        String text = readText(stream);
        try {
            JsonElement parsed = JsonParser.parseString(text);
            // A bare primitive is not an answer any endpoint here gives; it is what the lenient parser makes
            // of an HTML or plain-text error page, so it is reported as no body rather than as a string.
            boolean structured = parsed.isJsonObject() || parsed.isJsonArray();
            return new JsonResponse(status, structured ? parsed : null, retryAfter);
        } catch (RuntimeException parseFailure) {
            return new JsonResponse(status, null, retryAfter);
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
     * <p>A wait longer than {@link #MAX_RETRY_AFTER} (a day) is held to it, a number too large to parse
     * included: the service asked for a very long wait, and that is what the caller is told, in a form
     * no later arithmetic overflows on.
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
        if (!value.isEmpty() && value.chars().allMatch(c -> c >= '0' && c <= '9')) {
            try {
                return atMostADay(Duration.ofSeconds(Long.parseLong(value)));
            } catch (NumberFormatException tooManyDigits) {
                // Digits only, so a number of seconds, just one past what a long holds.
                return MAX_RETRY_AFTER;
            }
        }
        Instant at = parseHttpDate(value);
        if (at == null) {
            return null;
        }
        Instant reference = parseHttpDate(date);
        Duration delay = Duration.between(reference != null ? reference : now, at);
        return delay.isNegative() ? Duration.ZERO : atMostADay(delay);
    }

    private static Duration atMostADay(Duration delay) {
        return delay.compareTo(MAX_RETRY_AFTER) > 0 ? MAX_RETRY_AFTER : delay;
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

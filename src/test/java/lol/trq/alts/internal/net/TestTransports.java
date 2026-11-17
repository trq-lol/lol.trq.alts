package lol.trq.alts.internal.net;

import java.io.IOException;
import java.util.concurrent.Executor;
import javax.net.ssl.SSLSocketFactory;
import lol.trq.alts.net.NetworkScope;
import lol.trq.alts.net.ProxyRoute;
import lol.trq.alts.spi.ProxyProvider;

/**
 * Builds transports for tests in other packages. Each call makes a new transport, so a test owns what it
 * is given and nothing it installs outlives it; there is nothing process-wide left to reset.
 */
public final class TestTransports {

    /** A virtual-thread executor tests share; its threads are named so a stray task is attributable. */
    public static final Executor EXECUTOR = lol.trq.alts.TestExecutors.perTask(
            Thread.ofVirtual().name("test-io-", 0).factory());

    private TestTransports() {}

    /** A transport with no proxy provider, on the shared test executor. */
    public static HttpTransport direct() {
        return new HttpTransport(null, EXECUTOR);
    }

    /** A transport routed by {@code provider}, on the shared test executor. */
    public static HttpTransport through(ProxyProvider provider) {
        return new HttpTransport(provider, EXECUTOR);
    }

    /** A transport routed by {@code provider} whose blocking work runs on {@code executor}. */
    public static HttpTransport on(ProxyProvider provider, Executor executor) {
        return new HttpTransport(provider, executor);
    }

    /** A transport whose TLS trusts what {@code tls} trusts, for a loopback HTTPS origin. */
    public static HttpTransport trusting(ProxyProvider provider, SSLSocketFactory tls) {
        return new HttpTransport(provider, EXECUTOR, tls);
    }

    /** Returns how many close actions {@code transport} still holds registered. */
    public static int closerCount(HttpTransport transport) {
        return transport.closerCount();
    }

    /** Returns the route {@code transport} resolves for {@code scope}. */
    public static ProxyRoute routeFor(HttpTransport transport, NetworkScope scope) throws IOException {
        return transport.routeFor(scope);
    }
}

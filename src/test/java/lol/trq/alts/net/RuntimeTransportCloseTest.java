package lol.trq.alts.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpsServer;
import java.net.InetAddress;
import java.nio.file.Path;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;
import lol.trq.alts.AltsRuntime;
import lol.trq.alts.account.AccountEndpoints;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Closing a runtime closes the proxy tunnels its transport keeps alive. A pooled tunnel is a live
 * connection to the host's proxy under one route's identity; left open, it outlives the runtime that
 * chose the route.
 */
class RuntimeTransportCloseTest {

    @TempDir
    Path dir;

    @Test
    void closingTheRuntimeClosesItsPooledTunnels() throws Exception {
        // A runtime layers TLS with the JVM's default factory, so for this one test that default trusts
        // the loopback origin. Restored below; nothing else in this test class reaches TLS.
        SSLSocketFactory previous = HttpsURLConnection.getDefaultSSLSocketFactory();
        try (LoopbackTls tls = LoopbackTls.generate();
                ConnectProxy proxy = new ConnectProxy(null)) {
            HttpsServer origin = tls.newServer();
            origin.createContext("/", exchange -> {
                exchange.getRequestBody().readAllBytes();
                exchange.sendResponseHeaders(404, -1);
                exchange.close();
            });
            origin.start();
            HttpsURLConnection.setDefaultSSLSocketFactory(tls.trustingFactory());
            String loopback = InetAddress.getLoopbackAddress().getHostAddress();
            try {
                AltsRuntime<Object> alts = new AltsRuntime.Builder<Object>()
                        .sessionInjector(session -> {})
                        .vaultDirectory(() -> dir)
                        .mainThread(Runnable::run)
                        .toastSink((level, title, description, durationMs) -> {})
                        .accountEndpoints(new AccountEndpoints("https://" + loopback + ":"
                                + origin.getAddress().getPort()))
                        .proxyProvider(scope -> ProxyRoute.http(loopback, proxy.port()))
                        .build();

                assertTrue(alts.profileLookup().byName("Alex").isEmpty());
                assertTrue(alts.profileLookup().byName("Steve").isEmpty());
                assertEquals(1, proxy.requestLines().size(), "the second lookup reused the pooled tunnel");
                assertEquals(0, proxy.tunnelsClosedByClient());

                alts.close();

                for (int i = 0; i < 200 && proxy.tunnelsClosedByClient() == 0; i++) {
                    Thread.sleep(10);
                }
                assertEquals(1, proxy.tunnelsClosedByClient(), "closing the runtime closed the pooled tunnel");
            } finally {
                origin.stop(0);
            }
        } finally {
            HttpsURLConnection.setDefaultSSLSocketFactory(previous);
        }
    }
}

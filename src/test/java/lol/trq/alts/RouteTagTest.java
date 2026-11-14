package lol.trq.alts;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import lol.trq.alts.auth.LoginResult;
import lol.trq.alts.auth.MicrosoftAuthConfig;
import lol.trq.alts.bulk.BulkOptions;
import lol.trq.alts.bulk.BulkProgress;
import lol.trq.alts.bulk.BulkReport;
import lol.trq.alts.model.LoginMode;
import lol.trq.alts.net.NetworkScope;
import lol.trq.alts.net.ProxyRoute;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * A host that pins each account to its own proxy has nothing to route a new account's first sign-in on:
 * no account UUID exists yet. The route tag is how it says which proxy to use, and the provider sees it
 * on every request of that sign-in, through the runtime's own routes.
 */
class RouteTagTest {

    @TempDir
    Path dir;

    private HttpServer services;
    private final AtomicInteger next = new AtomicInteger();
    private final List<NetworkScope> scopes = new CopyOnWriteArrayList<>();

    @BeforeEach
    void start() throws Exception {
        services = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        services.createContext("/minecraft/profile", exchange -> {
            int id = next.incrementAndGet();
            byte[] body = String.format("{\"id\":\"00000000000040008000%012x\",\"name\":\"Alt%d\"}", id, id)
                    .getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        services.start();
    }

    @AfterEach
    void stop() {
        services.stop(0);
    }

    private AltsRuntime<Object> runtime() {
        String base = "http://" + InetAddress.getLoopbackAddress().getHostAddress() + ":"
                + services.getAddress().getPort();
        return new AltsRuntime.Builder<Object>()
                .sessionInjector(session -> {})
                .vaultDirectory(() -> dir)
                .mainThread(Runnable::run)
                .toastSink((level, title, description, durationMs) -> {})
                .microsoftAuth(MicrosoftAuthConfig.of("test-client")
                        .withEndpoints(null, null, null, null, null, base + "/minecraft/profile"))
                .proxyProvider(scope -> {
                    scopes.add(scope);
                    return ProxyRoute.direct();
                })
                .build();
    }

    @Test
    void aRoutedSessionSignInReachesTheProviderWithItsTag() throws Exception {
        try (AltsRuntime<Object> alts = runtime()) {
            LoginResult routed = alts.loginService()
                    .routed("pool-7")
                    .loginSession("opaque-session-token", LoginMode.ADD)
                    .get(10, TimeUnit.SECONDS);
            LoginResult plain = alts.loginService()
                    .loginSession("another-token", LoginMode.ADD)
                    .get(10, TimeUnit.SECONDS);

            assertTrue(routed.success() && plain.success(), routed.message() + " / " + plain.message());
            assertEquals(2, scopes.size(), scopes.toString());
            assertEquals(Optional.of("pool-7"), scopes.get(0).routeTag());
            assertEquals(Optional.empty(), scopes.get(1).routeTag(), "the service itself stays untagged");
            assertEquals(2, alts.store().accounts().size(), "a routed view stores like the service it came from");
        }
    }

    @Test
    void aTaggedImportCarriesTheTagOnEveryRequestAndAnUntaggedOneNone() throws Exception {
        List<String> tokens = List.of("eyJa.one", "eyJb.two", "eyJc.three");
        try (AltsRuntime<Object> alts = runtime()) {
            BulkReport tagged = alts.bulk()
                    .importCredentials(
                            tokens, LoginMode.ADD, BulkOptions.defaults().withRouteTag("pool-7"), null)
                    .report()
                    .get(30, TimeUnit.SECONDS);

            assertEquals(3, tagged.succeeded(), tagged.toString());
            assertEquals(3, scopes.size(), "one profile hop per imported session: " + scopes);
            assertTrue(
                    scopes.stream().allMatch(scope -> scope.routeTag().equals(Optional.of("pool-7"))),
                    scopes.toString());

            scopes.clear();
            BulkReport untagged = alts.bulk()
                    .importCredentials(tokens, LoginMode.ADD, BulkOptions.defaults(), BulkProgress.NONE)
                    .report()
                    .get(30, TimeUnit.SECONDS);
            assertEquals(3, untagged.succeeded());
            assertTrue(scopes.stream().allMatch(scope -> scope.routeTag().isEmpty()), scopes.toString());
        }
    }
}

package lol.trq.alts;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import javax.imageio.ImageIO;
import lol.trq.alts.account.AccountEndpoints;
import lol.trq.alts.account.AccountException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The account endpoints and the avatar template are set on the builder, because the services they feed
 * have no public factory of their own: what the builder names is where the runtime's services go.
 */
class AltsRuntimeBuilderRoutesTest {

    private static final String UUID = "00000000-0000-4000-8000-0000000000a1";

    @TempDir
    Path dir;

    private HttpServer server;
    private final List<String> paths = new CopyOnWriteArrayList<>();
    private byte[] png;

    @BeforeEach
    void startServer() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ImageIO.write(new BufferedImage(64, 64, BufferedImage.TYPE_INT_ARGB), "png", out);
        png = out.toByteArray();
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", exchange -> {
            String path = exchange.getRequestURI().getRawPath();
            paths.add(path);
            exchange.getRequestBody().readAllBytes();
            if (path.startsWith("/avatar/")) {
                exchange.getResponseHeaders().add("Content-Type", "image/png");
                exchange.sendResponseHeaders(200, png.length);
                exchange.getResponseBody().write(png);
            } else {
                exchange.sendResponseHeaders(404, -1);
            }
            exchange.close();
        });
        server.start();
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    private String base() {
        return "http://" + InetAddress.getLoopbackAddress().getHostAddress() + ":"
                + server.getAddress().getPort();
    }

    private AltsRuntime.Builder<String> builder() {
        return new AltsRuntime.Builder<String>()
                .sessionInjector(session -> {})
                .vaultDirectory(() -> dir)
                .mainThread(Runnable::run)
                .toastSink((level, title, description, durationMs) -> {});
    }

    @Test
    void theAccountServicesAndTheProfileLookupGoWhereTheBuilderSays() throws Exception {
        try (AltsRuntime<String> alts =
                builder().accountEndpoints(new AccountEndpoints(base())).build()) {
            assertTrue(alts.profileLookup().byName("Alex").isEmpty(), "the loopback knows nobody");
            assertThrows(
                    AccountException.class,
                    () -> alts.accountServices("token", UUID).entitlements().fetch());
        }

        assertTrue(paths.size() >= 2, "both requests reached the configured base: " + paths);
        assertTrue(paths.stream().anyMatch(path -> path.contains("Alex")), "the lookup went there: " + paths);
    }

    @Test
    void anAvatarTemplateIsFetchedThroughTheRuntime() throws Exception {
        try (AltsRuntime<String> alts = builder()
                .textureUploader(bytes -> "head")
                .avatarUrlTemplate(base() + "/avatar/{uuid}/{size}.png")
                .build()) {
            String head = null;
            for (int i = 0; i < 400 && head == null; i++) {
                head = alts.skinCache().get(UUID);
                if (head == null) {
                    Thread.sleep(10);
                }
            }
            assertEquals("head", head);
        }

        assertTrue(paths.stream().anyMatch(path -> path.startsWith("/avatar/" + UUID + "/")), "fetched: " + paths);
    }

    @Test
    void aTemplateWithoutAUuidOrBesideASourceFailsTheBuild() {
        assertThrows(
                IllegalArgumentException.class,
                () -> builder().avatarUrlTemplate(base() + "/avatar.png").build());
        assertThrows(
                IllegalStateException.class,
                () -> builder()
                        .avatarSource((uuid, size) -> null)
                        .avatarUrlTemplate(base() + "/avatar/{uuid}.png")
                        .build());

        // Neither refused build kept the store files.
        try (AltsRuntime<String> alts = builder().build()) {
            assertTrue(alts.store().loadError().isEmpty());
        }
    }
}

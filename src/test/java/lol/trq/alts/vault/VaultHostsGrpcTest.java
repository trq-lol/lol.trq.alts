package lol.trq.alts.vault;

import static lol.trq.alts.vault.VaultWorld.await;
import static lol.trq.alts.vault.VaultWorld.failure;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.AltsRuntime;
import lol.trq.alts.internal.vault.GrpcGatewayChannel;
import lol.trq.alts.internal.vault.TestAvpHost;
import lol.trq.alts.spi.VaultRpcChannel;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Transport selection through a built runtime: the mapping's scheme picks the wire, the factory the channel. */
class VaultHostsGrpcTest {

    @TempDir
    Path dir;

    private TestAvpHost host;
    private GrpcGatewayChannel gateway;
    private final List<AltsRuntime<Object>> runtimes = new ArrayList<>();

    @BeforeEach
    void start() throws Exception {
        host = new TestAvpHost();
        gateway = new GrpcGatewayChannel(host);
    }

    @AfterEach
    void stop() {
        runtimes.forEach(AltsRuntime::close);
        gateway.close();
        host.close();
    }

    private String locator() {
        return VaultWorld.locator(host);
    }

    private AltsRuntime<Object> runtime(Function<String, URI> mapping, Function<URI, VaultRpcChannel> channels) {
        AltsRuntime.Builder<Object> b = new AltsRuntime.Builder<Object>()
                .sessionInjector(session -> {})
                .vaultDirectory(() -> dir.resolve("r" + runtimes.size()))
                .mainThread(Runnable::run)
                .toastSink((level, title, description, durationMs) -> {})
                .vaultHostAddress(mapping);
        if (channels != null) {
            b.vaultRpcChannel(channels);
        }
        AltsRuntime<Object> alts = b.build();
        runtimes.add(alts);
        return alts;
    }

    /** A channel that counts closes, to show the runtime never closes one. */
    static final class Owned implements VaultRpcChannel, AutoCloseable {
        final VaultRpcChannel inner;
        volatile boolean closed;

        Owned(VaultRpcChannel inner) {
            this.inner = inner;
        }

        @Override
        public CompletableFuture<Reply> unary(
                String method, byte[] request, Map<String, String> metadata, Duration deadline) {
            return inner.unary(method, request, metadata, deadline);
        }

        @Override
        public void close() {
            closed = true;
        }
    }

    @Test
    void aGrpcsMappingWithoutAChannelIsNotConfigured() {
        AltsRuntime<Object> alts = runtime(l -> URI.create("grpcs://" + l), null);
        assertEquals(
                Kind.NOT_CONFIGURED,
                failure(alts.vault().connectFirstContact(locator())).kind());
        assertEquals(0, host.requests().size());
    }

    @Test
    void aGrpcsMappingUsesTheInjectedChannel() {
        List<URI> asked = new ArrayList<>();
        AltsRuntime<Object> alts = runtime(l -> URI.create("grpcs://" + l), uri -> {
            asked.add(uri);
            return gateway;
        });
        VaultHost h = await(alts.vault().connectFirstContact(locator()));
        assertEquals(Base64.getEncoder().encodeToString(host.key()), h.hostKey());
        assertEquals(locator(), h.locator());
        assertEquals(List.of(URI.create("grpcs://" + locator())), asked);
        assertEquals(1, gateway.count("avp.Vault/GetHostInfo"));
    }

    @Test
    void anHttpsMappingIgnoresTheChannel() {
        List<URI> asked = new ArrayList<>();
        AltsRuntime<Object> alts = runtime(l -> URI.create("http://" + l), uri -> {
            asked.add(uri);
            return gateway;
        });
        await(alts.vault().connectFirstContact(locator()));
        assertEquals(List.of(), asked);
        assertEquals(0, gateway.calls().size());
        assertEquals(1, host.count("/.well-known/avp"));
    }

    @Test
    void aChannelFactoryThatThrowsOrReturnsNullIsInvalidInput() {
        AltsRuntime<Object> throwing = runtime(l -> URI.create("grpc://" + l), uri -> {
            throw new IllegalStateException("no channel");
        });
        assertEquals(
                Kind.INVALID_INPUT,
                failure(throwing.vault().connectFirstContact(locator())).kind());
        AltsRuntime<Object> nulls = runtime(l -> URI.create("grpc://" + l), uri -> null);
        assertEquals(
                Kind.INVALID_INPUT,
                failure(nulls.vault().connectFirstContact(locator())).kind());
        AltsRuntime<Object> other = runtime(l -> URI.create("ftp://" + l), uri -> gateway);
        assertEquals(
                Kind.INVALID_INPUT,
                failure(other.vault().connectFirstContact(locator())).kind());
        AltsRuntime<Object> hostless = runtime(l -> URI.create("grpc:opaque"), uri -> gateway);
        assertEquals(
                Kind.INVALID_INPUT,
                failure(hostless.vault().connectFirstContact(locator())).kind());
    }

    @Test
    void theSameHostOverTwoProfilesKeepsItsTokensApart() throws Exception {
        AtomicReference<String> scheme = new AtomicReference<>("http");
        AltsRuntime<Object> alts = runtime(l -> URI.create(scheme.get() + "://" + l), uri -> gateway);
        OwnerIdentity owner = OwnerIdentity.generate();
        SharedVault created = await(SharedVault.create(await(alts.vault().connectFirstContact(locator())), owner));
        assertEquals(1, host.count("/api/auth/keypair/challenge"));
        assertEquals(0, gateway.calls().size());

        scheme.set("grpc");
        VaultHost overGrpc = await(alts.vault().connectFirstContact(locator()));
        SharedVault reopened = await(SharedVault.open(overGrpc, owner, created.repoId()));
        assertEquals(created.repoId(), reopened.repoId());
        assertEquals(1, gateway.count("avp.Vault/Challenge"), "a token minted at the http origin is not reused");
        assertEquals(2, host.count("/api/auth/keypair/challenge"));
    }

    @Test
    void theFactoryRunsOncePerUriAndCloseNeverClosesTheChannel() throws Exception {
        TestAvpHost second = new TestAvpHost();
        try (GrpcGatewayChannel secondGateway = new GrpcGatewayChannel(second)) {
            List<Owned> made = new ArrayList<>();
            AltsRuntime<Object> alts = runtime(l -> URI.create("grpc://" + l), uri -> {
                Owned o = new Owned(uri.getPort() == host.base().getPort() ? gateway : secondGateway);
                made.add(o);
                return o;
            });
            await(alts.vault().connectFirstContact(locator()));
            await(alts.vault().connectFirstContact(locator()));
            assertEquals(1, made.size(), "one channel per mapped URI");
            await(alts.vault().connectFirstContact(VaultWorld.locator(second)));
            assertEquals(2, made.size());

            AltsRuntime<Object> another = runtime(l -> URI.create("grpc://" + l), uri -> {
                Owned o = new Owned(gateway);
                made.add(o);
                return o;
            });
            await(another.vault().connectFirstContact(locator()));
            assertEquals(3, made.size(), "the cache is per runtime");

            alts.close();
            another.close();
            for (Owned o : made) {
                assertFalse(o.closed, "the runtime never closes a channel");
            }
        } finally {
            second.close();
        }
    }
}

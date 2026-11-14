package lol.trq.alts.internal.vault;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.fail;

import com.google.gson.JsonPrimitive;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;
import lol.trq.alts.AltsException;
import lol.trq.alts.internal.avp.AvpCrypto;
import lol.trq.alts.internal.avp.OwnerKeys;
import lol.trq.alts.internal.avp.Payload;
import lol.trq.alts.net.HttpTransport;
import lol.trq.alts.net.NetworkScope;
import lol.trq.alts.net.ProxyRoute;

/** One test's world: a test host, a transport that records every scope, a token cache and a clock. */
final class VaultFixture implements AutoCloseable {

    static final String ACCOUNT = "0b5e7f2a-5d1c-4a6e-9c1e-1f0d4a7b3c21";

    final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
    final List<NetworkScope> scopes = Collections.synchronizedList(new ArrayList<>());
    final HttpTransport transport = new HttpTransport(
            scope -> {
                scopes.add(scope);
                return ProxyRoute.direct();
            },
            executor);
    final TokenCache tokens = new TokenCache();
    final AtomicLong skew = new AtomicLong();
    final LongSupplier clock = () -> System.currentTimeMillis() + skew.get();
    final TestAvpHost host;
    private final List<TestAvpHost> others = new ArrayList<>();

    VaultFixture() throws IOException {
        host = new TestAvpHost();
    }

    TestAvpHost anotherHost() throws IOException {
        TestAvpHost h = new TestAvpHost();
        others.add(h);
        return h;
    }

    HostClient connect() {
        return connect(host);
    }

    HostClient connect(TestAvpHost h) {
        return HostClient.connect(transport, h.base(), null, tokens, clock);
    }

    /** An owner identity from fresh entropy; the entropy is kept for the zero-knowledge checks. */
    record Owner(byte[] entropy, OwnerKeys keys) {
        MemberKeys member() {
            return MemberKeys.ofOwner(keys);
        }
    }

    static Owner newOwner() {
        byte[] entropy = AvpCrypto.randomBytes(32);
        return new Owner(entropy, OwnerKeys.fromEntropy(entropy));
    }

    VaultEngine create(Owner owner) {
        return await(VaultEngine.create(connect(), owner.keys(), clock));
    }

    /** Bob's whole join: prepareJoin on his home host, the owner's invite, then the join itself. */
    VaultEngine invite(VaultEngine owner, MemberKeys member) {
        HostClient home = connect();
        await(owner.invite(await(VaultEngine.prepareJoin(home, member, owner.repoId()))));
        return await(VaultEngine.join(home, member, owner.locator(), clock));
    }

    static void set(VaultEngine v, String field, String value) {
        await(v.write(e -> e.setField(ACCOUNT, field, new JsonPrimitive(value))));
    }

    static String field(Payload p, String name) {
        Payload.Account a = p.accounts().get(ACCOUNT);
        if (a == null || !a.fields().containsKey(name)) {
            return null;
        }
        return a.fields().get(name).value().getAsString();
    }

    static <T> T await(CompletableFuture<T> f) {
        try {
            return f.get(30, TimeUnit.SECONDS);
        } catch (ExecutionException e) {
            if (e.getCause() instanceof AltsException ae) {
                throw ae;
            }
            throw new AssertionError("a vault future failed with something other than AltsException", e.getCause());
        } catch (InterruptedException | TimeoutException e) {
            throw new AssertionError("the vault future did not complete", e);
        }
    }

    /** The failure a future ends with; it must be an {@link AltsException}. */
    static AltsException failure(CompletableFuture<?> f) {
        try {
            f.get(30, TimeUnit.SECONDS);
        } catch (ExecutionException e) {
            return assertInstanceOf(AltsException.class, e.getCause(), "a vault future fails only with AltsException");
        } catch (InterruptedException | TimeoutException e) {
            throw new AssertionError("the vault future did not complete", e);
        }
        return fail("expected the vault operation to fail");
    }

    @Override
    public void close() {
        host.close();
        others.forEach(TestAvpHost::close);
        transport.close();
        executor.shutdownNow();
    }
}

package lol.trq.alts.vault;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Path;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsRuntime;
import lol.trq.alts.internal.vault.TestAvpHost;

/**
 * One public-API vault test's world: a runtime on a temporary directory whose vault reaches loopback test
 * hosts over plain {@code http}, and the honest test host of the engine tests in front of it.
 */
final class VaultWorld implements AutoCloseable {

    final TestAvpHost host;
    final AltsRuntime<Object> alts;

    VaultWorld(Path dir) throws IOException {
        host = new TestAvpHost();
        alts = new AltsRuntime.Builder<Object>()
                .sessionInjector(session -> {})
                .vaultDirectory(() -> dir)
                .mainThread(Runnable::run)
                .toastSink((level, title, description, durationMs) -> {})
                .vaultHostAddress(locator -> URI.create("http://" + locator))
                .build();
    }

    /** The test host's locator, {@code 127.0.0.1:<port>}. */
    static String locator(TestAvpHost h) {
        URI base = h.base();
        return base.getHost() + ":" + base.getPort();
    }

    /** The first contact with the world's host, by locator alone. */
    VaultHost home() {
        return await(alts.vault().connectFirstContact(locator(host)));
    }

    static <T> T await(CompletableFuture<T> f) {
        try {
            return f.get(60, TimeUnit.SECONDS);
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
            f.get(60, TimeUnit.SECONDS);
        } catch (ExecutionException e) {
            return assertInstanceOf(AltsException.class, e.getCause(), "a vault future fails only with AltsException");
        } catch (InterruptedException | TimeoutException e) {
            throw new AssertionError("the vault future did not complete", e);
        }
        return fail("expected the vault operation to fail");
    }

    @Override
    public void close() {
        alts.close();
        host.close();
    }
}

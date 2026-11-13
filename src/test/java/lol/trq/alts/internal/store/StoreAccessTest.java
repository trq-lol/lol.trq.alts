package lol.trq.alts.internal.store;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicBoolean;
import lol.trq.alts.AltsRuntime;
import lol.trq.alts.internal.ChildFirstLoader;
import lol.trq.alts.spi.StoreKeyProvider;
import lol.trq.alts.store.AccountStore;
import lol.trq.alts.store.HostSecrets;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The bridge sees every key provider and every store a runtime opens, so no code but the store package
 * may install one: a foreign bridge is refused whenever it is offered, and the library goes on working.
 */
class StoreAccessTest {

    @TempDir
    Path dir;

    @Test
    void aForeignBridgeIsRefusedAndTheLibraryStillBuilds() {
        AtomicBoolean reached = new AtomicBoolean();
        StoreAccess.Bridge foreign = new StoreAccess.Bridge() {
            @Override
            public AccountStore openAccounts(
                    Path directory, String fileName, String keyBinding, StoreKeyProvider key, boolean migrate) {
                reached.set(true);
                return null;
            }

            @Override
            public HostSecrets openSecrets(
                    Path directory, String fileName, String keyBinding, StoreKeyProvider key, boolean migrate) {
                reached.set(true);
                return null;
            }

            @Override
            public void close(AccountStore store) {
                reached.set(true);
            }

            @Override
            public void close(HostSecrets secrets) {
                reached.set(true);
            }
        };

        // Refused as foreign, not merely as late: the check does not depend on what was installed first.
        assertThrows(IllegalArgumentException.class, () -> StoreAccess.install(foreign));
        assertNotSame(foreign, StoreAccess.bridge());

        try (AltsRuntime<Object> alts = new AltsRuntime.Builder<Object>()
                .sessionInjector(session -> {})
                .vaultDirectory(() -> dir)
                .mainThread(Runnable::run)
                .toastSink((level, title, description, durationMs) -> {})
                .storeKeyProvider(() -> "0123456789abcdef0123456789abcdef".getBytes())
                .build()) {
            assertTrue(alts.store().loadError().isEmpty());
        }
        assertFalse(reached.get(), "the foreign bridge never saw a key provider or a store");
    }

    @Test
    void aBridgeOfTheRightNameFromAnotherClassLoaderIsRefused() {
        String bridgeName = "lol.trq.alts.store.StoreBridge";
        ClassLoader foreign = new ChildFirstLoader(StoreAccessTest.class.getClassLoader(), bridgeName);

        // Initializing the copy runs its static initializer, which offers a bridge of the library's own
        // class name to the library's StoreAccess; only the defining loader tells it apart.
        ExceptionInInitializerError refused =
                assertThrows(ExceptionInInitializerError.class, () -> Class.forName(bridgeName, true, foreign));

        assertInstanceOf(IllegalArgumentException.class, refused.getCause());
        assertNotSame(foreign, StoreAccess.bridge().getClass().getClassLoader());
    }

    @Test
    void theLibrarysOwnBridgeIsNotInstalledTwice() {
        StoreAccess.Bridge installed = StoreAccess.bridge();

        assertThrows(IllegalStateException.class, () -> StoreAccess.install(installed));
    }
}

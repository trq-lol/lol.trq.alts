package lol.trq.alts.store;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import lol.trq.alts.model.AccountType;
import lol.trq.alts.model.AltAccount;
import lol.trq.alts.spi.StoreKeyProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * A host key replaces the machine-derived one without stranding the files written before it, and a file
 * sealed under a host key stays sealed when that key is not there.
 */
class StoreKeyProviderTest {

    private static final String FILE_NAME = "accounts.dat";
    private static final String UUID = "00000000-0000-4000-8000-0000000000c1";
    private static final StoreKeyProvider HOST_KEY = () -> "0123456789abcdef0123456789abcdef".getBytes();

    @TempDir
    Path storeDir;

    @BeforeEach
    void bindStore() {
        AltStore.bind(() -> storeDir);
        AltStore.accounts().clear();
        AltStore.useAccount(null);
        AltStore.load();
    }

    @AfterEach
    void removeProvider() {
        AltStore.keyProvider(null);
        AltStore.flush();
    }

    private Path storeFile() {
        return storeDir.resolve(FILE_NAME);
    }

    private static AltAccount alex() {
        return AltAccount.of(UUID, "Alex", "access", AccountType.MICROSOFT);
    }

    private static void reload() {
        AltStore.accounts().clear();
        AltStore.load();
    }

    @Test
    void aStoreRoundTripsUnderAHostKey() {
        AltStore.keyProvider(HOST_KEY);
        AltStore.addAccount(alex());

        reload();

        assertTrue(AltStore.loadError().isEmpty());
        assertEquals(1, AltStore.accounts().size());
    }

    @Test
    void aStoreWrittenUnderAHostKeyDoesNotOpenWithoutIt() throws Exception {
        AltStore.keyProvider(HOST_KEY);
        AltStore.addAccount(alex());
        byte[] sealed = Files.readAllBytes(storeFile());

        AltStore.keyProvider(null);
        reload();

        assertTrue(AltStore.loadError().isPresent(), "without the host key the file is unreadable, and says so");
        assertTrue(AltStore.accounts().isEmpty());
        assertArrayEquals(sealed, Files.readAllBytes(storeFile()), "a failed load must leave the file as it was");

        AltStore.addAccount(AltAccount.of("00000000-0000-4000-8000-0000000000c2", "Steve", "b", AccountType.OFFLINE));

        assertArrayEquals(
                sealed,
                Files.readAllBytes(storeDir.resolve(FILE_NAME + ".unreadable")),
                "a later save must keep the sealed file rather than destroy it");
    }

    @Test
    void aStoreWrittenUnderADifferentHostKeyDoesNotOpen() {
        AltStore.keyProvider(HOST_KEY);
        AltStore.addAccount(alex());

        AltStore.keyProvider(() -> "another-host-key-of-enough-bytes".getBytes());
        reload();

        assertTrue(AltStore.loadError().isPresent());
        assertTrue(AltStore.accounts().isEmpty());
    }

    @Test
    void aFileFromBeforeTheHostKeyLoadsAndIsResealedUnderIt() {
        AltStore.addAccount(alex());

        AltStore.keyProvider(HOST_KEY);
        reload();

        assertTrue(AltStore.loadError().isEmpty(), "installing a key provider must not strand existing accounts");
        assertEquals(1, AltStore.accounts().size());

        AltStore.keyProvider(null);
        reload();

        assertTrue(AltStore.loadError().isPresent(), "the migrated file is now sealed under the host key only");
    }

    @Test
    void aProviderThatCannotAnswerFailsClosed() throws Exception {
        AltStore.addAccount(alex());
        byte[] machineKeyed = Files.readAllBytes(storeFile());

        AltStore.keyProvider(() -> {
            throw new IllegalStateException("keystore locked");
        });
        reload();

        String loadError = AltStore.loadError().orElseThrow();
        assertFalse(loadError.contains("keystore locked"), "a provider's message is not ours to publish: " + loadError);
        assertTrue(AltStore.accounts().isEmpty(), "no fallback to the machine key while a provider is installed");

        AltStore.addAccount(alex());

        assertTrue(
                AltStore.saveError().isPresent(), "nothing may be written under a weaker key than the host asked for");
        assertArrayEquals(machineKeyed, Files.readAllBytes(storeFile()));

        AltStore.keyProvider(null);
        AltStore.flush();
        assertTrue(AltStore.saveError().isEmpty());
    }

    @Test
    void tooLittleKeyMaterialIsRefused() {
        AltStore.keyProvider(() -> new byte[StoreKeyProvider.MIN_LENGTH - 1]);

        AltStore.addAccount(alex());

        assertTrue(AltStore.saveError().isPresent());
        assertFalse(Files.exists(storeFile()));

        AltStore.keyProvider(null);
        AltStore.flush();
    }
}

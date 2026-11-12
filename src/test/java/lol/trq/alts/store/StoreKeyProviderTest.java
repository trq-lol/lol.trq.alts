package lol.trq.alts.store;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import lol.trq.alts.model.AccountType;
import lol.trq.alts.model.AltAccount;
import lol.trq.alts.spi.StoreKeyProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * A host key is what makes a copied store directory useless without the host's secret. So once one is
 * installed nothing may open, be written, or be left behind under the machine-derived key, except on the
 * one launch where the host asks for files from before the key to be migrated.
 */
class StoreKeyProviderTest {

    private static final String FILE_NAME = "accounts.dat";
    private static final String KEY_BINDING = "lol.trq.alts";
    private static final String UUID = "00000000-0000-4000-8000-0000000000c1";
    private static final String OTHER_UUID = "00000000-0000-4000-8000-0000000000c2";
    private static final StoreKeyProvider HOST_KEY = () -> "0123456789abcdef0123456789abcdef".getBytes();

    @TempDir
    Path storeDir;

    @BeforeEach
    void bindStore() {
        StoreTestHooks.reset();
        AltStore.bind(() -> storeDir);
        AltStore.load();
    }

    @AfterEach
    void forgetTheHostKey() {
        StoreTestHooks.reset();
    }

    private Path storeFile() {
        return storeDir.resolve(FILE_NAME);
    }

    private static AltAccount alex() {
        return AltAccount.of(UUID, "Alex", "access", AccountType.MICROSOFT);
    }

    private static AltAccount steve() {
        return AltAccount.of(OTHER_UUID, "Steve", "b", AccountType.OFFLINE);
    }

    private static void reload() {
        AltStore.accounts().clear();
        AltStore.load();
    }

    /** Starts over as a new process would: nothing in memory, and only the given key and opt-in. */
    private void restart(StoreKeyProvider key, boolean migrateFromMachineKey) {
        StoreTestHooks.reset();
        AltStore.bind(() -> storeDir, key, migrateFromMachineKey);
        AltStore.load();
    }

    private boolean holds(String uuid) {
        return AltStore.accounts().stream().anyMatch(account -> uuid.equals(account.uuid()));
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

        restart(null, false);

        assertTrue(AltStore.loadError().isPresent(), "without the host key the file is unreadable, and says so");
        assertTrue(AltStore.accounts().isEmpty());
        assertArrayEquals(sealed, Files.readAllBytes(storeFile()), "a failed load must leave the file as it was");

        AltStore.addAccount(steve());

        List<byte[]> kept = StoreTestHooks.unreadableCopies(storeDir, FILE_NAME);
        assertEquals(1, kept.size(), "a later save must keep the sealed file rather than destroy it");
        assertArrayEquals(sealed, kept.get(0));
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
    void aFileFromBeforeTheHostKeyDoesNotLoadUnlessTheHostAsksForTheMigration() throws Exception {
        AltStore.addAccount(alex());
        byte[] machineKeyed = Files.readAllBytes(storeFile());

        restart(HOST_KEY, false);

        assertTrue(
                AltStore.loadError().isPresent(),
                "a store sealed under the machine key must not load under a host key by default");
        assertTrue(AltStore.accounts().isEmpty());
        assertArrayEquals(machineKeyed, Files.readAllBytes(storeFile()), "and it is left exactly as it was");
    }

    @Test
    void migratingToAHostKeyLeavesNothingInTheDirectoryThatOpensUnderTheMachineKey() throws Exception {
        // Two writes, so the rolling backup exists and is sealed under the machine key as well, plus an
        // unreadable copy from some earlier incident that happens to be a machine-keyed store.
        AltStore.addAccount(alex());
        AltStore.addAccount(steve());
        Files.copy(storeFile(), storeDir.resolve(FILE_NAME + ".unreadable.1"));
        assertTrue(Files.exists(storeDir.resolve(FILE_NAME + ".bak")), "the test needs a machine-keyed backup");

        restart(HOST_KEY, true);
        AltStore.flush();

        assertTrue(AltStore.loadError().isEmpty(), "the migration must not strand the existing accounts");
        assertEquals(2, AltStore.accounts().size());
        assertEquals(
                List.of(),
                StoreTestHooks.filesOpeningUnderMachineKey(storeDir, KEY_BINDING),
                "a host key protects a copied directory only if no file in it still opens under the old key");

        restart(HOST_KEY, false);

        assertTrue(AltStore.loadError().isEmpty(), "the migrated store is sealed under the host key");
        assertEquals(2, AltStore.accounts().size());
    }

    @Test
    void aMachineKeyedFilePlantedOverAHostKeyedStoreDoesNotLoad() throws Exception {
        AltStore.addAccount(steve());
        byte[] planted = Files.readAllBytes(storeFile());
        Files.delete(storeFile());

        restart(HOST_KEY, false);
        AltStore.addAccount(alex());
        Files.write(storeFile(), planted);

        restart(HOST_KEY, false);

        assertTrue(AltStore.loadError().isPresent(), "a file anyone on the machine could have sealed is not trusted");
        assertFalse(holds(OTHER_UUID), "the planted account must not reach the list");
    }

    @Test
    void aNullProviderNeverRemovesAnInstalledOne() throws Exception {
        AltStore.keyProvider(HOST_KEY);
        AltStore.addAccount(alex());

        AltStore.keyProvider(null);
        AltStore.bind(() -> storeDir);
        AltStore.bind(() -> storeDir, null, false);
        reload();

        assertTrue(AltStore.loadError().isEmpty(), "the store is still read under the host key");
        assertTrue(holds(UUID));

        AltStore.addAccount(steve());

        assertFalse(
                StoreTestHooks.opensUnderMachineKey(storeFile(), KEY_BINDING),
                "and still written under it: binding again must not downgrade the store to the machine key");
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
    }

    @Test
    void aStoreWhoseKeyWasUnavailableIsNotOverwrittenOnceTheKeyComesBack() throws Exception {
        AtomicBoolean locked = new AtomicBoolean();
        StoreKeyProvider keychain = () -> {
            if (locked.get()) {
                throw new IllegalStateException("keychain locked");
            }
            return HOST_KEY.keyMaterial();
        };
        AltStore.keyProvider(keychain);
        AltStore.addAccount(alex());
        byte[] real = Files.readAllBytes(storeFile());

        // The next launch starts with the keychain locked; it is unlocked a moment later.
        locked.set(true);
        restart(keychain, false);
        assertTrue(AltStore.loadError().isPresent());
        locked.set(false);

        AltStore.addAccount(steve());
        AltStore.save();

        assertTrue(AltStore.saveError().isPresent(), "a refused write must say so");
        assertArrayEquals(
                real,
                Files.readAllBytes(storeFile()),
                "the store was never read, so a list holding only what was added since must not replace it");
        assertEquals(List.of(storeFile()), listDirectory(), "and nothing else may appear on disk either");

        AltStore.load();

        assertTrue(AltStore.loadError().isEmpty(), "a load that works retracts the failure");
        assertTrue(AltStore.saveError().isEmpty(), "and with it the refusal");
        assertTrue(holds(UUID), "the real store is what the list holds now");

        AltStore.addAccount(steve());
        reload();

        assertTrue(holds(UUID) && holds(OTHER_UUID), "and from here on writes land again");
    }

    @Test
    void outsideTheTestSuiteAnInstalledKeyCannotBeRemoved() throws Exception {
        AltStore.keyProvider(HOST_KEY);
        AltStore.addAccount(alex());
        System.clearProperty("lol.trq.alts.testSeams");
        try {
            assertThrows(IllegalStateException.class, StoreTestHooks::reset);
        } finally {
            System.setProperty("lol.trq.alts.testSeams", "true");
        }

        AltStore.addAccount(steve());

        assertFalse(
                StoreTestHooks.opensUnderMachineKey(storeFile(), KEY_BINDING),
                "the reset is a test seam; in an application it must not be a way to drop the host key");
    }

    @Test
    void tooLittleKeyMaterialIsRefused() {
        AltStore.keyProvider(() -> new byte[StoreKeyProvider.MIN_LENGTH - 1]);

        AltStore.addAccount(alex());

        assertTrue(AltStore.saveError().isPresent());
        assertFalse(Files.exists(storeFile()));
    }

    private List<Path> listDirectory() throws Exception {
        try (var entries = Files.list(storeDir)) {
            return entries.toList();
        }
    }
}

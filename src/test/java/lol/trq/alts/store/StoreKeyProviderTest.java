package lol.trq.alts.store;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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

    private AccountStore store;

    @BeforeEach
    void openStore() {
        store = AccountStore.open(storeDir);
        store.load();
    }

    @AfterEach
    void closeStore() {
        store.close();
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

    private void reload() {
        store.accounts().clear();
        store.load();
    }

    /** Starts over as a new process would: nothing in memory, and only the given key and opt-in. */
    private void restart(StoreKeyProvider key, boolean migrateFromMachineKey) {
        store.close();
        store = AccountStore.open(storeDir, null, null, key, migrateFromMachineKey, null);
        store.load();
    }

    private boolean holds(String uuid) {
        return store.accounts().stream().anyMatch(account -> uuid.equals(account.uuid()));
    }

    @Test
    void aStoreRoundTripsUnderAHostKey() {
        restart(HOST_KEY, false);
        store.addAccount(alex());

        reload();

        assertTrue(store.loadError().isEmpty());
        assertEquals(1, store.accounts().size());
    }

    @Test
    void aStoreWrittenUnderAHostKeyDoesNotOpenWithoutIt() throws Exception {
        restart(HOST_KEY, false);
        store.addAccount(alex());
        byte[] sealed = Files.readAllBytes(storeFile());

        restart(null, false);

        assertTrue(store.loadError().isPresent(), "without the host key the file is unreadable, and says so");
        assertTrue(store.accounts().isEmpty());
        assertArrayEquals(sealed, Files.readAllBytes(storeFile()), "a failed load must leave the file as it was");

        List<byte[]> kept = StoreTestHooks.unreadableCopies(storeDir, FILE_NAME);
        assertEquals(1, kept.size(), "the failed load copies the sealed file aside");
        assertArrayEquals(sealed, kept.get(0));

        store.addAccount(steve());
        store.save();
        store.close();

        assertArrayEquals(
                sealed,
                Files.readAllBytes(storeFile()),
                "a store without the key must not write a machine-keyed store over the host-keyed one");
        assertFalse(StoreTestHooks.opensUnderMachineKey(storeFile(), KEY_BINDING));

        restart(HOST_KEY, false);
        assertTrue(holds(UUID), "the host-keyed store is still there for the runtime that has the key");
    }

    @Test
    void aStoreWrittenUnderADifferentHostKeyDoesNotOpen() throws Exception {
        restart(HOST_KEY, false);
        store.addAccount(alex());
        byte[] sealed = Files.readAllBytes(storeFile());

        restart(() -> "another-host-key-of-enough-bytes".getBytes(), false);

        assertTrue(store.loadError().isPresent());
        assertTrue(store.accounts().isEmpty());

        store.addAccount(steve());
        store.save();
        store.close();

        assertArrayEquals(sealed, Files.readAllBytes(storeFile()), "the wrong key writes nothing over the file");
        restart(HOST_KEY, false);
        assertTrue(store.loadError().isEmpty(), "and it still opens under the key that sealed it");
        assertTrue(holds(UUID) && !holds(OTHER_UUID));
    }

    @Test
    void aFileFromBeforeTheHostKeyDoesNotLoadUnlessTheHostAsksForTheMigration() throws Exception {
        store.addAccount(alex());
        byte[] machineKeyed = Files.readAllBytes(storeFile());

        restart(HOST_KEY, false);

        assertTrue(
                store.loadError().isPresent(),
                "a store sealed under the machine key must not load under a host key by default");
        assertTrue(store.accounts().isEmpty());
        assertArrayEquals(machineKeyed, Files.readAllBytes(storeFile()), "and it is left exactly as it was");
    }

    @Test
    void migratingToAHostKeyLeavesNothingInTheDirectoryThatOpensUnderTheMachineKey() throws Exception {
        // Two writes, so the rolling backup exists and is sealed under the machine key as well, plus an
        // unreadable copy from some earlier incident that happens to be a machine-keyed store.
        store.addAccount(alex());
        store.addAccount(steve());
        Files.copy(storeFile(), storeDir.resolve(FILE_NAME + ".unreadable.1"));
        assertTrue(Files.exists(storeDir.resolve(FILE_NAME + ".bak")), "the test needs a machine-keyed backup");

        restart(HOST_KEY, true);
        store.flush();

        assertTrue(store.loadError().isEmpty(), "the migration must not strand the existing accounts");
        assertEquals(2, store.accounts().size());
        assertEquals(
                List.of(),
                StoreTestHooks.filesOpeningUnderMachineKey(storeDir, KEY_BINDING),
                "a host key protects a copied directory only if no file in it still opens under the old key");

        restart(HOST_KEY, false);

        assertTrue(store.loadError().isEmpty(), "the migrated store is sealed under the host key");
        assertEquals(2, store.accounts().size());
    }

    @Test
    void aMachineKeyedFilePlantedOverAHostKeyedStoreDoesNotLoad() throws Exception {
        store.addAccount(steve());
        byte[] planted = Files.readAllBytes(storeFile());
        Files.delete(storeFile());

        restart(HOST_KEY, false);
        store.addAccount(alex());
        Files.write(storeFile(), planted);

        restart(HOST_KEY, false);

        assertTrue(store.loadError().isPresent(), "a file anyone on the machine could have sealed is not trusted");
        assertFalse(holds(OTHER_UUID), "the planted account must not reach the list");
    }

    @Test
    void aProviderThatCannotAnswerFailsClosed() throws Exception {
        store.addAccount(alex());
        byte[] machineKeyed = Files.readAllBytes(storeFile());

        restart(
                () -> {
                    throw new IllegalStateException("keystore locked");
                },
                false);

        String loadError = store.loadError().orElseThrow();
        assertFalse(loadError.contains("keystore locked"), "a provider's message is not ours to publish: " + loadError);
        assertTrue(store.accounts().isEmpty(), "no fallback to the machine key while a provider is installed");

        store.addAccount(alex());

        assertTrue(store.saveError().isPresent(), "nothing may be written under a weaker key than the host asked for");
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
        restart(keychain, false);
        store.addAccount(alex());
        byte[] real = Files.readAllBytes(storeFile());

        // The next launch starts with the keychain locked; it is unlocked a moment later.
        locked.set(true);
        restart(keychain, false);
        assertTrue(store.loadError().isPresent());
        locked.set(false);

        store.addAccount(steve());
        store.save();

        assertTrue(store.saveError().isPresent(), "a refused write must say so");
        assertArrayEquals(
                real,
                Files.readAllBytes(storeFile()),
                "the store was never read, so a list holding only what was added since must not replace it");
        assertEquals(List.of(storeFile()), listDirectory(), "and nothing else may appear on disk either");

        store.load();
        store.flush();

        assertArrayEquals(
                real,
                Files.readAllBytes(storeFile()),
                "the snapshot held back while refused is stale once the load replaced memory; it is never written");
        assertTrue(store.loadError().isEmpty(), "a load that works retracts the failure");
        assertTrue(store.saveError().isEmpty(), "and with it the refusal");
        assertTrue(holds(UUID), "the real store is what the list holds now");

        store.addAccount(steve());
        reload();

        assertTrue(holds(UUID) && holds(OTHER_UUID), "and from here on writes land again");
    }

    @Test
    void discardingAFileUnreadForWantOfTheKeyKeepsACopyOfIt() throws Exception {
        restart(HOST_KEY, false);
        store.addAccount(alex());
        byte[] real = Files.readAllBytes(storeFile());
        restart(
                () -> {
                    throw new IllegalStateException("keychain gone for good");
                },
                false);
        assertEquals(List.of(), StoreTestHooks.unreadableCopies(storeDir, FILE_NAME), "intact, so not copied yet");

        store.discardUnreadable();

        List<byte[]> kept = StoreTestHooks.unreadableCopies(storeDir, FILE_NAME);
        assertEquals(1, kept.size(), "giving up on the file must not cost it");
        assertArrayEquals(real, kept.get(0));
    }

    @Test
    void tooLittleKeyMaterialIsRefused() {
        restart(() -> new byte[StoreKeyProvider.MIN_LENGTH - 1], false);

        store.addAccount(alex());

        assertTrue(store.saveError().isPresent());
        assertFalse(Files.exists(storeFile()));
    }

    private List<Path> listDirectory() throws Exception {
        try (var entries = Files.list(storeDir)) {
            return entries.filter(file -> !StoreTestHooks.isLockFile(file)).toList();
        }
    }
}

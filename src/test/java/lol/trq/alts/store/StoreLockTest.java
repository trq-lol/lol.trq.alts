package lol.trq.alts.store;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import lol.trq.alts.model.AccountType;
import lol.trq.alts.model.AltAccount;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * A store owns its file for as long as it is open. A second owner of the same file is refused when it
 * opens, never discovered later as a file two writers took turns replacing; and once a store is closed
 * it hands the file back intact and writes nothing more.
 */
class StoreLockTest {

    private static final String UUID = "00000000-0000-4000-8000-0000000000e1";
    private static final String OTHER_UUID = "00000000-0000-4000-8000-0000000000e2";

    @TempDir
    Path storeDir;

    private static AltAccount alex() {
        return AltAccount.of(UUID, "Alex", "access", AccountType.MICROSOFT);
    }

    private static AltAccount steve() {
        return AltAccount.of(OTHER_UUID, "Steve", "b", AccountType.OFFLINE);
    }

    private static boolean holds(AccountStore store, String uuid) {
        return store.accounts().stream().anyMatch(account -> uuid.equals(account.uuid()));
    }

    /** Opens the directory afresh, as the next owner would, loads it, and closes it again. */
    private AccountStore reopened() {
        AccountStore next = AccountStore.open(storeDir);
        next.load();
        next.close();
        return next;
    }

    @Test
    void aSecondOwnerOfTheSameFileIsRefusedAndTheFirstKeepsWorking() {
        AccountStore first = AccountStore.open(storeDir);
        try {
            first.load();
            first.addAccount(alex());

            IllegalStateException refused =
                    assertThrows(IllegalStateException.class, () -> AccountStore.open(storeDir));
            assertTrue(refused.getMessage().contains("accounts.dat"), "the refusal names the file");
            assertFalse(
                    refused.getMessage().contains(storeDir.toString()), "and never its path: " + refused.getMessage());

            first.addAccount(steve());
            assertTrue(first.saveError().isEmpty(), "the refused second owner must not disturb the first");
        } finally {
            first.close();
        }

        AccountStore next = reopened();
        assertTrue(next.loadError().isEmpty());
        assertTrue(holds(next, UUID) && holds(next, OTHER_UUID), "what the first owner wrote is all there");
    }

    @Test
    void theAccountAndSecretFilesAreLockedApart() {
        AccountStore accounts = AccountStore.open(storeDir);
        HostSecrets secrets = HostSecrets.open(storeDir);
        try {
            assertThrows(IllegalStateException.class, () -> HostSecrets.open(storeDir));
            assertThrows(IllegalStateException.class, () -> AccountStore.open(storeDir));
        } finally {
            secrets.close();
            accounts.close();
        }
    }

    @Test
    void closeIsIdempotentAndHandsTheFileBack() {
        AccountStore store = AccountStore.open(storeDir);
        store.addAccount(alex());

        store.close();
        store.close();

        assertTrue(holds(reopened(), UUID));
    }

    @Test
    void closeWritesWhatIsStillWaiting() {
        AccountStore store = AccountStore.open(storeDir, null, null, null, false, Duration.ofMinutes(10));
        store.addAccount(alex());
        assertFalse(Files.exists(storeDir.resolve("accounts.dat")), "the write is still gathered in memory");

        store.close();

        assertTrue(holds(reopened(), UUID), "closing must not lose a coalesced write");
    }

    @Test
    void closeRemovesTheShutdownFlush() {
        AccountStore store = AccountStore.open(storeDir, null, null, null, false, Duration.ofMinutes(10));
        store.addAccount(alex());
        Thread hook = store.fileForTests().shutdownFlushForTests();
        assertNotNull(hook, "a coalesced write registers the flush that runs at exit");

        store.close();

        assertNull(store.fileForTests().shutdownFlushForTests());
        assertFalse(Runtime.getRuntime().removeShutdownHook(hook), "close() must have deregistered it already");
    }

    @Test
    void theShutdownFlushWritesWhatAHostThatNeverClosedLeftWaiting() throws Exception {
        AccountStore store = AccountStore.open(storeDir, null, null, null, false, Duration.ofMinutes(10));
        try {
            store.addAccount(alex());
            assertFalse(Files.exists(storeDir.resolve("accounts.dat")));

            // What the JVM does at exit for a host that never closed its runtime.
            store.fileForTests().shutdownFlushForTests().run();

            String onDisk = EncryptionUtil.decrypt(
                    Files.readString(storeDir.resolve("accounts.dat")).strip(),
                    EncryptionUtil.getHardwareKey("lol.trq.alts"));
            assertTrue(onDisk.contains(UUID), "the gathered write reached the disk without a close");
        } finally {
            store.close();
        }
    }

    @Test
    void afterCloseTheStoreChangesMemoryOnlyAndSaysSo() throws Exception {
        AccountStore store = AccountStore.open(storeDir);
        store.addAccount(alex());
        byte[] before = Files.readAllBytes(storeDir.resolve("accounts.dat"));
        store.close();

        store.addAccount(steve());
        store.save();
        store.flush();

        assertTrue(holds(store, OTHER_UUID), "the list in memory still follows the mutator");
        assertTrue(store.saveError().isPresent(), "a mutation that will never be written must say so");
        assertArrayEquals(before, Files.readAllBytes(storeDir.resolve("accounts.dat")), "nothing reaches the disk");

        store.load();
        assertTrue(store.loadError().isPresent(), "a closed store reads nothing, and says so");
        assertTrue(holds(store, OTHER_UUID), "and leaves memory as it was");
    }

    @Test
    void closedHostSecretsWriteNothing() throws Exception {
        HostSecrets secrets = HostSecrets.open(storeDir);
        secrets.put("feature.api-key", "value");
        byte[] before = Files.readAllBytes(storeDir.resolve("secrets.dat"));
        secrets.close();
        secrets.close();

        secrets.put("feature.other-key", "other");

        assertEquals("other", secrets.get("feature.other-key"));
        assertTrue(secrets.saveError().isPresent());
        assertArrayEquals(before, Files.readAllBytes(storeDir.resolve("secrets.dat")));
        HostSecrets next = HostSecrets.open(storeDir);
        next.load();
        next.close();
        assertEquals("value", next.get("feature.api-key"));
        assertNull(next.get("feature.other-key"));
    }
}

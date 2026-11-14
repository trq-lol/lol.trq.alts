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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.internal.store.EncryptionUtil;
import lol.trq.alts.internal.store.StoreFileSeams;
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

            AltsException refused = assertThrows(AltsException.class, () -> AccountStore.open(storeDir));
            assertEquals(Kind.CONFLICT, refused.kind(), "another owner holds the file");
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
            assertEquals(
                    Kind.CONFLICT,
                    assertThrows(AltsException.class, () -> HostSecrets.open(storeDir))
                            .kind());
            assertEquals(
                    Kind.CONFLICT,
                    assertThrows(AltsException.class, () -> AccountStore.open(storeDir))
                            .kind());
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
        Thread hook = StoreFileSeams.shutdownFlush(store.fileForTests());
        assertNotNull(hook, "a coalesced write registers the flush that runs at exit");

        store.close();

        assertNull(StoreFileSeams.shutdownFlush(store.fileForTests()));
        assertFalse(Runtime.getRuntime().removeShutdownHook(hook), "close() must have deregistered it already");
    }

    @Test
    void theShutdownFlushWritesWhatAHostThatNeverClosedLeftWaiting() throws Exception {
        AccountStore store = AccountStore.open(storeDir, null, null, null, false, Duration.ofMinutes(10));
        try {
            store.addAccount(alex());
            assertFalse(Files.exists(storeDir.resolve("accounts.dat")));

            // What the JVM does at exit for a host that never closed its runtime.
            StoreFileSeams.shutdownFlush(store.fileForTests()).run();

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

    /**
     * The lock is what keeps a second owner from reading the file before the first has finished writing
     * it. Released before the final write, a next owner could open and load the file between the two
     * and see a store without the last change, or have that change land over what it then writes.
     */
    @Test
    void theLockIsHeldThroughTheFinalWriteOfClose() throws Exception {
        AccountStore first = AccountStore.open(storeDir, null, null, null, false, Duration.ofHours(1));
        first.load();
        first.addAccount(alex());
        CountDownLatch writing = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        StoreFileSeams.beforeWrite(first.fileForTests(), () -> {
            writing.countDown();
            try {
                release.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
        });

        Thread closing = Thread.ofPlatform().start(first::close);
        try {
            assertTrue(writing.await(10, TimeUnit.SECONDS), "close() reached its final write");
            assertEquals(
                    Kind.CONFLICT,
                    assertThrows(
                                    AltsException.class,
                                    () -> AccountStore.open(storeDir),
                                    "no one else may open the file while its last change is still being written")
                            .kind());
        } finally {
            release.countDown();
            closing.join(TimeUnit.SECONDS.toMillis(10));
        }

        assertFalse(closing.isAlive(), "close() returned");
        assertTrue(holds(reopened(), UUID), "and the next owner reads the change close() wrote");
    }
}

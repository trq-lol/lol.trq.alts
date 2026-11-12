package lol.trq.alts.store;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import lol.trq.alts.model.AccountType;
import lol.trq.alts.model.AltAccount;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The store file is the only copy of every credential the user saved, so a write has to be all or
 * nothing, writers have to take turns, and a write that did not happen has to say so.
 */
class AltStorePersistenceTest {

    private static final String FILE_NAME = "accounts.dat";
    private static final String UUID = "00000000-0000-4000-8000-0000000000a1";

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
    void settle() {
        AltStore.flush();
        AltStore.writeDelay(null);
    }

    private Path storeFile() {
        return storeDir.resolve(FILE_NAME);
    }

    private static String uuid(int n) {
        return String.format("00000000-0000-4000-8000-%012d", n);
    }

    private static AltAccount account(int n) {
        return AltAccount.of(uuid(n), "Player" + n, "access-" + n, AccountType.MICROSOFT);
    }

    private static void reload() {
        AltStore.accounts().clear();
        AltStore.load();
    }

    /** Runs {@code work} on {@code threads} threads released together, and rethrows what any of them threw. */
    private static void concurrently(int threads, IndexedWork work) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            CountDownLatch start = new CountDownLatch(1);
            List<Future<?>> running = new ArrayList<>();
            for (int t = 0; t < threads; t++) {
                int thread = t;
                running.add(pool.submit(() -> {
                    start.await();
                    work.run(thread);
                    return null;
                }));
            }
            start.countDown();
            for (Future<?> future : running) {
                future.get(60, TimeUnit.SECONDS);
            }
        } finally {
            pool.shutdownNow();
        }
    }

    @FunctionalInterface
    private interface IndexedWork {
        void run(int thread) throws Exception;
    }

    @Test
    void concurrentMutationsAndSavesLeaveAFileHoldingEveryAccount() throws Exception {
        int threads = 8;
        int perThread = 25;

        concurrently(threads, thread -> {
            for (int i = 0; i < perThread; i++) {
                AltAccount added = account(thread * perThread + i);
                AltStore.addAccount(added);
                AltStore.updateCredentials(added.withTokens("rotated", "refresh-" + added.uuid(), 9_000L));
                AltStore.save();
            }
        });
        reload();

        assertTrue(AltStore.loadError().isEmpty(), "the file must still decrypt after overlapping saves");
        assertTrue(AltStore.saveError().isEmpty());
        assertEquals(threads * perThread, AltStore.accounts().size(), "no account may be lost to a race");
        Set<String> uuids = new HashSet<>();
        for (AltAccount stored : AltStore.accounts()) {
            uuids.add(stored.uuid());
            assertEquals("refresh-" + stored.uuid(), stored.refreshToken(), "the last write must be the newest state");
        }
        assertEquals(threads * perThread, uuids.size(), "no account may be stored twice");
        assertFalse(Files.exists(storeDir.resolve(FILE_NAME + ".tmp")), "no staging file may be left behind");
    }

    @Test
    void concurrentMutationsUnderCoalescedWritesAllReachTheFile() throws Exception {
        AltStore.writeDelay(Duration.ofMillis(5));
        int threads = 4;
        int perThread = 50;

        concurrently(threads, thread -> {
            for (int i = 0; i < perThread; i++) {
                AltStore.addAccount(account(thread * perThread + i));
            }
        });
        AltStore.flush();
        reload();

        assertTrue(AltStore.loadError().isEmpty());
        assertEquals(threads * perThread, AltStore.accounts().size());
    }

    @Test
    void concurrentAddsOfOneAccountStoreItOnce() throws Exception {
        concurrently(8, thread -> {
            for (int i = 0; i < 20; i++) {
                AltStore.addAccount(AltAccount.of(UUID, "Alex", "access-" + thread + "-" + i, AccountType.MICROSOFT));
            }
        });

        assertEquals(1, AltStore.accounts().size(), "an add is a merge onto the stored entry, never a second one");
    }

    @Test
    void reAddingAnAccountKeepsItsPosition() {
        AltStore.addAccount(account(1));
        AltStore.addAccount(account(2));

        AltStore.addAccount(AltAccount.of(uuid(1), "Player1", "fresh", AccountType.MICROSOFT));

        assertEquals(uuid(1), AltStore.accounts().get(0).uuid(), "the entry is replaced where it stands");
        assertEquals("fresh", AltStore.accounts().get(0).accessToken());
    }

    @Test
    void aFailedSaveIsReportedWithoutAPathAndClearedByTheNextSuccess() throws Exception {
        // A regular file where the store directory should be: the directory cannot be created.
        Path blocker = Files.writeString(storeDir.resolve("blocker"), "not a directory");
        AtomicReference<Path> directory = new AtomicReference<>(blocker.resolve("store"));
        AltStore.bind(directory::get);

        AltStore.addAccount(account(1));

        String error = AltStore.saveError().orElseThrow(() -> new AssertionError("a failed save must be reported"));
        assertTrue(error.startsWith(FILE_NAME + ":"), "the failure names the file: " + error);
        assertFalse(error.contains(storeDir.toString()), "the failure must not carry a filesystem path: " + error);
        assertEquals(1, AltStore.accounts().size(), "a failed save must not undo the mutation in memory");

        directory.set(storeDir);
        AltStore.flush();

        assertTrue(AltStore.saveError().isEmpty(), "a save that works must retract the earlier failure");
        reload();
        assertEquals(1, AltStore.accounts().size(), "the state that failed to save is what the retry wrote");
    }

    @Test
    void anUnreadableFileIsReportedWithoutAPath() throws Exception {
        Files.writeString(storeFile(), "not an encrypted store");

        AltStore.load();

        String error = AltStore.loadError().orElseThrow();
        assertTrue(error.startsWith(FILE_NAME + ":"), "the failure names the file: " + error);
        assertFalse(error.contains(storeDir.toString()), "the failure must not carry a filesystem path: " + error);
    }

    @Test
    void anIoFailureOnLoadIsReportedWithoutAPath() throws Exception {
        // A directory where the file should be fails in the JDK with a message that is the absolute path.
        Files.createDirectory(storeFile());

        AltStore.load();

        String error = AltStore.loadError().orElseThrow();
        assertFalse(error.contains(storeDir.toString()), "the failure must not carry a filesystem path: " + error);
        assertFalse(error.contains(storeDir.getFileName().toString()), "nor any part of one: " + error);
    }

    @Test
    void aSaveKeepsTheFileItReplacedAsABackup() throws Exception {
        AltStore.addAccount(account(1));
        byte[] first = Files.readAllBytes(storeFile());

        AltStore.addAccount(account(2));

        assertArrayEquals(
                first,
                Files.readAllBytes(storeDir.resolve(FILE_NAME + ".bak")),
                "the previous good file must survive the write that replaced it");
        assertFalse(Arrays.equals(first, Files.readAllBytes(storeFile())));
    }

    @Test
    void anUnreadableFileIsNeverRotatedOverTheBackup() throws Exception {
        AltStore.addAccount(account(1));
        AltStore.addAccount(account(2));
        byte[] backup = Files.readAllBytes(storeDir.resolve(FILE_NAME + ".bak"));

        Files.writeString(storeFile(), "damaged");
        AltStore.load();
        AltStore.save();

        assertArrayEquals(
                backup,
                Files.readAllBytes(storeDir.resolve(FILE_NAME + ".bak")),
                "the backup holds the last good file, and a damaged one must not replace it");
    }

    @Test
    void repeatedSavesReuseOneDerivedKeyWithAFreshNonceEachTime() throws Exception {
        AltStore.addAccount(account(1));
        byte[] first = Base64.getDecoder().decode(Files.readString(storeFile()));
        AltStore.save();
        byte[] second = Base64.getDecoder().decode(Files.readString(storeFile()));

        assertArrayEquals(
                Arrays.copyOfRange(first, 0, 16),
                Arrays.copyOfRange(second, 0, 16),
                "the salt, and so the derived key, is reused for the life of the process");
        assertFalse(
                Arrays.equals(Arrays.copyOfRange(first, 16, 28), Arrays.copyOfRange(second, 16, 28)),
                "a reused key is only sound with a nonce that never repeats");
        assertNotEquals(Arrays.toString(first), Arrays.toString(second));
    }

    @Test
    void theStoreFileIsReadableByItsOwnerOnly() throws Exception {
        assumeTrue(storeDir.getFileSystem().supportedFileAttributeViews().contains("posix"));

        AltStore.addAccount(account(1));
        AltStore.addAccount(account(2));

        assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(storeFile())));
        assertEquals(
                "rw-------",
                PosixFilePermissions.toString(Files.getPosixFilePermissions(storeDir.resolve(FILE_NAME + ".bak"))));
    }

    @Test
    void aFileWrittenByTheFreshSaltPerSaveSchemeStillLoads() throws Exception {
        // What every release up to 0.11.x wrote: a fresh salt and one PBKDF2 derivation per save.
        String json = "{\"accounts\":[{\"uuid\":\"" + UUID + "\",\"username\":\"Alex\",\"accessToken\":\"legacy\","
                + "\"type\":\"MICROSOFT\",\"lastUsed\":1,\"refreshToken\":\"legacy-refresh\",\"expiresAt\":5}]}";
        Files.writeString(storeFile(), EncryptionUtil.encrypt(json, EncryptionUtil.getHardwareKey("lol.trq.alts")));

        AltStore.load();

        assertTrue(AltStore.loadError().isEmpty(), "an existing file must keep loading");
        assertEquals(1, AltStore.accounts().size());
        assertEquals("legacy-refresh", AltStore.accounts().get(0).refreshToken());
    }

    @Test
    void invalidEntriesAreSkippedWithoutLosingTheValidOnes() throws Exception {
        String json = "{\"accounts\":["
                + "{\"username\":\"NoUuid\",\"accessToken\":\"a\",\"type\":\"MICROSOFT\"},"
                + "null,"
                + "{\"uuid\":\"" + uuid(1) + "\",\"username\":\"Kept\",\"accessToken\":\"old\",\"type\":\"OFFLINE\"},"
                + "{\"uuid\":\"  \",\"username\":\"Blank\",\"accessToken\":\"b\",\"type\":\"OFFLINE\"},"
                + "{\"uuid\":\"" + uuid(1) + "\",\"username\":\"Kept\",\"accessToken\":\"new\",\"type\":\"OFFLINE\"},"
                + "{\"uuid\":\"" + uuid(2) + "\",\"username\":\"Other\",\"accessToken\":\"c\",\"type\":\"OFFLINE\"}"
                + "]}";
        Files.writeString(storeFile(), EncryptionUtil.encrypt(json, EncryptionUtil.getHardwareKey("lol.trq.alts")));

        AltStore.load();

        assertTrue(AltStore.loadError().isEmpty(), "a store with some bad entries still loaded");
        assertEquals(2, AltStore.accounts().size(), "the valid entries must survive the invalid ones");
        assertEquals("new", AltStore.accounts().get(0).accessToken(), "of two entries for one UUID the later wins");
        String warning = AltStore.loadWarning().orElseThrow(() -> new AssertionError("skipped entries must be noted"));
        assertTrue(warning.contains("4"), "three unusable entries and one duplicate were skipped: " + warning);

        // Every mutator keys on the UUID; none may throw over what the file held.
        AltStore.markBanned(uuid(2), "example.net", null);
        AltStore.clearRefreshToken(uuid(2));
        AltStore.removeAccount(account(2));
        assertEquals(1, AltStore.accounts().size());

        AltStore.load();
        assertTrue(AltStore.loadWarning().isEmpty(), "a clean load retracts the note");
    }

    @Test
    void usingAnAccountPersistsItsLastUsedTime() {
        AltAccount stored =
                new AltAccount(UUID, "Alex", "access", AccountType.MICROSOFT, 1L, null, null, null, null, null, 0L);
        AltStore.addAccount(stored);

        AltStore.useAccount(stored);
        reload();

        assertTrue(AltStore.accounts().get(0).lastUsed() > 1L, "the stamp must reach the disk, not just memory");
    }

    @Test
    void usingAStaleCopyDoesNotWriteItsCredentialsBack() {
        AltAccount stale = AltAccount.of(UUID, "Alex", "old-access", AccountType.MICROSOFT)
                .withTokens("old-access", "old-refresh", 1_000L);
        AltStore.addAccount(stale);
        AltStore.updateCredentials(stale.withTokens("new-access", "new-refresh", 2_000L));

        AltStore.useAccount(stale);
        reload();

        assertEquals(
                "new-refresh",
                AltStore.accounts().get(0).refreshToken(),
                "a rotated refresh token must not be replaced by the spent one a caller still holds");
    }

    @Test
    void coalescedWritesWaitForTheFlush() {
        AltStore.writeDelay(Duration.ofMinutes(10));

        AltStore.addAccount(account(1));
        AltStore.addAccount(account(2));
        assertFalse(Files.exists(storeFile()), "with a write delay a mutator returns before the file is written");

        AltStore.flush();
        assertTrue(Files.exists(storeFile()), "flush writes what is waiting before it returns");
        reload();
        assertEquals(2, AltStore.accounts().size());
    }

    @Test
    void coalescedWritesReachTheDiskWithoutAFlush() throws Exception {
        AltStore.writeDelay(Duration.ofMillis(10));

        AltStore.addAccount(account(1));

        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20);
        while (!Files.exists(storeFile()) && System.nanoTime() < deadline) {
            Thread.sleep(5);
        }
        assertTrue(Files.exists(storeFile()), "the background writer must not depend on the host calling flush");
    }

    @Test
    void aLoadSeesStateStillWaitingToBeWritten() {
        AltStore.writeDelay(Duration.ofMinutes(10));
        AltStore.addAccount(account(1));

        reload();

        assertEquals(1, AltStore.accounts().size(), "a load must not read a file older than what memory held");
    }

    @Test
    void theFileOnDiskIsNeverPlaintext() throws Exception {
        AltStore.addAccount(account(1));

        String onDisk = new String(Files.readAllBytes(storeFile()), StandardCharsets.ISO_8859_1);
        assertFalse(onDisk.contains("access-1"));
    }
}

package lol.trq.alts.store;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import lol.trq.alts.AltsFailure;
import lol.trq.alts.AltsFailure.Kind;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The host secrets persist by the same rules as the account store. */
class HostSecretsPersistenceTest {

    private static final String FILE_NAME = "secrets.dat";

    @TempDir
    Path storeDir;

    private HostSecrets secrets;

    @BeforeEach
    void openStore() {
        secrets = HostSecrets.open(storeDir);
        secrets.load();
    }

    @AfterEach
    void closeStore() {
        secrets.close();
    }

    private Path storeFile() {
        return storeDir.resolve(FILE_NAME);
    }

    @Test
    void aSecretSurvivesAReload() {
        secrets.put("feature.api-key", "value");

        secrets.load();

        assertTrue(secrets.loadError().isEmpty());
        assertEquals("value", secrets.get("feature.api-key"));
    }

    @Test
    void concurrentPutsAllReachTheFile() throws Exception {
        List<Thread> threads = new ArrayList<>();
        for (int t = 0; t < 4; t++) {
            int thread = t;
            threads.add(new Thread(() -> {
                for (int i = 0; i < 50; i++) {
                    secrets.put("key-" + (thread * 50 + i), "value-" + (thread * 50 + i));
                }
            }));
        }
        threads.forEach(Thread::start);
        for (Thread thread : threads) {
            thread.join();
        }

        secrets.load();

        assertTrue(secrets.loadError().isEmpty(), "the file must still decrypt after overlapping saves");
        for (int i = 0; i < 200; i++) {
            assertEquals("value-" + i, secrets.get("key-" + i));
        }
    }

    @Test
    void aFailedSaveIsReportedWithoutAPathAndRetried() throws Exception {
        // A non-empty directory where the staging file has to go: the write cannot be staged.
        Path blocker = Files.createDirectory(storeDir.resolve(FILE_NAME + ".tmp"));
        Path inside = Files.writeString(blocker.resolve("inside"), "in the way");

        secrets.put("feature.api-key", "value");

        AltsFailure errorFailure =
                secrets.saveError().orElseThrow(() -> new AssertionError("a failed save must be reported"));
        assertEquals(Kind.STORAGE, errorFailure.kind());
        String error = errorFailure.message();
        assertFalse(error.contains(storeDir.toString()), "the failure must not carry a filesystem path: " + error);

        Files.delete(inside);
        Files.delete(blocker);
        secrets.flush();

        assertTrue(secrets.saveError().isEmpty());
        assertTrue(Files.exists(storeFile()));
    }

    @Test
    void anUnreadableFileIsReportedWithoutAPathAndPreserved() throws Exception {
        byte[] original = "not an encrypted store".getBytes();
        Files.write(storeFile(), original);

        secrets.load();

        AltsFailure errorFailure = secrets.loadError().orElseThrow();
        assertEquals(Kind.STORAGE, errorFailure.kind());
        String error = errorFailure.message();
        assertFalse(error.contains(storeDir.toString()), "the failure must not carry a filesystem path: " + error);

        assertArrayEquals(
                original,
                StoreTestHooks.unreadableCopies(storeDir, FILE_NAME).get(0),
                "the load alone copies the unreadable file aside");

        secrets.put("feature.api-key", "value");
        secrets.save();

        assertTrue(secrets.saveError().isPresent(), "nothing is written over a file that could not be read");
        assertArrayEquals(original, Files.readAllBytes(storeFile()));

        assertTrue(secrets.discardUnreadable(), "until the host gives up on it");
        assertTrue(secrets.saveError().isEmpty());
        secrets.load();
        assertEquals("value", secrets.get("feature.api-key"), "and the next write started a new file");
    }

    @Test
    void coalescedWritesWaitForTheFlush() {
        secrets.close();
        secrets = HostSecrets.open(storeDir, null, null, null, false, Duration.ofMinutes(10));

        secrets.put("feature.api-key", "value");
        assertFalse(Files.exists(storeFile()));

        secrets.flush();
        assertTrue(Files.exists(storeFile()));
    }

    @Test
    void aNullEntryInTheFileDoesNotCostTheOthers() throws Exception {
        String json = "{\"secrets\":{\"feature.api-key\":\"value\",\"key-1\":null}}";
        Files.writeString(
                storeFile(), EncryptionUtil.encrypt(json, EncryptionUtil.getHardwareKey("lol.trq.alts.secrets")));

        secrets.load();

        assertTrue(secrets.loadError().isEmpty());
        assertEquals("value", secrets.get("feature.api-key"));
        assertNull(secrets.get("key-1"));
    }
}

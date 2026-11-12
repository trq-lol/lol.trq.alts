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
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The secret store persists by the same rules as the account store. */
class SecretStorePersistenceTest {

    private static final String FILE_NAME = "secrets.dat";

    @TempDir
    Path storeDir;

    @BeforeEach
    void bindStore() throws Exception {
        SecretStore.bind(() -> storeDir);
        // The map is not exposed, so the way to empty it is to load a store that holds nothing.
        Files.writeString(
                storeFile(),
                EncryptionUtil.encrypt("{\"secrets\":{}}", EncryptionUtil.getHardwareKey("lol.trq.alts.secrets")));
        SecretStore.load();
        Files.delete(storeFile());
    }

    @AfterEach
    void settle() {
        SecretStore.flush();
        SecretStore.writeDelay(null);
    }

    private Path storeFile() {
        return storeDir.resolve(FILE_NAME);
    }

    @Test
    void aSecretSurvivesAReload() {
        SecretStore.put("feature.api-key", "value");

        SecretStore.load();

        assertTrue(SecretStore.loadError().isEmpty());
        assertEquals("value", SecretStore.get("feature.api-key"));
    }

    @Test
    void concurrentPutsAllReachTheFile() throws Exception {
        List<Thread> threads = new ArrayList<>();
        for (int t = 0; t < 4; t++) {
            int thread = t;
            threads.add(new Thread(() -> {
                for (int i = 0; i < 50; i++) {
                    SecretStore.put("key-" + (thread * 50 + i), "value-" + (thread * 50 + i));
                }
            }));
        }
        threads.forEach(Thread::start);
        for (Thread thread : threads) {
            thread.join();
        }

        SecretStore.load();

        assertTrue(SecretStore.loadError().isEmpty(), "the file must still decrypt after overlapping saves");
        for (int i = 0; i < 200; i++) {
            assertEquals("value-" + i, SecretStore.get("key-" + i));
        }
    }

    @Test
    void aFailedSaveIsReportedWithoutAPathAndRetried() throws Exception {
        Path blocker = Files.writeString(storeDir.resolve("blocker"), "not a directory");
        AtomicReference<Path> directory = new AtomicReference<>(blocker.resolve("store"));
        SecretStore.bind(directory::get);

        SecretStore.put("feature.api-key", "value");

        String error = SecretStore.saveError().orElseThrow(() -> new AssertionError("a failed save must be reported"));
        assertFalse(error.contains(storeDir.toString()), "the failure must not carry a filesystem path: " + error);

        directory.set(storeDir);
        SecretStore.flush();

        assertTrue(SecretStore.saveError().isEmpty());
        assertTrue(Files.exists(storeFile()));
    }

    @Test
    void anUnreadableFileIsReportedWithoutAPathAndPreserved() throws Exception {
        byte[] original = "not an encrypted store".getBytes();
        Files.write(storeFile(), original);

        SecretStore.load();

        String error = SecretStore.loadError().orElseThrow();
        assertFalse(error.contains(storeDir.toString()), "the failure must not carry a filesystem path: " + error);

        SecretStore.put("feature.api-key", "value");
        assertArrayEquals(original, Files.readAllBytes(storeDir.resolve(FILE_NAME + ".unreadable")));
    }

    @Test
    void coalescedWritesWaitForTheFlush() {
        SecretStore.writeDelay(Duration.ofMinutes(10));

        SecretStore.put("feature.api-key", "value");
        assertFalse(Files.exists(storeFile()));

        SecretStore.flush();
        assertTrue(Files.exists(storeFile()));
    }

    @Test
    void aNullEntryInTheFileDoesNotCostTheOthers() throws Exception {
        String json = "{\"secrets\":{\"feature.api-key\":\"value\",\"key-1\":null}}";
        Files.writeString(
                storeFile(), EncryptionUtil.encrypt(json, EncryptionUtil.getHardwareKey("lol.trq.alts.secrets")));

        SecretStore.load();

        assertTrue(SecretStore.loadError().isEmpty());
        assertEquals("value", SecretStore.get("feature.api-key"));
        assertNull(SecretStore.get("key-1"));
    }
}

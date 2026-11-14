package lol.trq.alts.store;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import lol.trq.alts.internal.store.EncryptionUtil;
import lol.trq.alts.internal.store.StoreFileSeams;
import lol.trq.alts.model.AccountType;
import lol.trq.alts.model.AltAccount;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * A store file that cannot be read is not an empty store, and the two must never be conflated. The
 * default key is derived from machine properties, so a renamed OS user or a moved home directory turns
 * a perfectly good file unreadable — at which point saving anything at all would write an empty list
 * over every account the user had. So nothing is written over it until a load succeeds or the host
 * explicitly discards it, and it is copied aside the moment the load fails.
 */
class AccountStoreUnreadableFileTest {

    private static final String FILE_NAME = "accounts.dat";
    private static final String UUID = "00000000-0000-4000-8000-00000000000a";
    private static final String OTHER_UUID = "00000000-0000-4000-8000-00000000000b";

    @TempDir
    Path storeDir;

    private AccountStore store;

    @BeforeEach
    void openStore() {
        store = AccountStore.open(storeDir);
    }

    @AfterEach
    void closeStore() {
        store.close();
    }

    private Path storeFile() {
        return storeDir.resolve(FILE_NAME);
    }

    private List<byte[]> keptCopies() throws Exception {
        return StoreTestHooks.unreadableCopies(storeDir, FILE_NAME);
    }

    private boolean kept(byte[] content) throws Exception {
        return keptCopies().stream().anyMatch(copy -> Arrays.equals(copy, content));
    }

    private static AltAccount alex() {
        return AltAccount.of(UUID, "Alex", "access", AccountType.MICROSOFT);
    }

    private static AltAccount steve() {
        return AltAccount.of(OTHER_UUID, "Steve", "b", AccountType.OFFLINE);
    }

    private boolean holds(String uuid) {
        return store.accounts().stream().anyMatch(account -> uuid.equals(account.uuid()));
    }

    private void reload() {
        store.accounts().clear();
        store.load();
    }

    @Test
    void anAbsentFileIsNotAFailure() {
        store.load();

        assertTrue(store.loadError().isEmpty(), "there is nothing wrong with a store that was never written");
    }

    @Test
    void anUnreadableFileReportsTheFailureAndKeepsTheInMemoryList() throws Exception {
        store.accounts().add(alex());
        Files.writeString(storeFile(), "not an encrypted store");

        store.load();

        assertTrue(store.loadError().isPresent(), "an unreadable file must be reported, not swallowed");
        assertEquals(1, store.accounts().size(), "a failed load must not clear what is already held");
    }

    @Test
    void anUnreadableFileIsCopiedAsideByTheLoadAlone() throws Exception {
        byte[] original = "not an encrypted store".getBytes(StandardCharsets.UTF_8);
        Files.write(storeFile(), original);

        store.load();

        assertEquals(1, keptCopies().size(), "the copy is made when the load fails, before anything else");
        assertArrayEquals(original, keptCopies().get(0), "and it is the original bytes");
    }

    @Test
    void nothingIsWrittenOverAnUnreadableFile() throws Exception {
        byte[] original = "not an encrypted store".getBytes(StandardCharsets.UTF_8);
        Files.write(storeFile(), original);
        store.load();

        store.addAccount(alex());
        assertTrue(store.saveError().isPresent(), "a refused write must say so");
        store.save();
        store.flush();
        store.close();

        assertArrayEquals(original, Files.readAllBytes(storeFile()), "mutation, save and close all left it alone");
        assertFalse(Files.exists(storeDir.resolve(FILE_NAME + ".bak")), "nor did any of them rotate it away");
        assertTrue(holds(UUID), "the account lives in memory only");
    }

    @Test
    void writesResumeOnceALoadSucceeds() throws Exception {
        Files.writeString(storeFile(), "not an encrypted store");
        store.load();
        store.addAccount(alex());
        assertTrue(store.saveError().isPresent());

        // The host puts a good file back (a restored copy, say), and loads again.
        Files.writeString(
                storeFile(),
                EncryptionUtil.encrypt("{\"accounts\":[]}", EncryptionUtil.getHardwareKey("lol.trq.alts")));
        byte[] restored = Files.readAllBytes(storeFile());
        store.load();
        store.flush();

        assertArrayEquals(
                restored, Files.readAllBytes(storeFile()), "the load must not write the snapshot it held back");

        assertTrue(store.loadError().isEmpty(), "a load that works must retract the earlier failure");
        assertTrue(store.saveError().isEmpty(), "and with it the refusal");
        store.addAccount(steve());
        assertTrue(store.saveError().isEmpty());
        reload();
        assertTrue(holds(OTHER_UUID), "writes land again");
        assertFalse(holds(UUID), "what was added while refused was replaced by what the load read");
    }

    @Test
    void aSecondFailedLoadKeepsTheRefusal() throws Exception {
        byte[] original = "not an encrypted store".getBytes(StandardCharsets.UTF_8);
        Files.write(storeFile(), original);
        store.load();
        store.load();

        store.addAccount(alex());
        store.save();

        assertTrue(store.saveError().isPresent(), "failing again is no reason to start writing");
        assertArrayEquals(original, Files.readAllBytes(storeFile()));
    }

    @Test
    void aFileThatDecryptsButIsNotAStoreIsNotWrittenOver() throws Exception {
        Files.writeString(
                storeFile(), EncryptionUtil.encrypt("not json at all", EncryptionUtil.getHardwareKey("lol.trq.alts")));
        byte[] original = Files.readAllBytes(storeFile());
        store.load();
        assertTrue(store.loadError().isPresent());

        store.addAccount(alex());
        store.save();
        store.close();

        assertTrue(store.saveError().isPresent());
        assertArrayEquals(original, Files.readAllBytes(storeFile()), "opening is not the same as being a store");
    }

    @Test
    void aDirectoryWhereTheFileShouldBeIsNotReplaced() throws Exception {
        Files.createDirectory(storeFile());
        store.load();
        assertTrue(store.loadError().isPresent());

        store.addAccount(alex());
        store.save();

        assertTrue(store.saveError().isPresent());
        assertTrue(Files.isDirectory(storeFile()), "whatever is there is left as it is");
        // A move over a directory can fail on its own; what must hold is that the failed read refused the
        // writes, which only a refusal has to be discarded to lift.
        assertTrue(store.discardUnreadable(), "the failed read is what refused the writes");
    }

    @Test
    void writesResumeOnceTheFileIsGone() throws Exception {
        Files.writeString(storeFile(), "not an encrypted store");
        store.load();
        store.addAccount(alex());
        Files.delete(storeFile());

        store.load();

        assertTrue(store.saveError().isEmpty(), "with no file left to protect, what was held back is written");
        reload();
        assertTrue(holds(UUID));
    }

    @Test
    void discardingTheUnreadableFileStartsANewStoreAndKeepsTheCopy() throws Exception {
        byte[] original = "not an encrypted store".getBytes(StandardCharsets.UTF_8);
        Files.write(storeFile(), original);
        store.load();
        store.addAccount(alex());

        assertTrue(store.discardUnreadable());

        assertTrue(store.saveError().isEmpty());
        assertTrue(store.loadError().isEmpty(), "the file on disk is now the one just written");
        assertTrue(kept(original), "the discarded file survives as its copy");
        assertEquals(1, keptCopies().size(), "and only once");
        reload();
        assertTrue(holds(UUID), "what memory held is the new store");

        store.addAccount(steve());
        store.save();
        assertEquals(1, keptCopies().size(), "a good file is never copied aside as though unreadable");
        assertFalse(store.discardUnreadable(), "with nothing refused there is nothing to discard");
    }

    @Test
    void noUnreadableFileIsLostAcrossIncidents() throws Exception {
        byte[] first = "the file that held the accounts".getBytes(StandardCharsets.UTF_8);
        Files.write(storeFile(), first);
        store.load();
        store.addAccount(alex());
        store.discardUnreadable();

        // A later run finds the store unreadable again, with different content.
        byte[] second = "another file that held accounts".getBytes(StandardCharsets.UTF_8);
        Files.write(storeFile(), second);
        store.load();

        assertTrue(kept(first), "the copy from the first incident must still be there");
        assertTrue(kept(second), "and the second unreadable file must have been kept too");
    }

    @Test
    void onlyTheNewestUnreadableCopiesAreKept() throws Exception {
        int incidents = StoreFileSeams.MAX_UNREADABLE_KEPT + 3;
        for (int incident = 0; incident < incidents; incident++) {
            Files.writeString(storeFile(), "unreadable store number " + incident);
            store.load();
            // Copies are named by the millisecond; a distinct stamp keeps the order the test relies on.
            Thread.sleep(2);
        }

        assertEquals(
                StoreFileSeams.MAX_UNREADABLE_KEPT, keptCopies().size(), "the copies must not pile up without bound");
        assertTrue(kept(("unreadable store number " + (incidents - 1)).getBytes(StandardCharsets.UTF_8)));
        assertFalse(
                kept("unreadable store number 0".getBytes(StandardCharsets.UTF_8)),
                "it is the oldest copies that make room");
    }

    @Test
    void reloadingTheSameUnreadableFileDoesNotPileUpCopies() throws Exception {
        Files.writeString(storeFile(), "not an encrypted store");

        store.load();
        store.load();
        store.load();

        assertEquals(1, keptCopies().size(), "one copy per distinct file, however often it is read");
    }
}

package lol.trq.alts.store;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import lol.trq.alts.model.AccountType;
import lol.trq.alts.model.AltAccount;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * A store file that cannot be read is not an empty store, and the two must never be conflated. The
 * encryption key is derived from machine properties, so a renamed OS user or a moved home directory
 * turns a perfectly good file unreadable — at which point saving anything at all would write an empty
 * list over every account the user had.
 */
class AccountStoreUnreadableFileTest {

    private static final String FILE_NAME = "accounts.dat";
    private static final String UUID = "00000000-0000-4000-8000-00000000000a";

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
        return keptCopies().stream().anyMatch(copy -> java.util.Arrays.equals(copy, content));
    }

    private static AltAccount alex() {
        return AltAccount.of(UUID, "Alex", "access", AccountType.MICROSOFT);
    }

    @Test
    void anAbsentFileIsNotAFailure() {
        store.load();

        assertTrue(store.loadError().isEmpty(), "there is nothing wrong with a store that was never written");
    }

    @Test
    void aReadableFileClearsAnEarlierFailure() throws Exception {
        Files.writeString(storeFile(), "not an encrypted store");
        store.load();
        assertTrue(store.loadError().isPresent());

        store.accounts().clear();
        store.addAccount(AltAccount.of(UUID, "Alex", "access", AccountType.MICROSOFT));
        store.load();

        assertTrue(store.loadError().isEmpty(), "a load that works must retract the earlier failure");
    }

    @Test
    void anUnreadableFileReportsTheFailureAndKeepsTheInMemoryList() throws Exception {
        store.accounts().add(AltAccount.of(UUID, "Alex", "access", AccountType.MICROSOFT));
        Files.writeString(storeFile(), "not an encrypted store");

        store.load();

        assertTrue(store.loadError().isPresent(), "an unreadable file must be reported, not swallowed");
        assertEquals(1, store.accounts().size(), "a failed load must not clear what is already held");
    }

    @Test
    void savingOverAnUnreadableFileKeepsACopyOfIt() throws Exception {
        byte[] original = "not an encrypted store".getBytes(StandardCharsets.UTF_8);
        Files.write(storeFile(), original);
        store.load();

        store.addAccount(alex());

        assertEquals(1, keptCopies().size(), "the unreadable file must survive the save that replaced it");
        assertArrayEquals(original, keptCopies().get(0), "the copy must be the original bytes");
        assertTrue(Files.size(storeFile()) > 0, "the store itself is rewritten with the current list");
    }

    @Test
    void noUnreadableFileIsLostWhenItIsReplaced() throws Exception {
        byte[] first = "the file that held the accounts".getBytes(StandardCharsets.UTF_8);
        Files.write(storeFile(), first);
        store.load();
        store.addAccount(alex());

        // A later run finds the store unreadable again, with different content, and saves again.
        byte[] second = "another file that held accounts".getBytes(StandardCharsets.UTF_8);
        Files.write(storeFile(), second);
        store.load();
        store.save();

        assertTrue(kept(first), "the copy from the first incident must still be there");
        assertTrue(kept(second), "and the second unreadable file must have been kept too, not skipped");
    }

    @Test
    void aFailureIsNoLongerReportedOnceTheStoreHasBeenRewritten() throws Exception {
        Files.writeString(storeFile(), "not an encrypted store");
        store.load();
        assertTrue(store.loadError().isPresent());

        store.addAccount(alex());

        assertTrue(
                store.loadError().isEmpty(),
                "the file on disk is now a good one; reporting it unreadable for the rest of the run is wrong");

        store.save();
        store.save();

        assertEquals(1, keptCopies().size(), "and the good file must not be copied aside as though unreadable");
    }

    @Test
    void onlyTheNewestUnreadableCopiesAreKept() throws Exception {
        int incidents = StoreFile.MAX_UNREADABLE_KEPT + 3;
        for (int incident = 0; incident < incidents; incident++) {
            Files.writeString(storeFile(), "unreadable store number " + incident);
            store.load();
            store.save();
        }

        assertEquals(StoreFile.MAX_UNREADABLE_KEPT, keptCopies().size(), "the copies must not pile up without bound");
        assertTrue(kept(("unreadable store number " + (incidents - 1)).getBytes(StandardCharsets.UTF_8)));
        assertFalse(
                kept("unreadable store number 0".getBytes(StandardCharsets.UTF_8)),
                "it is the oldest copies that make room");
    }
}

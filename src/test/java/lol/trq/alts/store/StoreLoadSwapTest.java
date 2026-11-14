package lol.trq.alts.store;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import lol.trq.alts.model.AccountType;
import lol.trq.alts.model.AltAccount;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * A load replaces what memory holds with what the file holds, in one step. A host reads the store from
 * its render thread while a load runs on another, and must never see an empty list, or a missing
 * secret, that the file does not hold. And a file that holds nothing replaces what memory held, rather
 * than being read as "nothing to change".
 */
@org.junit.jupiter.api.Timeout(value = 120, unit = TimeUnit.SECONDS)
class StoreLoadSwapTest {

    private static final int ACCOUNTS = 3;
    private static final int LOADS = 200;

    @TempDir
    Path dir;

    private static AltAccount account(int index) {
        return AltAccount.of("00000000-0000-4000-8000-00000000000" + index, "Alt" + index, "t", AccountType.MICROSOFT);
    }

    @Test
    void aReaderNeverSeesTheAccountsMissingWhileTheyAreLoaded() throws Exception {
        AccountStore store = AccountStore.open(dir);
        try {
            store.load();
            for (int i = 0; i < ACCOUNTS; i++) {
                store.addAccount(account(i));
            }
            AtomicBoolean loading = new AtomicBoolean(true);
            AtomicInteger wrongViews = new AtomicInteger();
            Thread reader = Thread.ofPlatform().start(() -> {
                while (loading.get()) {
                    if (store.accounts().size() != ACCOUNTS) {
                        wrongViews.incrementAndGet();
                    }
                }
            });

            for (int i = 0; i < LOADS; i++) {
                store.load();
            }
            loading.set(false);
            reader.join();

            assertEquals(0, wrongViews.get(), "a reader saw a list the file does not hold");
            assertEquals(ACCOUNTS, store.accounts().size());
        } finally {
            store.close();
        }
    }

    @Test
    void aReaderNeverSeesASecretMissingWhileTheSecretsAreLoaded() throws Exception {
        HostSecrets secrets = HostSecrets.open(dir);
        try {
            secrets.load();
            secrets.put("feature.api-key", "value");
            AtomicBoolean loading = new AtomicBoolean(true);
            AtomicInteger missing = new AtomicInteger();
            Thread reader = Thread.ofPlatform().start(() -> {
                while (loading.get()) {
                    if (secrets.get("feature.api-key") == null) {
                        missing.incrementAndGet();
                    }
                }
            });

            for (int i = 0; i < LOADS; i++) {
                secrets.load();
            }
            loading.set(false);
            reader.join();

            assertEquals(0, missing.get(), "a reader saw a secret missing that the file holds");
        } finally {
            secrets.close();
        }
    }

    @Test
    void aStoreFileHoldingNothingReplacesWhatMemoryHeld() {
        AccountStore store = AccountStore.open(dir);
        try {
            store.load();
            store.addAccount(account(1));
            // A sealed file whose plaintext is empty: written, then read back as a store of nothing.
            store.fileForTests().submit(() -> "");
            store.fileForTests().flush();

            store.load();

            assertTrue(store.loadError().isEmpty(), "an empty store is a store, not an unreadable file");
            assertTrue(store.accounts().isEmpty(), "what memory held is replaced by what the file holds");
        } finally {
            store.close();
        }
    }

    @Test
    void aSecretFileHoldingNothingReplacesWhatMemoryHeld() {
        HostSecrets secrets = HostSecrets.open(dir);
        try {
            secrets.load();
            secrets.put("feature.api-key", "value");
            secrets.fileForTests().submit(() -> "");
            secrets.fileForTests().flush();

            secrets.load();

            assertTrue(secrets.loadError().isEmpty());
            assertNull(secrets.get("feature.api-key"));
        } finally {
            secrets.close();
        }
    }
}

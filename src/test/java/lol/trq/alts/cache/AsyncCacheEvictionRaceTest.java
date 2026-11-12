package lol.trq.alts.cache;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

/**
 * A cache is read from many threads at once, and reading is what orders its entries for eviction. That
 * ordering changing underneath an eviction must never surface as a failure of the read that triggered
 * it, and must never leave the key that read asked for waiting on a fetch nobody started.
 */
class AsyncCacheEvictionRaceTest {

    private static final int BOUND = 512;
    private static final int NEW_KEYS = 400;

    @Test
    void readsRacingAnEvictionNeverFailAndNeverStrandAKey() throws Exception {
        AtomicLong clock = new AtomicLong();
        AsyncCache<Integer, String> cache = new AsyncCache<>(key -> "value-" + key, 0L, BOUND, clock::incrementAndGet);
        for (int key = 0; key < BOUND; key++) {
            cache.get(key);
        }

        AtomicBoolean running = new AtomicBoolean(true);
        AtomicReference<Throwable> readerFailure = new AtomicReference<>();
        List<Thread> readers = new ArrayList<>();
        for (int reader = 0; reader < 4; reader++) {
            int offset = reader * 131;
            Thread thread = new Thread(() -> {
                try {
                    for (int i = offset; running.get(); i++) {
                        // Every read restamps an entry, which is what reorders them mid-eviction.
                        cache.get(Math.floorMod(i * 7919, BOUND));
                    }
                } catch (Throwable failure) {
                    readerFailure.compareAndSet(null, failure);
                }
            });
            thread.setDaemon(true);
            thread.start();
            readers.add(thread);
        }

        Throwable insertFailure = null;
        try {
            for (int key = BOUND; key < BOUND + NEW_KEYS; key++) {
                cache.get(key);
            }
        } catch (Throwable failure) {
            insertFailure = failure;
        } finally {
            running.set(false);
            for (Thread thread : readers) {
                thread.join(5_000);
            }
        }

        assertNull(insertFailure, "a read that triggers an eviction must not fail because of it");
        assertNull(readerFailure.get(), "nor may any other read");

        // Whatever was evicted along the way, asking again must always end in a value: a key left
        // marked as loading with no fetch behind it would answer null for good.
        for (int key = BOUND; key < BOUND + NEW_KEYS; key++) {
            assertEquals("value-" + key, await(cache, key), "key " + key + " never resolved");
        }
    }

    private static String await(AsyncCache<Integer, String> cache, int key) throws InterruptedException {
        for (int attempt = 0; attempt < 400; attempt++) {
            String value = cache.get(key);
            if (value != null) {
                return value;
            }
            Thread.sleep(5);
        }
        return null;
    }
}

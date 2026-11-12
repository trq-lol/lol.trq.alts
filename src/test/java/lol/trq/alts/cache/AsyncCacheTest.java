package lol.trq.alts.cache;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

class AsyncCacheTest {

    @Test
    void missReturnsNullThenFills() throws Exception {
        AsyncCache<String, String> cache = new AsyncCache<>(key -> "value:" + key);

        assertNull(cache.get("a"), "first get is a miss and must not block");
        assertEquals("value:a", awaitValue(cache, "a"));
    }

    @Test
    void nullLoaderMarksKeyFailed() throws Exception {
        AsyncCache<String, String> cache = new AsyncCache<>(key -> null);

        assertNull(cache.get("a"));
        Thread.sleep(100);
        assertNull(cache.get("a"), "a null fetch stays failed until its backoff elapses");
    }

    @Test
    void concurrentGetsTriggerOneFetchPerKey() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        AsyncCache<String, String> cache = new AsyncCache<>(key -> {
            calls.incrementAndGet();
            sleepQuietly(50);
            return "v";
        });

        cache.get("a");
        cache.get("a");
        cache.get("a");

        assertEquals("v", awaitValue(cache, "a"));
        assertEquals(1, calls.get(), "PENDING dedup must collapse concurrent gets into one fetch");
    }

    @Test
    void invalidateForcesRefetch() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        AsyncCache<String, String> cache = new AsyncCache<>(key -> "v" + calls.incrementAndGet());

        assertEquals("v1", awaitValue(cache, "a"));
        cache.invalidate("a");
        assertEquals("v2", awaitValue(cache, "a"));
    }

    /** A failed first fetch is retried once its backoff elapses, not abandoned until invalidate(). */
    @Test
    void aFailedKeyIsRetriedAfterItsBackoff() throws Exception {
        AtomicLong clock = new AtomicLong(1_000_000L);
        AtomicInteger calls = new AtomicInteger();
        AsyncCache<String, String> cache =
                new AsyncCache<>(key -> calls.incrementAndGet() == 1 ? null : "recovered", 0L, 16, clock::get);

        assertNull(cache.get("a"));
        awaitCalls(calls, 1);
        Thread.sleep(50);
        assertNull(cache.get("a"), "inside the backoff nothing is refetched");
        Thread.sleep(50);
        assertEquals(1, calls.get(), "a failed key is not hammered");

        clock.addAndGet(5_001L);
        assertEquals("recovered", awaitValue(cache, "a"));
        assertEquals(2, calls.get());
    }

    /** The regression this guards: a refresh that failed used to replace a good value with nothing. */
    @Test
    void aFailedRefreshKeepsTheStaleValue() throws Exception {
        AtomicLong clock = new AtomicLong(1_000_000L);
        AtomicInteger calls = new AtomicInteger();
        AtomicBoolean healthy = new AtomicBoolean(true);
        AsyncCache<String, String> cache = new AsyncCache<>(
                key -> {
                    int call = calls.incrementAndGet();
                    if (!healthy.get()) {
                        throw new IllegalStateException("service down");
                    }
                    return "v" + call;
                },
                1_000L,
                16,
                clock::get);

        assertEquals("v1", awaitValue(cache, "a"));

        healthy.set(false);
        clock.addAndGet(2_000L);
        assertEquals("v1", cache.get("a"), "the stale value is served while the refresh runs");
        awaitCalls(calls, 2);
        Thread.sleep(50);
        assertEquals("v1", cache.get("a"), "and still served once the refresh has failed");
        Thread.sleep(50);
        assertEquals(2, calls.get(), "the failed refresh waits out its backoff before the next attempt");

        healthy.set(true);
        clock.addAndGet(5_001L);
        assertEquals("v1", cache.get("a"), "the retry is kicked off without blanking the entry");
        awaitCalls(calls, 3);
        for (int i = 0; i < 200 && !"v3".equals(cache.get("a")); i++) {
            Thread.sleep(10);
        }
        assertEquals("v3", cache.get("a"), "a later refresh that succeeds replaces the stale value");
    }

    @Test
    void theCacheIsBoundedAndDropsTheLeastRecentlyRead() throws Exception {
        AtomicLong clock = new AtomicLong(1_000_000L);
        AtomicInteger calls = new AtomicInteger();
        AsyncCache<String, String> cache = new AsyncCache<>(
                key -> {
                    calls.incrementAndGet();
                    return "value:" + key;
                },
                0L,
                2,
                clock::get);

        assertEquals("value:a", awaitValue(cache, "a"));
        clock.addAndGet(10L);
        assertEquals("value:b", awaitValue(cache, "b"));
        clock.addAndGet(10L);
        assertEquals("value:a", cache.get("a"), "reading a makes b the least recently read");
        clock.addAndGet(10L);

        assertEquals("value:c", awaitValue(cache, "c"));

        assertEquals(2, cache.size(), "the bound holds");
        assertEquals(3, calls.get());
        assertEquals("value:a", cache.get("a"), "the recently read entry survived");
        assertEquals(3, calls.get(), "and was served without a refetch");
        assertNull(cache.get("b"), "the least recently read entry was dropped");
    }

    private static void awaitCalls(AtomicInteger calls, int expected) throws InterruptedException {
        for (int i = 0; i < 200 && calls.get() < expected; i++) {
            Thread.sleep(10);
        }
        assertEquals(expected, calls.get());
    }

    private static String awaitValue(AsyncCache<String, String> cache, String key) throws InterruptedException {
        for (int i = 0; i < 200; i++) {
            String value = cache.get(key);
            if (value != null) {
                return value;
            }
            Thread.sleep(10);
        }
        throw new AssertionError("cache never filled key " + key);
    }

    private static void sleepQuietly(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        }
    }
}

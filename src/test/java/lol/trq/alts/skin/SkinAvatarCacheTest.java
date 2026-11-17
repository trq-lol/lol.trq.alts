package lol.trq.alts.skin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import lol.trq.alts.spi.AvatarSource;
import org.junit.jupiter.api.Test;

/**
 * The avatar cache keys on UUID and treats a failure as temporary. Keying on username meant a rename
 * broke the head for good; caching a failure permanently meant one network blip did the same. Both are
 * regressions this guards.
 */
class SkinAvatarCacheTest {

    private static final Executor IO =
            lol.trq.alts.TestExecutors.perTask(Thread.ofVirtual().factory());

    private static final byte[] PNG = {1, 2, 3, 4};

    /** Waits for the cache to fill for a key, since the fetch resolves on a background thread. */
    private static <H> H await(SkinAvatarCache<H> cache, String key) throws InterruptedException {
        for (int i = 0; i < 200; i++) {
            H handle = cache.get(key);
            if (handle != null) {
                return handle;
            }
            Thread.sleep(5);
        }
        throw new AssertionError("avatar never filled for " + key);
    }

    @Test
    void fetchesThroughTheSourceAndUploads() throws Exception {
        AtomicInteger fetches = new AtomicInteger();
        AvatarSource source = (uuid, size) -> {
            fetches.incrementAndGet();
            return PNG;
        };
        SkinAvatarCache<String> cache = new SkinAvatarCache<>(source, bytes -> "handle", Runnable::run, IO);

        assertEquals("handle", await(cache, "uuid-1"));
        // A filled entry is served from memory, not refetched.
        cache.get("uuid-1");
        assertEquals(1, fetches.get(), "a ready avatar is not fetched twice");
    }

    @Test
    void nullUploaderMeansTheCacheStaysEmpty() {
        SkinAvatarCache<String> cache = new SkinAvatarCache<>((uuid, size) -> PNG, null, Runnable::run, IO);

        assertNull(cache.get("uuid-1"), "with no uploader there is nowhere to put a handle");
    }

    /**
     * A failed fetch is retried once its backoff elapses, rather than caching the failure forever. The
     * old sentinel turned a single blip into a permanently broken head.
     */
    @Test
    void aFailureIsRetriedAfterItsBackoff() throws Exception {
        AtomicInteger fetches = new AtomicInteger();
        AtomicLong now = new AtomicLong(0);
        // Fails the first call, succeeds the second.
        AvatarSource source = (uuid, size) -> fetches.incrementAndGet() == 1 ? null : PNG;
        SkinAvatarCache<String> cache = new SkinAvatarCache<>(source, bytes -> "handle", Runnable::run, IO, now::get);

        // First get triggers the failing fetch.
        assertNull(cache.get("uuid-1"));
        Thread.sleep(30);
        assertNull(cache.get("uuid-1"), "still failed, and inside the backoff window");
        assertEquals(1, fetches.get(), "a failure inside its backoff is not retried");

        // Advance past the backoff; the next get re-arms the fetch, which now succeeds.
        now.addAndGet(10_000);
        assertEquals("handle", await(cache, "uuid-1"));
        assertTrue(fetches.get() >= 2, "the elapsed backoff must allow a retry");
    }

    @Test
    void keysAreCaseInsensitiveOnTheUuid() throws Exception {
        AtomicInteger fetches = new AtomicInteger();
        AvatarSource source = (uuid, size) -> {
            fetches.incrementAndGet();
            return PNG;
        };
        SkinAvatarCache<String> cache = new SkinAvatarCache<>(source, bytes -> "handle", Runnable::run, IO);

        assertNotNull(await(cache, "ABCDEF"));
        cache.get("abcdef");
        assertEquals(1, fetches.get(), "the same UUID in another case is the same entry");
    }

    /**
     * After a skin change the host invalidates the entry; the next get must fetch again and serve the
     * new head, and the old handle is handed back so the host can free it.
     */
    @Test
    void invalidateRefetchesAndReturnsTheOldHandle() throws Exception {
        AtomicInteger uploads = new AtomicInteger();
        SkinAvatarCache<String> cache = new SkinAvatarCache<>(
                (uuid, size) -> PNG, bytes -> "head-" + uploads.incrementAndGet(), Runnable::run, IO);

        assertEquals("head-1", await(cache, "uuid-1"));
        assertEquals("head-1", cache.invalidate("UUID-1"), "invalidate hands back the handle it dropped");
        assertEquals("head-2", await(cache, "uuid-1"), "the next get fetches the new head");
    }

    @Test
    void invalidateOfAnUnknownOrBlankKeyReturnsNull() {
        SkinAvatarCache<String> cache = new SkinAvatarCache<>((uuid, size) -> PNG, bytes -> "h", Runnable::run, IO);

        assertNull(cache.invalidate("never-requested"));
        assertNull(cache.invalidate(" "));
        assertNull(cache.invalidate(null));
    }

    /**
     * A fetch that was in flight when the entry was invalidated may carry the old skin. Its result must
     * be dropped, not stored over the fresh fetch the invalidation allows.
     */
    @Test
    void aFetchInFlightAtInvalidateIsDiscarded() throws Exception {
        ConcurrentLinkedQueue<Runnable> mainThread = new ConcurrentLinkedQueue<>();
        AtomicInteger uploads = new AtomicInteger();
        SkinAvatarCache<String> cache = new SkinAvatarCache<>(
                (uuid, size) -> PNG, bytes -> "head-" + uploads.incrementAndGet(), mainThread::add, IO);

        assertNull(cache.get("uuid-1"));
        // Let the stale fetch reach the main-thread queue, then invalidate before it runs.
        for (int i = 0; i < 200 && mainThread.isEmpty(); i++) Thread.sleep(5);
        assertNull(cache.invalidate("uuid-1"), "nothing was ready to hand back");
        mainThread.poll().run();

        assertEquals(0, uploads.get(), "the overtaken fetch must not upload or store");
        assertNull(cache.get("uuid-1"), "a fresh fetch starts instead");
        for (int i = 0; i < 200 && mainThread.isEmpty(); i++) Thread.sleep(5);
        mainThread.poll().run();
        assertEquals("head-1", cache.get("uuid-1"));
    }

    /** Consecutive failures must lengthen the wait: 5 s after the first, 10 s after the second. */
    @Test
    void backoffGrowsWithConsecutiveFailures() throws Exception {
        AtomicInteger fetches = new AtomicInteger();
        AtomicLong now = new AtomicLong(0);
        AvatarSource failing = (uuid, size) -> {
            fetches.incrementAndGet();
            return null;
        };
        SkinAvatarCache<String> cache = new SkinAvatarCache<>(failing, bytes -> "h", Runnable::run, IO, now::get);

        cache.get("uuid-1");
        Thread.sleep(30);
        now.set(5_000);
        cache.get("uuid-1"); // retried after the 5 s backoff, fails again
        Thread.sleep(30);
        assertEquals(2, fetches.get());

        now.set(5_000 + 9_000);
        cache.get("uuid-1");
        Thread.sleep(30);
        assertEquals(2, fetches.get(), "the second failure waits 10 s, so 9 s is too early");

        now.set(5_000 + 10_000);
        cache.get("uuid-1");
        Thread.sleep(30);
        assertEquals(3, fetches.get());
    }

    /**
     * The regression this guards: an {@link Error} out of the fetch — an image decode running out of
     * memory — slipped past a catch for {@link Exception}, so nothing ever resolved the entry and the head
     * stayed pending, never retried, for the life of the process.
     */
    @Test
    void anErrorFromTheSourceResolvesToAFailureThatIsRetried() throws Exception {
        AtomicInteger fetches = new AtomicInteger();
        AtomicLong now = new AtomicLong(0);
        AvatarSource source = (uuid, size) -> {
            if (fetches.incrementAndGet() == 1) {
                throw new OutOfMemoryError("simulated: decoding a hostile image");
            }
            return PNG;
        };
        SkinAvatarCache<String> cache = new SkinAvatarCache<>(source, bytes -> "handle", Runnable::run, IO, now::get);

        assertNull(cache.get("uuid-1"));
        Thread.sleep(50);
        assertNull(cache.get("uuid-1"));
        assertEquals(1, fetches.get(), "the failure backs off rather than refetching at once");

        now.addAndGet(10_000);
        assertEquals("handle", await(cache, "uuid-1"), "the entry was failed-with-retry, not stuck pending");
    }

    @Test
    void anErrorFromTheUploaderResolvesToAFailureThatIsRetried() throws Exception {
        AtomicInteger uploads = new AtomicInteger();
        AtomicLong now = new AtomicLong(0);
        SkinAvatarCache<String> cache = new SkinAvatarCache<>(
                (uuid, size) -> PNG,
                bytes -> {
                    if (uploads.incrementAndGet() == 1) {
                        throw new OutOfMemoryError("simulated: texture allocation");
                    }
                    return "handle";
                },
                Runnable::run,
                IO,
                now::get);

        assertNull(cache.get("uuid-1"));
        Thread.sleep(50);
        assertNull(cache.get("uuid-1"));

        now.addAndGet(10_000);
        assertEquals("handle", await(cache, "uuid-1"));
    }

    @Test
    void aMainThreadExecutorThatRefusesTheTaskResolvesToAFailureThatIsRetried() throws Exception {
        AtomicInteger submissions = new AtomicInteger();
        AtomicLong now = new AtomicLong(0);
        SkinAvatarCache<String> cache = new SkinAvatarCache<>(
                (uuid, size) -> PNG,
                bytes -> "handle",
                task -> {
                    if (submissions.incrementAndGet() == 1) {
                        throw new IllegalStateException("simulated: executor shut down");
                    }
                    task.run();
                },
                IO,
                now::get);

        assertNull(cache.get("uuid-1"));
        Thread.sleep(50);
        assertNull(cache.get("uuid-1"));

        now.addAndGet(10_000);
        assertEquals("handle", await(cache, "uuid-1"));
    }

    /**
     * A screen of hundreds of heads asks for all of them in one frame. Unbounded, that is hundreds of
     * connections at once, competing with a login for sockets; the rest must wait their turn and still
     * all arrive.
     */
    @Test
    void onlyAFewDownloadsAreInFlightAtOnce() throws Exception {
        AtomicInteger inFlight = new AtomicInteger();
        AtomicInteger peak = new AtomicInteger();
        AvatarSource source = (uuid, size) -> {
            peak.accumulateAndGet(inFlight.incrementAndGet(), Math::max);
            try {
                Thread.sleep(10);
            } finally {
                inFlight.decrementAndGet();
            }
            return PNG;
        };
        SkinAvatarCache<String> cache = new SkinAvatarCache<>(source, bytes -> "handle", Runnable::run, IO);

        for (int i = 0; i < 40; i++) {
            cache.get("uuid-" + i);
        }
        for (int i = 0; i < 40; i++) {
            assertEquals("handle", await(cache, "uuid-" + i), "a queued avatar must still arrive");
        }

        assertTrue(peak.get() <= SkinAvatarCache.MAX_CONCURRENT_FETCHES, "downloads in flight at once: " + peak.get());
        assertTrue(peak.get() > 1, "the bound must not serialise the downloads");
    }

    @Test
    void anAvatarInvalidatedWhileQueuedIsNeverFetched() throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        ConcurrentLinkedQueue<String> fetched = new ConcurrentLinkedQueue<>();
        AvatarSource source = (uuid, size) -> {
            fetched.add(uuid);
            release.await();
            return PNG;
        };
        SkinAvatarCache<String> cache = new SkinAvatarCache<>(source, bytes -> "handle", Runnable::run, IO);

        for (int i = 0; i < SkinAvatarCache.MAX_CONCURRENT_FETCHES; i++) {
            cache.get("busy-" + i);
        }
        cache.get("queued");
        cache.invalidate("queued");
        release.countDown();
        for (int i = 0; i < SkinAvatarCache.MAX_CONCURRENT_FETCHES; i++) {
            await(cache, "busy-" + i);
        }
        Thread.sleep(30);

        assertFalse(fetched.contains("queued"), "an abandoned fetch must not spend a request");
    }
}

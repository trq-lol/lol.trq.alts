package lol.trq.alts.skin;

import java.io.ByteArrayInputStream;
import java.util.Map;
import java.util.Objects;
import java.util.Queue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executor;
import java.util.concurrent.Semaphore;
import lol.trq.alts.spi.AvatarSource;
import lol.trq.alts.spi.MainThreadExecutor;
import lol.trq.alts.spi.TextureUploader;

/**
 * In-memory cache of player face avatars, keyed by UUID. The bytes come from the runtime's
 * {@link AvatarSource} (by default one that crops the face from Mojang's own skin); downloads happen on
 * the runtime's executor, a few at a time, and GPU uploads are marshalled onto the host's main/render thread via {@link MainThreadExecutor} and
 * produced by the host's {@link TextureUploader}.
 *
 * <p><strong>Keyed by UUID, not username.</strong> A username is a mutable display attribute — a rename
 * leaves a cache keyed on the old one pointing at nothing, so the head breaks for good. The UUID is the
 * stable identity, so the head survives a name change.
 *
 * <p>The handle type {@code H} is the host renderer's opaque texture type, so this cache serves any
 * renderer (NanoVG, Skija, …) unchanged — only the eventual blit differs and stays host-side.
 *
 * <p>Entry states (a {@link ConcurrentHashMap} forbids nulls, so each is a real sentinel):
 *
 * <ul>
 *   <li>absent from map &rarr; not requested yet
 *   <li>a {@link Pending} &rarr; fetch in flight; one instance per fetch, so a fetch overtaken by
 *       {@link #invalidate} cannot write its stale result back
 *   <li>a {@link Failed} &rarr; a fetch failed; retried after a growing backoff, not forever abandoned
 *   <li>a host handle &rarr; ready to draw
 * </ul>
 *
 * <p>There is no public constructor: {@code AltsRuntime#skinCache()} returns the runtime's one cache.
 *
 * @param <H> the host's opaque texture-handle type
 * @author trq
 * @since 0.1.0
 */
public final class SkinAvatarCache<H> {

    private static final int FACE_PX = 64;

    /** First retry waits this long after a failure; each further failure doubles it, up to the cap. */
    private static final long RETRY_BASE_MILLIS = 5_000L;

    /** Longest a failed avatar waits before it is tried again. */
    private static final long RETRY_MAX_MILLIS = 5 * 60_000L;

    /** How many avatar downloads may be in flight at once; the rest wait their turn. */
    static final int MAX_CONCURRENT_FETCHES = 6;

    private final Map<String, Object> cache = new ConcurrentHashMap<>();
    private final Semaphore slots = new Semaphore(MAX_CONCURRENT_FETCHES);
    private final Queue<Runnable> waiting = new ConcurrentLinkedQueue<>();
    private final AvatarSource source;
    private final TextureUploader<H> uploader;
    private final MainThreadExecutor mainThread;
    private final Executor executor;
    private final java.util.function.LongSupplier clock;

    static {
        SkinBridge.install();
    }

    /**
     * Creates a cache that sources faces from {@code source}, uploads via {@code uploader}, marshals
     * onto {@code mainThread}, and downloads on {@code executor}. Package-private: the runtime builds the
     * one cache it hands out, through {@link SkinBridge}.
     *
     * @param source the avatar source
     * @param uploader the host texture uploader; if null the cache stays empty and always returns null
     * @param mainThread the host main-thread executor used to marshal uploads
     * @param executor the executor the downloads run on
     */
    SkinAvatarCache(
            AvatarSource source, TextureUploader<H> uploader, MainThreadExecutor mainThread, Executor executor) {
        this(source, uploader, mainThread, executor, System::currentTimeMillis);
    }

    // Exists so the retry backoff can be exercised against a controllable clock in tests.
    SkinAvatarCache(
            AvatarSource source,
            TextureUploader<H> uploader,
            MainThreadExecutor mainThread,
            Executor executor,
            java.util.function.LongSupplier clock) {
        this.source = Objects.requireNonNull(source, "AvatarSource");
        this.uploader = uploader;
        this.mainThread = Objects.requireNonNull(mainThread, "MainThreadExecutor");
        this.executor = Objects.requireNonNull(executor, "executor");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * Returns the cached avatar for {@code uuid} if ready, otherwise {@code null}. On a cache miss, or on
     * a past failure whose backoff has elapsed, this starts an async fetch so a later frame can pick it
     * up.
     *
     * @param uuid the player UUID to resolve an avatar for; null or blank yields null
     * @return the ready handle, or null while a fetch is pending, is backing off, or was just started
     * @since 0.10.0
     */
    @SuppressWarnings("unchecked")
    public H get(String uuid) {
        if (uuid == null || uuid.isBlank() || uploader == null) {
            return null;
        }
        String key = uuid.toLowerCase(java.util.Locale.ROOT);
        Object existing = cache.get(key);

        if (existing == null) {
            Pending pending = new Pending();
            if (cache.putIfAbsent(key, pending) == null) {
                fetchAsync(key, pending);
            }
            return null;
        }
        if (existing instanceof Pending) {
            return null;
        }
        if (existing instanceof Failed failed) {
            // A failure is temporary. Once its backoff elapses, the next request re-arms the fetch,
            // rather than the head staying broken for the life of the process.
            Pending pending = new Pending(failed.failures());
            if (clock.getAsLong() >= failed.retryAt() && cache.replace(key, failed, pending)) {
                fetchAsync(key, pending);
            }
            return null;
        }
        return (H) existing;
    }

    /**
     * Drops the cached avatar for {@code uuid}, so the next {@link #get} fetches it again. For a skin the
     * host knows has changed: without this the old head is served for the life of the process.
     *
     * <p>A fetch already in flight for this UUID is abandoned; its result is discarded rather than
     * stored, since it may predate the change.
     *
     * @param uuid the player UUID whose avatar to drop; null or blank is a no-op
     * @return the handle that was cached, for the host to release, or null if none was ready
     * @since 0.12.0
     */
    @SuppressWarnings("unchecked")
    public H invalidate(String uuid) {
        if (uuid == null || uuid.isBlank()) {
            return null;
        }
        Object removed = cache.remove(uuid.toLowerCase(java.util.Locale.ROOT));
        return removed == null || removed instanceof Pending || removed instanceof Failed ? null : (H) removed;
    }

    /**
     * Queues an avatar fetch and starts it as soon as a slot is free.
     *
     * <p>At most {@link #MAX_CONCURRENT_FETCHES} downloads are in flight at once. A screen listing
     * hundreds of accounts asks for every head in one frame, and unbounded that is hundreds of
     * simultaneous connections competing with a login for sockets and for the host's executor. The
     * waiting fetches sit in a queue rather than on blocked threads, so the bound costs a host-supplied
     * executor nothing.
     *
     * @param key the cache key being fetched
     * @param pending the marker this fetch owns
     */
    private void fetchAsync(String key, Pending pending) {
        waiting.add(() -> startFetch(key, pending));
        drain();
    }

    /** Starts queued fetches until the slots or the queue run out. */
    private void drain() {
        while (slots.tryAcquire()) {
            Runnable next = waiting.poll();
            if (next == null) {
                slots.release();
                // A fetch queued between the poll and the release would otherwise wait for a slot nobody
                // is going to hand it.
                if (waiting.isEmpty()) {
                    return;
                }
                continue;
            }
            next.run();
        }
    }

    /**
     * Fetches an avatar off-thread and hands it to the main thread for upload. Called holding a slot,
     * which is given back when the download ends, however it ends.
     *
     * <p>Every way this can go wrong ends with the entry marked failed. A pending marker that nothing
     * resolves is never retried, so the head would stay missing for the life of the process — and the
     * failures that used to slip through were exactly the ones not shaped like an {@link Exception}: an
     * {@link Error} out of an image decode, an executor or a main-thread executor refusing the task.
     *
     * @param key the cache key being fetched
     * @param pending the marker this fetch owns
     */
    private void startFetch(String key, Pending pending) {
        // Invalidated while it sat in the queue: nobody is waiting for this one any more.
        if (cache.get(key) != pending) {
            slots.release();
            return;
        }
        CompletableFuture<byte[]> download;
        try {
            download = CompletableFuture.supplyAsync(() -> downloadBytes(key), executor);
        } catch (Throwable refused) {
            slots.release();
            markFailed(key, pending);
            return;
        }
        download.whenComplete((bytes, failure) -> {
            slots.release();
            try {
                if (failure != null || bytes == null) {
                    markFailed(key, pending);
                    return;
                }
                try {
                    mainThread.execute(() -> upload(key, pending, bytes));
                } catch (Throwable refused) {
                    markFailed(key, pending);
                }
            } finally {
                drain();
            }
        });
    }

    private byte[] downloadBytes(String key) {
        try {
            return source.avatarPng(key, FACE_PX);
        } catch (Throwable ignored) {
            // Throwable, not Exception: a source that runs out of memory decoding a hostile image has
            // failed this one avatar, and the entry must still resolve.
            return null;
        }
    }

    private void upload(String key, Pending pending, byte[] bytes) {
        // Invalidated (or superseded) while in flight: the result may be the old skin, so drop it.
        if (cache.get(key) != pending) {
            return;
        }
        try {
            H handle = uploader.upload(new ByteArrayInputStream(bytes));
            if (handle != null) {
                cache.replace(key, pending, handle);
            } else {
                markFailed(key, pending);
            }
        } catch (Throwable ignored) {
            markFailed(key, pending);
        }
    }

    /**
     * Records a failure with a backoff that grows with the run of consecutive failures for this key, so
     * a persistently missing avatar is retried ever less often rather than hammered or given up on.
     *
     * @param key the cache key that failed
     * @param pending the fetch that failed; nothing is recorded if it is no longer the current one
     */
    private void markFailed(String key, Pending pending) {
        int priorFailures = pending.priorFailures;
        long delay = Math.min(RETRY_BASE_MILLIS << Math.min(priorFailures, 6), RETRY_MAX_MILLIS);
        cache.replace(key, pending, new Failed(priorFailures + 1, clock.getAsLong() + delay));
    }

    /**
     * An in-flight fetch. Identity matters: a fetch may only write its outcome over its own marker.
     * Carries the failure count of the entry it replaced so the backoff keeps growing across retries.
     */
    private static final class Pending {
        final int priorFailures;

        Pending() {
            this(0);
        }

        Pending(int priorFailures) {
            this.priorFailures = priorFailures;
        }
    }

    /**
     * A failed fetch, carrying how many times it has failed and the earliest time to try again.
     *
     * @param failures the count of consecutive failures
     * @param retryAt the epoch-millis time before which the entry is not retried
     */
    private record Failed(int failures, long retryAt) {}
}

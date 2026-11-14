package lol.trq.alts.cache;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.function.Function;
import java.util.function.LongSupplier;

/**
 * A lazy, non-blocking, per-key value cache. {@link #get(Object)} never blocks: on a cache miss it
 * returns {@code null} and fires a background fetch, so a later call (e.g. the next frame) sees the
 * filled value. This is the data-only distillation of {@link lol.trq.alts.skin.SkinAvatarCache} — it
 * drops the GPU/main-thread upload step, since plain data needs no marshalling.
 *
 * <p>Each key sits in one of these states, each a real marker object because a
 * {@link ConcurrentHashMap} forbids null values:
 *
 * <ul>
 *   <li>absent &rarr; never requested
 *   <li>pending &rarr; a first fetch is in flight
 *   <li>failed &rarr; the last fetch threw or returned {@code null}, and no value was ever held. Retried
 *       once a backoff elapses — it grows with each consecutive failure — or at once after
 *       {@link #invalidate(Object)}
 *   <li>a hit &rarr; a value with the time it was fetched at
 * </ul>
 *
 * <p>With a positive {@code ttlMillis} the cache is <em>stale-while-revalidate</em>: once an entry
 * ages past the TTL, {@link #get(Object)} keeps returning the stale value <em>and</em> kicks off a
 * refresh in the background, so the UI never flickers to empty. A refresh that fails leaves the stale
 * value in place and is tried again after the same growing backoff: a value that was good a moment ago is
 * a better answer than nothing, and a service having a bad minute must not blank every entry that
 * happened to expire during it.
 *
 * <p>The cache is bounded. Past {@code maxEntries}, the entries read longest ago are dropped, so a host
 * that looks up an ever-growing set of keys holds a fixed amount rather than all of them for the life of
 * the process.
 *
 * <p>The {@code loader} runs on the executor the cache was given (for the runtime's game-stats caches,
 * the runtime's executor), so it may block. It must be thread-safe and should return {@code null}
 * (or throw) to signal failure.
 *
 * @param <K> the lookup key (e.g. a player UUID string)
 * @param <V> the cached value (e.g. a stats record)
 * @author trq
 * @since 0.1.0
 */
public final class AsyncCache<K, V> {

    /**
     * The entry bound a cache gets when none is given.
     *
     * @since 0.12.0
     */
    public static final int DEFAULT_MAX_ENTRIES = 4096;

    /** First retry waits this long after a failure; each further failure doubles it, up to the cap. */
    private static final long RETRY_BASE_MILLIS = 5_000L;

    /** Longest a failed key waits before it is tried again. */
    private static final long RETRY_MAX_MILLIS = 5 * 60_000L;

    private final ConcurrentHashMap<K, Entry> entries = new ConcurrentHashMap<>();
    private final Executor executor;
    private final Function<K, V> loader;
    private final long ttlMillis;
    private final int maxEntries;
    private final LongSupplier clock;

    /**
     * Creates a cache whose entries never expire (refresh only via {@link #invalidate(Object)}).
     *
     * @param executor the executor the loader runs on; never the common pool unless the caller says so
     * @param loader the background fetch; returns {@code null} or throws to mark a key failed
     * @since 1.0.0
     */
    public AsyncCache(Executor executor, Function<K, V> loader) {
        this(executor, loader, 0L);
    }

    /**
     * Creates a cache with stale-while-revalidate expiry, holding at most {@link #DEFAULT_MAX_ENTRIES}.
     *
     * @param executor the executor the loader runs on
     * @param loader the background fetch; returns {@code null} or throws to mark a key failed
     * @param ttlMillis how long a fetched value is fresh, in milliseconds; {@code <= 0} never expires
     * @since 1.0.0
     */
    public AsyncCache(Executor executor, Function<K, V> loader, long ttlMillis) {
        this(executor, loader, ttlMillis, DEFAULT_MAX_ENTRIES);
    }

    /**
     * Creates a cache with stale-while-revalidate expiry and a given entry bound.
     *
     * @param executor the executor the loader runs on
     * @param loader the background fetch; returns {@code null} or throws to mark a key failed
     * @param ttlMillis how long a fetched value is fresh, in milliseconds; {@code <= 0} never expires
     * @param maxEntries the most entries to hold before the least recently read are dropped; at least 1
     * @since 1.0.0
     */
    public AsyncCache(Executor executor, Function<K, V> loader, long ttlMillis, int maxEntries) {
        this(executor, loader, ttlMillis, maxEntries, System::currentTimeMillis);
    }

    // Exists so expiry, the retry backoff and eviction order can be exercised against a controllable clock.
    AsyncCache(Executor executor, Function<K, V> loader, long ttlMillis, int maxEntries, LongSupplier clock) {
        if (maxEntries < 1) {
            throw new IllegalArgumentException("maxEntries must be at least 1");
        }
        this.executor = Objects.requireNonNull(executor, "executor");
        this.loader = Objects.requireNonNull(loader, "loader");
        this.ttlMillis = ttlMillis;
        this.maxEntries = maxEntries;
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * Returns the cached value for {@code key} if present, otherwise {@code null}. On a miss this
     * starts a background fetch; on a stale hit it serves the stale value and refreshes in the
     * background; on a past failure whose backoff has elapsed it tries again.
     *
     * @param key the lookup key
     * @return the value if ready (possibly stale), or {@code null} while pending, failed, or just
     *     requested
     * @since 0.2.0
     */
    @SuppressWarnings("unchecked")
    public V get(K key) {
        long now = clock.getAsLong();
        Entry existing = entries.get(key);

        if (existing == null) {
            Entry pending = Entry.pending(now, 0);
            if (entries.putIfAbsent(key, pending) == null) {
                try {
                    evictIfOver(key);
                } catch (RuntimeException evictionFailed) {
                    // The marker is already in the map. Whatever went wrong keeping the cache within its
                    // bound, the fetch below must still run, or this key would answer null for good.
                }
                fetch(key, pending);
            }
            return null;
        }
        existing.lastRead = now;

        if (existing.value != null) {
            boolean stale = ttlMillis > 0 && now - existing.fetchedAt > ttlMillis;
            if (stale && !existing.loading && now >= existing.retryAt) {
                // Stale: refresh in the background but keep serving the old value, during the refresh
                // and after it if the refresh fails.
                Entry refreshing = existing.refreshing(now);
                if (entries.replace(key, existing, refreshing)) {
                    fetch(key, refreshing);
                }
            }
            return (V) existing.value;
        }

        if (!existing.loading && now >= existing.retryAt) {
            // A failure is temporary: once its backoff elapses the next request re-arms the fetch.
            Entry pending = Entry.pending(now, existing.failures);
            if (entries.replace(key, existing, pending)) {
                fetch(key, pending);
            }
        }
        return null;
    }

    /**
     * Runs the loader for a key and writes the outcome over the marker the fetch was started for. A
     * fetch overtaken by {@link #invalidate(Object)}, {@link #clear()} or an eviction finds its marker
     * gone and writes nothing, so a stale result never resurrects a dropped entry.
     *
     * @param key the key to load
     * @param marker the in-flight entry this fetch owns
     */
    private void fetch(K key, Entry marker) {
        CompletableFuture<V> loading;
        try {
            loading = CompletableFuture.supplyAsync(() -> loader.apply(key), executor);
        } catch (RuntimeException rejected) {
            // The executor refused the task. Resolve the marker anyway, or the key would stay pending forever.
            entries.replace(key, marker, marker.failed(clock.getAsLong()));
            return;
        }
        loading.whenComplete((value, error) -> {
            long now = clock.getAsLong();
            Entry outcome = error != null || value == null ? marker.failed(now) : Entry.hit(value, now, marker);
            entries.replace(key, marker, outcome);
        });
    }

    /**
     * Drops the entries read longest ago until the cache is back within its bound. The key just
     * requested is never the one dropped.
     *
     * @param justAdded the key whose insertion may have put the cache over its bound
     */
    private void evictIfOver(K justAdded) {
        int excess = entries.size() - maxEntries;
        if (excess <= 0) {
            return;
        }
        // Each read time is copied out once, before sorting. Other threads restamp entries while this
        // runs, and a sort whose keys change under it is one the JDK is entitled to abort.
        List<Candidate<K>> candidates = new ArrayList<>();
        for (Map.Entry<K, Entry> entry : entries.entrySet()) {
            if (!entry.getKey().equals(justAdded)) {
                candidates.add(new Candidate<>(entry.getKey(), entry.getValue(), entry.getValue().lastRead));
            }
        }
        candidates.sort(Comparator.comparingLong(Candidate::lastRead));
        for (int i = 0; i < excess && i < candidates.size(); i++) {
            Candidate<K> victim = candidates.get(i);
            entries.remove(victim.key(), victim.entry());
        }
    }

    /**
     * An entry as it stood when an eviction looked at it.
     *
     * @param key the entry's key
     * @param entry the entry itself, so only that exact instance is removed
     * @param lastRead when it had last been read at that moment
     * @param <K> the key type
     */
    private record Candidate<K>(K key, Entry entry, long lastRead) {}

    /**
     * Drops the entry for {@code key} so the next {@link #get(Object)} refetches it. Use to force a
     * refresh, or to retry a failed key without waiting out its backoff.
     *
     * @param key the key to evict
     * @since 0.2.0
     */
    public void invalidate(K key) {
        entries.remove(key);
    }

    /**
     * Drops every entry.
     *
     * @since 0.2.0
     */
    public void clear() {
        entries.clear();
    }

    /**
     * Returns how many keys the cache currently tracks, counting those pending or failed.
     *
     * @return the entry count
     * @since 0.12.0
     */
    public int size() {
        return entries.size();
    }

    /**
     * One key's state. Identity matters: a fetch may only write its outcome over the marker it was
     * started for, so every transition makes a new instance.
     */
    private static final class Entry {

        /** The held value, or null when none was ever fetched. */
        final Object value;

        /** When {@link #value} was fetched, in clock millis. */
        final long fetchedAt;

        /** Whether a fetch is in flight for this entry. */
        final boolean loading;

        /** How many fetches in a row have failed. */
        final int failures;

        /** The clock time before which a failed entry is not tried again. */
        final long retryAt;

        /** When the entry was last read, for eviction order. Racy by design: a near-miss costs nothing. */
        volatile long lastRead;

        private Entry(Object value, long fetchedAt, boolean loading, int failures, long retryAt, long lastRead) {
            this.value = value;
            this.fetchedAt = fetchedAt;
            this.loading = loading;
            this.failures = failures;
            this.retryAt = retryAt;
            this.lastRead = lastRead;
        }

        static Entry pending(long now, int failures) {
            return new Entry(null, 0L, true, failures, 0L, now);
        }

        static Entry hit(Object value, long now, Entry previous) {
            return new Entry(value, now, false, 0, 0L, previous.lastRead);
        }

        Entry refreshing(long now) {
            return new Entry(value, fetchedAt, true, failures, retryAt, now);
        }

        /**
         * Returns this entry with its fetch failed: any held value is kept, and the next attempt is
         * pushed back by a delay that doubles with each consecutive failure.
         */
        Entry failed(long now) {
            long delay = Math.min(RETRY_BASE_MILLIS << Math.min(failures, 6), RETRY_MAX_MILLIS);
            return new Entry(value, fetchedAt, false, failures + 1, now + delay, lastRead);
        }
    }
}

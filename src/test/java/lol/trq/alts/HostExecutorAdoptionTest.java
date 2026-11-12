package lol.trq.alts;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import lol.trq.alts.account.Entitlements;
import lol.trq.alts.auth.AltAccountServiceImpl;
import lol.trq.alts.auth.AltLoginCallback.LoginResult;
import lol.trq.alts.auth.AltLoginServiceImpl;
import lol.trq.alts.bulk.BulkOperationsImpl;
import lol.trq.alts.bulk.BulkOptions;
import lol.trq.alts.bulk.BulkProgress;
import lol.trq.alts.bulk.BulkReport;
import lol.trq.alts.cache.AsyncCache;
import lol.trq.alts.model.AccountType;
import lol.trq.alts.model.AltAccount;
import lol.trq.alts.model.LoginMode;
import lol.trq.alts.net.IoExecutor;
import lol.trq.alts.skin.SkinAvatarCache;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A host that names its own executor gets the library's blocking work on it. The seam is worthless if
 * any call site still reaches for the JVM-wide common pool: the host bounded its threads, or wrapped
 * them to carry context, and one stray one-argument {@code supplyAsync} silently opts out of both.
 */
class HostExecutorAdoptionTest {

    private static final String HOST_THREAD_PREFIX = "host-io-";

    private final AtomicInteger submitted = new AtomicInteger();
    private final Set<String> strayThreads = ConcurrentHashMap.newKeySet();

    /** A host executor that counts what it is handed and runs each task on a recognisable thread. */
    private final Executor host = task -> {
        int id = submitted.incrementAndGet();
        Thread.ofPlatform().daemon().name(HOST_THREAD_PREFIX + id).start(task);
    };

    @BeforeEach
    void bindHostExecutor() {
        IoExecutor.bind(host);
    }

    @AfterEach
    void restoreDefault() {
        IoExecutor.resetForTests();
    }

    /** Records the current thread if it is not one of the host's. */
    private void onHostThread() {
        String name = Thread.currentThread().getName();
        if (!name.startsWith(HOST_THREAD_PREFIX)) {
            strayThreads.add(name);
        }
    }

    @Test
    void aCacheLoaderRunsOnTheHostExecutor() throws Exception {
        AsyncCache<String, String> cache = new AsyncCache<>(key -> {
            onHostThread();
            return "value";
        });

        cache.get("key");
        for (int i = 0; i < 400 && cache.get("key") == null; i++) {
            Thread.sleep(5);
        }

        assertEquals("value", cache.get("key"));
        assertEquals(1, submitted.get(), "the load must have been handed to the host's executor");
        assertTrue(strayThreads.isEmpty(), "ran off the host's executor: " + strayThreads);
    }

    @Test
    void anAvatarDownloadRunsOnTheHostExecutor() throws Exception {
        SkinAvatarCache<String> cache = new SkinAvatarCache<>(
                (uuid, size) -> {
                    onHostThread();
                    return new byte[] {1};
                },
                bytes -> "handle",
                Runnable::run);

        cache.get("uuid-1");
        for (int i = 0; i < 400 && cache.get("uuid-1") == null; i++) {
            Thread.sleep(5);
        }

        assertEquals("handle", cache.get("uuid-1"));
        assertEquals(1, submitted.get(), "the download must have been handed to the host's executor");
        assertTrue(strayThreads.isEmpty(), "ran off the host's executor: " + strayThreads);
    }

    @Test
    void aLoginResolvesOnTheHostExecutor() throws Exception {
        AltLoginServiceImpl logins = new AltLoginServiceImpl(session -> {}, null);

        // An empty token is refused before any request, but only after the route has gone off-thread.
        LoginResult result = logins.loginSession("", LoginMode.DIRECT).get(5, TimeUnit.SECONDS);

        assertFalse(result.success());
        assertEquals(1, submitted.get(), "the login must have been handed to the host's executor");
    }

    @Test
    void aBulkSweepRunsItsEntriesOnTheHostExecutor() throws Exception {
        AltLoginServiceImpl logins = new AltLoginServiceImpl(session -> {}, null);
        BulkOperationsImpl bulk = new BulkOperationsImpl(logins, new AltAccountServiceImpl(null), account -> () -> {
            onHostThread();
            return new Entitlements(Set.of());
        });
        List<AltAccount> accounts = List.of(
                AltAccount.of("00000000-0000-4000-8000-000000000001", "AltOne", "token", AccountType.MICROSOFT),
                AltAccount.of("00000000-0000-4000-8000-000000000002", "AltTwo", "token", AccountType.MICROSOFT));
        BulkOptions spaced = new BulkOptions(1, Duration.ofMillis(5), 0, Duration.ZERO, true);

        BulkReport report = bulk.entitlementsAll(accounts, spaced, BulkProgress.NONE)
                .report()
                .get(5, TimeUnit.SECONDS);

        assertEquals(2, report.succeeded());
        // Two reads, plus the spacing wait between them, which is scheduled onto the same executor.
        assertTrue(submitted.get() >= 2, "each read must have been handed to the host's executor");
        assertTrue(strayThreads.isEmpty(), "ran off the host's executor: " + strayThreads);
    }
}

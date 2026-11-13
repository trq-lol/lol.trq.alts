package lol.trq.alts;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import lol.trq.alts.model.AccountType;
import lol.trq.alts.model.AltAccount;
import lol.trq.alts.net.IoExecutor;
import lol.trq.alts.net.NetTestHooks;
import lol.trq.alts.net.NetworkScope;
import lol.trq.alts.net.ProxyRoute;
import lol.trq.alts.spi.StoreKeyProvider;
import lol.trq.alts.spi.ToastSink;
import lol.trq.alts.store.AccountStore;
import lol.trq.alts.store.HostSecrets;
import lol.trq.alts.store.StoreTestHooks;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Each runtime owns its stores. Two runtimes in one process keep their accounts and secrets apart, in
 * memory and on disk; two runtimes cannot share a store file, and the second is told so when it builds;
 * and closing a runtime writes what it holds and hands the files back.
 */
class AltsRuntimeStoresTest {

    private static final String ALEX = "00000000-0000-4000-8000-0000000000f1";
    private static final String STEVE = "00000000-0000-4000-8000-0000000000f2";
    private static final StoreKeyProvider KEY_A = () -> "key-a-0123456789abcdef0123456789".getBytes();
    private static final StoreKeyProvider KEY_B = () -> "key-b-fedcba9876543210fedcba9876".getBytes();

    @TempDir
    Path dirA;

    @TempDir
    Path dirB;

    @AfterEach
    void resetNetworkStatics() {
        // The transport and executor statics are still bound by build(); they are not what this tests.
        NetTestHooks.resetHttp();
        NetTestHooks.resetExecutor();
    }

    private static AltsRuntime.Builder<Object> builder(Path dir) {
        return new AltsRuntime.Builder<Object>()
                .sessionInjector(session -> {})
                .vaultDirectory(() -> dir)
                .mainThread(Runnable::run)
                .toastSink((level, title, description, durationMs) -> {});
    }

    private static AltAccount account(String uuid, String name) {
        return AltAccount.of(uuid, name, "access-" + name, AccountType.MICROSOFT);
    }

    private static boolean holds(AltsRuntime<?> alts, String uuid) {
        return alts.store().accounts().stream().anyMatch(account -> uuid.equals(account.uuid()));
    }

    @Test
    void twoRuntimesOnTwoDirectoriesNeverSeeEachOthersAccountsOrSecrets() throws Exception {
        try (AltsRuntime<Object> a = builder(dirA).storeKeyProvider(KEY_A).build();
                AltsRuntime<Object> b = builder(dirB).storeKeyProvider(KEY_B).build()) {
            assertTrue(a.store() != b.store() && a.secrets() != b.secrets(), "each runtime has stores of its own");

            // Driven concurrently, as two hosts in one process would.
            Thread fromA = new Thread(() -> {
                a.store().addAccount(account(ALEX, "Alex"));
                a.secrets().put("feature.api-key", "secret-a");
            });
            Thread fromB = new Thread(() -> {
                b.store().addAccount(account(STEVE, "Steve"));
                b.secrets().put("feature.api-key", "secret-b");
            });
            fromA.start();
            fromB.start();
            fromA.join(TimeUnit.SECONDS.toMillis(30));
            fromB.join(TimeUnit.SECONDS.toMillis(30));

            assertTrue(holds(a, ALEX) && !holds(a, STEVE), "a holds only what was added to a");
            assertTrue(holds(b, STEVE) && !holds(b, ALEX), "b holds only what was added to b");
            assertEquals("secret-a", a.secrets().get("feature.api-key"));
            assertEquals("secret-b", b.secrets().get("feature.api-key"));
        }

        try (AltsRuntime<Object> a = builder(dirA).storeKeyProvider(KEY_A).build()) {
            assertTrue(a.store().loadError().isEmpty());
            assertTrue(holds(a, ALEX) && !holds(a, STEVE), "on disk, a's directory holds a's accounts only");
            assertEquals("secret-a", a.secrets().get("feature.api-key"));
        }
        try (AltsRuntime<Object> b = builder(dirB).storeKeyProvider(KEY_B).build()) {
            assertTrue(b.store().loadError().isEmpty());
            assertTrue(holds(b, STEVE) && !holds(b, ALEX), "on disk, b's directory holds b's accounts only");
            assertEquals("secret-b", b.secrets().get("feature.api-key"));
        }
        try (AltsRuntime<Object> crossed = builder(dirA).storeKeyProvider(KEY_B).build()) {
            assertTrue(crossed.store().loadError().isPresent(), "a's files were sealed under a's key, not b's");
            assertTrue(crossed.secrets().loadError().isPresent());
        }
    }

    @Test
    void aSecondRuntimeOnTheSameDirectoryFailsToBuildAndTheFirstKeepsWorking() {
        try (AltsRuntime<Object> first = builder(dirA).build()) {
            first.store().addAccount(account(ALEX, "Alex"));

            IllegalStateException refused = assertThrows(
                    IllegalStateException.class, () -> builder(dirA).build());
            assertTrue(refused.getMessage().contains("in use"), "the failure says why: " + refused.getMessage());
            assertFalse(refused.getMessage().contains(dirA.toString()), "and names no path: " + refused.getMessage());

            first.store().addAccount(account(STEVE, "Steve"));
            first.secrets().put("feature.api-key", "value");
            first.store().flush();
            first.secrets().flush();
            assertTrue(first.store().saveError().isEmpty(), "the first runtime still persists");
            assertTrue(first.secrets().saveError().isEmpty());
        }

        try (AltsRuntime<Object> third = builder(dirA).build()) {
            assertTrue(holds(third, ALEX) && holds(third, STEVE), "once the first closed, its data is there");
            assertEquals("value", third.secrets().get("feature.api-key"));
        }
    }

    @Test
    void aRefusedBuildLeavesTheFirstRuntimesTransportExecutorAndToastsInPlace() throws Exception {
        ProxyRoute routeA = ProxyRoute.http("proxy-a.example", 3128);
        ProxyRoute routeB = ProxyRoute.http("proxy-b.example", 3128);
        Executor executorA = Runnable::run;
        Executor executorB = Runnable::run;
        List<String> toastsA = new CopyOnWriteArrayList<>();
        List<String> toastsB = new CopyOnWriteArrayList<>();

        try (AltsRuntime<Object> first = builder(dirA)
                .proxyProvider(scope -> routeA)
                .executor(executorA)
                .toastSink((level, title, description, durationMs) -> toastsA.add(title))
                .build()) {
            assertThrows(
                    IllegalStateException.class,
                    () -> builder(dirA)
                            .proxyProvider(scope -> routeB)
                            .executor(executorB)
                            .toastSink((level, title, description, durationMs) -> toastsB.add(title))
                            .build());

            assertSame(
                    routeA,
                    NetTestHooks.routeFor(NetworkScope.of(NetworkScope.Purpose.PROFILE)),
                    "the refused build must not have installed its proxy provider");
            assertSame(executorA, IoExecutor.executor(), "nor its executor");
            first.toasts().toast(ToastSink.Level.INFO, "still mine", "", 0);
            assertEquals(List.of("still mine"), toastsA, "nor its toast sink");
            assertTrue(toastsB.isEmpty());
        }
    }

    @Test
    void aRuntimeCoalescesTheWritesOfBothStores() {
        try (AltsRuntime<Object> alts = builder(dirA).build()) {
            Duration delay = StoreTestHooks.runtimeWriteDelay();
            assertTrue(delay.toMillis() > 0, "a burst of logins must not write the file once each");
            assertEquals(delay, StoreTestHooks.writeDelayOf(alts.store()));
            assertEquals(delay, StoreTestHooks.writeDelayOf(alts.secrets()));
        }
    }

    @Test
    void aBuildThatFailsAfterOpeningTheStoresReleasesBoth() {
        assertThrows(
                IllegalStateException.class,
                () -> builder(dirA)
                        .afterStoresOpenForTests(() -> {
                            throw new IllegalStateException("construction failed after the stores opened");
                        })
                        .build());

        AccountStore accounts = StoreTestHooks.openAccountStore(dirA);
        HostSecrets secrets = StoreTestHooks.openHostSecrets(dirA);
        StoreTestHooks.close(secrets);
        StoreTestHooks.close(accounts);
        try (AltsRuntime<Object> next = builder(dirA).build()) {
            assertTrue(next.store().loadError().isEmpty(), "and a runtime builds there afterwards");
        }
    }

    @Test
    void aBuildRefusedOnTheSecondFileReleasesTheFirst() {
        HostSecrets held = StoreTestHooks.openHostSecrets(dirA);
        try {
            assertThrows(IllegalStateException.class, () -> builder(dirA).build());

            // The refused build had already locked the account file; it must have let it go again.
            AccountStore accounts = StoreTestHooks.openAccountStore(dirA);
            accounts.load();
            assertTrue(accounts.loadError().isEmpty());
            StoreTestHooks.close(accounts);
        } finally {
            StoreTestHooks.close(held);
        }
    }

    @Test
    void closeIsIdempotentAndWritesWhatIsStillWaiting() {
        AltsRuntime<Object> alts = builder(dirA).build();
        // The builder coalesces writes, so these are still in memory when close() is called.
        alts.store().addAccount(account(ALEX, "Alex"));
        alts.secrets().put("feature.api-key", "value");

        alts.close();
        alts.close();

        try (AltsRuntime<Object> reopened = builder(dirA).build()) {
            assertTrue(holds(reopened, ALEX), "close must not lose a coalesced account write");
            assertEquals("value", reopened.secrets().get("feature.api-key"), "nor a coalesced secret");
        }
    }

    @Test
    void afterCloseTheStoresWriteNothing() throws Exception {
        AltsRuntime<Object> alts = builder(dirA).build();
        alts.store().addAccount(account(ALEX, "Alex"));
        alts.close();
        byte[] accountsBefore = Files.readAllBytes(dirA.resolve("accounts.dat"));

        alts.store().addAccount(account(STEVE, "Steve"));
        alts.secrets().put("feature.api-key", "value");

        assertTrue(alts.store().saveError().isPresent(), "a closed store reports the write it refused");
        assertTrue(alts.secrets().saveError().isPresent());
        assertArrayEquals(accountsBefore, Files.readAllBytes(dirA.resolve("accounts.dat")));
        assertFalse(Files.exists(dirA.resolve("secrets.dat")), "nothing new appears on disk");
        try (AltsRuntime<Object> reopened = builder(dirA).build()) {
            assertTrue(holds(reopened, ALEX));
            assertFalse(holds(reopened, STEVE), "what came after close was never persisted");
            assertNull(reopened.secrets().get("feature.api-key"));
        }
    }
}

package lol.trq.alts;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import lol.trq.alts.auth.LoginResult;
import lol.trq.alts.auth.MicrosoftAuthConfig;
import lol.trq.alts.bulk.BulkOptions;
import lol.trq.alts.bulk.BulkReport;
import lol.trq.alts.model.GameStats;
import lol.trq.alts.model.LoginMode;
import lol.trq.alts.net.NetworkScope;
import lol.trq.alts.net.ProxyRoute;
import lol.trq.alts.spi.GameStatsSource;
import lol.trq.alts.spi.ProxyProvider;
import lol.trq.alts.spi.StoreKeyProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The freeze's test of section 1: two runtimes in one JVM, with different directories, proxy providers,
 * key providers and executors, driven at the same time. Neither sees the other's accounts, secrets,
 * proxy choices or threads, and nothing of either runs on the JVM's common pool.
 */
class AltsRuntimeIsolationTest {

    private static final int LOGINS = 8;
    private static final StoreKeyProvider KEY_A = () -> "key-a-0123456789abcdef0123456789".getBytes();
    private static final StoreKeyProvider KEY_B = () -> "key-b-fedcba9876543210fedcba9876".getBytes();

    @TempDir
    Path dirA;

    @TempDir
    Path dirB;

    private HttpServer services;
    private ExecutorService hostA;
    private ExecutorService hostB;

    @BeforeEach
    void start() throws Exception {
        // Answers the profile hop of a session login with an identity derived from the token, so each
        // runtime's logins resolve to accounts of its own; answers every name lookup with "nobody".
        services = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        services.createContext("/minecraft/profile", exchange -> {
            if (!exchange.getRequestURI().getPath().equals("/minecraft/profile")) {
                // A name lookup, under the same prefix: nobody has that name.
                exchange.sendResponseHeaders(404, -1);
                exchange.close();
                return;
            }
            String token =
                    exchange.getRequestHeaders().getFirst("Authorization").substring("Bearer ".length());
            byte[] body = ("{\"id\":\"" + uuidFor(token) + "\",\"name\":\"" + token.replace("-", "") + "\"}")
                    .getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        services.createContext("/", exchange -> {
            exchange.getRequestBody().readAllBytes();
            exchange.sendResponseHeaders(404, -1);
            exchange.close();
        });
        services.setExecutor(
                lol.trq.alts.TestExecutors.perTask(Thread.ofVirtual().factory()));
        services.start();
        hostA = lol.trq.alts.TestExecutors.perTask(
                Thread.ofPlatform().daemon().name("host-a-", 0).factory());
        hostB = lol.trq.alts.TestExecutors.perTask(
                Thread.ofPlatform().daemon().name("host-b-", 0).factory());
    }

    @AfterEach
    void stop() {
        services.stop(0);
        hostA.shutdownNow();
        hostB.shutdownNow();
    }

    /** A token's account: the token's two numbers, as an undashed UUID. */
    private static String uuidFor(String token) {
        String[] parts = token.split("-");
        int runtime = parts[1].equals("a") ? 0xa : 0xb;
        return String.format("%08x00004000800000%010x", runtime, Integer.parseInt(parts[2]));
    }

    private String base() {
        return "http://" + InetAddress.getLoopbackAddress().getHostAddress() + ":"
                + services.getAddress().getPort();
    }

    /** One recorded route resolution: what was asked, and on which thread. */
    private record Asked(NetworkScope scope, String thread) {}

    private static ProxyProvider recording(List<Asked> into) {
        return scope -> {
            into.add(new Asked(scope, Thread.currentThread().getName()));
            return ProxyRoute.direct();
        };
    }

    private static GameStatsSource stats(Map<String, String> threads) {
        return new GameStatsSource() {
            @Override
            public String serverId() {
                return "example.net";
            }

            @Override
            public GameStats fetch(String uuid) {
                threads.put(uuid, Thread.currentThread().getName());
                return new GameStats("example.net", uuid, List.of(), 0L);
            }
        };
    }

    private AltsRuntime.Builder<Object> builder(Path dir) {
        return new AltsRuntime.Builder<Object>()
                .sessionInjector(session -> {})
                .vaultDirectory(() -> dir)
                .mainThread(Runnable::run)
                .toastSink((level, title, description, durationMs) -> {})
                .microsoftAuth(MicrosoftAuthConfig.of("test-client")
                        .withEndpoints(null, null, null, null, null, base() + "/minecraft/profile"));
    }

    /** Signs in {@link #LOGINS} accounts, looks up a name after each, and reads one stats entry. */
    private static void drive(AltsRuntime<Object> alts, String runtime, CountDownLatch go) throws Exception {
        go.await();
        for (int i = 0; i < LOGINS; i++) {
            LoginResult result = alts.loginService()
                    .loginSession("token-" + runtime + "-" + i, LoginMode.ADD)
                    .get(10, TimeUnit.SECONDS);
            assertTrue(result.success(), result.message());
            alts.profileLookup().byName("Nobody" + i);
        }
        alts.secrets().put("feature.api-key", "secret-" + runtime);
    }

    private static GameStats awaitStats(AltsRuntime<Object> alts, String uuid) throws InterruptedException {
        GameStats value = null;
        for (int i = 0; i < 400 && value == null; i++) {
            value = alts.gameStats("example.net").get(uuid);
            if (value == null) {
                Thread.sleep(5);
            }
        }
        return value;
    }

    @Test
    void twoRuntimesDrivenTogetherNeverShareProviderExecutorAccountsOrSecrets() throws Exception {
        List<Asked> askedA = new CopyOnWriteArrayList<>();
        List<Asked> askedB = new CopyOnWriteArrayList<>();
        Map<String, String> statsThreadsA = new ConcurrentHashMap<>();
        Map<String, String> statsThreadsB = new ConcurrentHashMap<>();

        try (AltsRuntime<Object> a = builder(dirA)
                        .proxyProvider(recording(askedA))
                        .executor(hostA)
                        .storeKeyProvider(KEY_A)
                        .gameStatsSource(stats(statsThreadsA))
                        .build();
                AltsRuntime<Object> b = builder(dirB)
                        .proxyProvider(recording(askedB))
                        .executor(hostB)
                        .storeKeyProvider(KEY_B)
                        .gameStatsSource(stats(statsThreadsB))
                        .build()) {
            CountDownLatch go = new CountDownLatch(1);
            ExecutorService drivers = Executors.newFixedThreadPool(2, task -> {
                Thread thread = new Thread(task);
                thread.setDaemon(true);
                return thread;
            });
            Future<?> runA = drivers.submit(() -> {
                Thread.currentThread().setName("driver-a");
                drive(a, "a", go);
                return null;
            });
            Future<?> runB = drivers.submit(() -> {
                Thread.currentThread().setName("driver-b");
                drive(b, "b", go);
                return null;
            });
            go.countDown();
            runA.get(60, TimeUnit.SECONDS);
            runB.get(60, TimeUnit.SECONDS);
            drivers.shutdown();

            assertNotNull(awaitStats(a, "uuid-a"));
            assertNotNull(awaitStats(b, "uuid-b"));

            // Every request a runtime made was routed by its own provider, and by no other.
            assertEquals(2 * LOGINS, askedA.size(), "a's provider saw a's requests, all of them: " + askedA);
            assertEquals(2 * LOGINS, askedB.size(), "b's provider saw b's requests, all of them: " + askedB);
            assertOnlyOwnThreads(askedA, "a");
            assertOnlyOwnThreads(askedB, "b");
            // The sign-in hop resolved off the caller's thread, on the runtime's own executor.
            assertEquals(
                    LOGINS,
                    askedA.stream()
                            .filter(x -> x.thread().startsWith("host-a-"))
                            .count());
            assertEquals(
                    LOGINS,
                    askedB.stream()
                            .filter(x -> x.thread().startsWith("host-b-"))
                            .count());
            assertTrue(statsThreadsA.get("uuid-a").startsWith("host-a-"), "a's stats loaded on a's executor");
            assertTrue(statsThreadsB.get("uuid-b").startsWith("host-b-"), "b's stats loaded on b's executor");
            assertFalse(statsThreadsA.containsKey("uuid-b") || statsThreadsB.containsKey("uuid-a"));

            // Each runtime holds the accounts it signed in, and only those.
            assertEquals(LOGINS, a.store().accounts().size());
            assertEquals(LOGINS, b.store().accounts().size());
            assertTrue(a.store().accounts().stream().allMatch(x -> x.uuid().startsWith("0000000a")));
            assertTrue(b.store().accounts().stream().allMatch(x -> x.uuid().startsWith("0000000b")));
            assertEquals("secret-a", a.secrets().get("feature.api-key"));
            assertEquals("secret-b", b.secrets().get("feature.api-key"));
        }

        // And on disk, under each runtime's own key.
        try (AltsRuntime<Object> crossed = builder(dirA).storeKeyProvider(KEY_B).build()) {
            assertTrue(crossed.store().loadError().isPresent(), "a's files are sealed under a's key");
        }
        try (AltsRuntime<Object> again = builder(dirB).storeKeyProvider(KEY_B).build()) {
            assertEquals(LOGINS, again.store().accounts().size());
            assertEquals("secret-b", again.secrets().get("feature.api-key"));
        }
    }

    private static void assertOnlyOwnThreads(List<Asked> asked, String runtime) {
        for (Asked one : asked) {
            String thread = one.thread();
            assertTrue(
                    thread.startsWith("host-" + runtime + "-") || thread.equals("driver-" + runtime),
                    "runtime " + runtime + "'s provider was asked from a thread not its own: " + thread);
            assertFalse(thread.contains("ForkJoinPool"), "nothing runs on the common pool: " + thread);
        }
    }

    @Test
    void closeLeavesAHostExecutorRunning() throws Exception {
        Map<String, String> threads = new ConcurrentHashMap<>();
        AltsRuntime<Object> alts =
                builder(dirA).executor(hostA).gameStatsSource(stats(threads)).build();
        assertNotNull(awaitStats(alts, "before"));

        alts.close();

        assertFalse(hostA.isShutdown(), "the runtime never shuts a host's executor down");
        AtomicReference<String> ran = new AtomicReference<>();
        hostA.submit(() -> ran.set(Thread.currentThread().getName())).get(5, TimeUnit.SECONDS);
        assertTrue(ran.get().startsWith("host-a-"), "and the host can still use it");
        assertNotNull(awaitStats(alts, "after"), "a cache of the closed runtime still loads on the host's executor");
        assertTrue(threads.get("after").startsWith("host-a-"));
    }

    @Test
    void closeShutsDownTheExecutorTheRuntimeCreated() throws Exception {
        Map<String, String> threads = new ConcurrentHashMap<>();
        AltsRuntime<Object> alts = builder(dirA).gameStatsSource(stats(threads)).build();
        assertNotNull(awaitStats(alts, "before"));
        String thread = threads.get("before");
        assertTrue(thread.startsWith("alts-io-"), "the library's own executor, not the common pool: " + thread);

        alts.close();

        // A load asked for after close is refused by the stopped executor and never reaches the source.
        assertEquals(null, alts.gameStats("example.net").get("after"));
        Thread.sleep(200);
        assertEquals(null, alts.gameStats("example.net").get("after"));
        assertFalse(threads.containsKey("after"), "nothing runs on a closed runtime's own executor");
        Set<String> names = Set.copyOf(threads.values());
        assertTrue(names.stream().noneMatch(name -> name.contains("ForkJoinPool")), names.toString());
    }

    /**
     * A paced run waiting between entries when its runtime closes must end, its report completing,
     * rather than wait for good on a delay its stopped executor would never run; the report still holds
     * every entry, the ones the run never reached reported as cancelled.
     */
    @Test
    void aPacedImportInFlightWhenTheRuntimeClosesStillReports() throws Exception {
        AltsRuntime<Object> alts = builder(dirA).build();
        CompletableFuture<BulkReport> report = alts.bulk()
                .importCredentials(
                        List.of("Alpha1", "Bravo2", "Charl3"),
                        LoginMode.ADD,
                        BulkOptions.of(1, Duration.ofMillis(500), 0, Duration.ofMillis(10), true),
                        null)
                .report();

        alts.close();

        BulkReport done = report.get(5, TimeUnit.SECONDS);
        assertEquals(3, done.results().size(), "every entry is in the report: " + done.results());
        for (int index = 0; index < 3; index++) {
            assertEquals(index, done.results().get(index).index());
        }
        for (int index = 1; index < 3; index++) {
            assertEquals(
                    AltsFailure.Kind.CANCELLED,
                    done.results().get(index).failure().orElseThrow().kind(),
                    "the entries after close never ran, and say why");
        }
    }
}

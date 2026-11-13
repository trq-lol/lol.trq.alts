package lol.trq.alts.account;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import lol.trq.alts.net.TestTransports;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The scheduled claim. Its wait is real-time (a scheduled sleep, then a short spin), so these run against
 * the real clock with small durations rather than a frozen one — a frozen clock would diverge from the
 * real sleep the wait performs. What each test defends: the burst does not fire before its lead time, it
 * stops the instant a change succeeds, and a terminal failure ends it rather than hammering a change that
 * can never land.
 */
class ScheduledClaimTest {

    private HttpServer server;
    private String base;
    private final AtomicInteger status = new AtomicInteger(403);
    private final AtomicInteger changeCalls = new AtomicInteger();
    private final AtomicLong firstCallMillis = new AtomicLong(-1);

    @BeforeEach
    void setUp() throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", exchange -> {
            if ("PUT".equals(exchange.getRequestMethod())) {
                changeCalls.incrementAndGet();
                firstCallMillis.compareAndSet(-1, System.currentTimeMillis());
            }
            exchange.getRequestBody().readAllBytes();
            int code = status.get();
            byte[] body = (code == 200 ? "{\"id\":\"a\",\"name\":\"Wanted\"}" : "{}").getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(code, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
        base = "http://" + InetAddress.getLoopbackAddress().getHostAddress() + ":"
                + server.getAddress().getPort();
    }

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.stop(0);
        }
    }

    private NameService name() {
        return AccountServices.create(TestTransports.direct(), "token", "uuid", new AccountEndpoints(base))
                .name();
    }

    @Test
    void noAttemptFiresBeforeTheLeadTime() throws Exception {
        // Target 400ms out, lead 100ms: nothing may fire before ~300ms from now.
        long start = System.currentTimeMillis();
        Instant target = Instant.now().plusMillis(400);
        status.set(200); // succeeds once it fires, so the run ends promptly

        ClaimOptions options =
                new ClaimOptions(Duration.ofMillis(100), Duration.ofMillis(500), Duration.ofMillis(5), 1, null);
        ClaimResult result = name().claimAt("Wanted", target, options).get();

        assertTrue(result.claimed(), "the change succeeds once the window opens");
        long firstAt = firstCallMillis.get() - start;
        assertTrue(firstAt >= 250, "no attempt may fire before the lead time; first was at " + firstAt + "ms");
    }

    @Test
    void aSuccessfulChangeStopsTheBurst() throws Exception {
        Instant target = Instant.now(); // already due: fire immediately
        status.set(200);

        ClaimOptions options = new ClaimOptions(Duration.ZERO, Duration.ofSeconds(2), Duration.ofMillis(5), 3, null);
        long start = System.currentTimeMillis();
        ClaimResult result = name().claimAt("Wanted", target, options).get();
        long elapsed = System.currentTimeMillis() - start;

        assertTrue(result.claimed(), "a 200 claims the name");
        assertTrue(result.finalResult().success());
        assertTrue(elapsed < 1_500, "the burst stops on success rather than running the whole window: " + elapsed);
        // Three workers may each fire once before they observe the success; it must not keep going.
        assertTrue(changeCalls.get() <= 4, "the burst stops promptly on success, saw " + changeCalls.get());
    }

    @Test
    void aDeadTokenEndsTheRunRatherThanHammering() throws Exception {
        Instant target = Instant.now();
        status.set(401); // unauthorized: terminal, can never succeed

        ClaimOptions options = new ClaimOptions(Duration.ZERO, Duration.ofSeconds(5), Duration.ofMillis(2), 1, null);
        long start = System.currentTimeMillis();
        ClaimResult result = name().claimAt("Wanted", target, options).get();
        long elapsed = System.currentTimeMillis() - start;

        assertFalse(result.claimed());
        assertTrue(elapsed < 1_000, "a terminal failure ends the run rather than filling the window: " + elapsed);
        assertTrue(changeCalls.get() <= 2, "a change that can never land is not retried for the window");
        assertEquals(ClaimResult.StopReason.TERMINAL_FAILURE, result.stopReason());
        assertFalse(result.rateLimited(), "a dead token is not a rate limit");
    }

    /**
     * The regression this guards: a 429 was just another refusal, so three workers a few milliseconds
     * apart kept sending for the whole window to a service that had asked to be left alone.
     */
    @Test
    void aRateLimitStopsEveryWorkerAndIsReportedAsOne() throws Exception {
        Instant target = Instant.now();
        status.set(429);

        ClaimOptions options = new ClaimOptions(Duration.ZERO, Duration.ofSeconds(5), Duration.ofMillis(2), 3, null);
        long start = System.currentTimeMillis();
        ClaimResult result = name().claimAt("Wanted", target, options).get();
        long elapsed = System.currentTimeMillis() - start;

        assertFalse(result.claimed(), "a rate limit is not a claim");
        assertEquals(ClaimResult.StopReason.RATE_LIMITED, result.stopReason());
        assertTrue(result.rateLimited());
        assertEquals(NameChangeResult.Outcome.RATE_LIMITED, result.finalResult().outcome());
        assertTrue(elapsed < 1_000, "the run stops at the limit rather than filling the window: " + elapsed);
        // Each of the three workers may already have an attempt on the wire when the first 429 lands.
        assertTrue(changeCalls.get() <= 3, "no worker keeps sending after the limit, saw " + changeCalls.get());
        assertEquals(changeCalls.get(), result.attempts());

        int after = changeCalls.get();
        Thread.sleep(150);
        assertEquals(after, changeCalls.get(), "nothing is sent once the run has stopped");
    }

    @Test
    void aRunThatExhaustsItsWindowSaysSo() throws Exception {
        Instant target = Instant.now();
        status.set(403); // unavailable: worth retrying until the window closes

        ClaimOptions options = new ClaimOptions(Duration.ZERO, Duration.ofMillis(150), Duration.ofMillis(10), 1, null);
        ClaimResult result = name().claimAt("Wanted", target, options).get();

        assertFalse(result.claimed());
        assertEquals(ClaimResult.StopReason.WINDOW_ELAPSED, result.stopReason());
        assertFalse(result.rateLimited());
        assertTrue(result.attempts() > 1, "an ordinary refusal is retried across the window");
    }

    @Test
    void aSuccessfulClaimReportsClaimedAsItsStopReason() throws Exception {
        status.set(200);

        ClaimResult result = name().claimAt(
                        "Wanted",
                        Instant.now(),
                        new ClaimOptions(Duration.ZERO, Duration.ofSeconds(2), Duration.ofMillis(5), 1, null))
                .get();

        assertTrue(result.claimed());
        assertEquals(ClaimResult.StopReason.CLAIMED, result.stopReason());
    }

    @Test
    void cancellingBeforeTheTargetMeansNoAttemptIsEverSent() throws Exception {
        status.set(200);
        Instant target = Instant.now().plusMillis(300);

        ClaimOptions options = new ClaimOptions(Duration.ZERO, Duration.ofSeconds(2), Duration.ofMillis(5), 3, null);
        CompletableFuture<ClaimResult> claim = name().claimAt("Wanted", target, options);
        Thread.sleep(50);
        assertTrue(claim.cancel(true));

        Thread.sleep(600); // well past the target and into what would have been the window
        assertTrue(claim.isCancelled());
        assertEquals(0, changeCalls.get(), "a cancelled claim must not fire when its target arrives");
    }

    @Test
    void cancellingMidBurstStopsTheWorkers() throws Exception {
        status.set(403); // keeps every worker retrying until told to stop

        ClaimOptions options = new ClaimOptions(Duration.ZERO, Duration.ofSeconds(10), Duration.ofMillis(5), 3, null);
        CompletableFuture<ClaimResult> claim = name().claimAt("Wanted", Instant.now(), options);
        for (int i = 0; i < 200 && changeCalls.get() < 3; i++) {
            Thread.sleep(5);
        }
        assertTrue(changeCalls.get() >= 3, "the burst is under way before it is cancelled");

        claim.cancel(true);
        Thread.sleep(100); // lets any attempt already on the wire land
        int settled = changeCalls.get();
        Thread.sleep(300);

        assertEquals(settled, changeCalls.get(), "no attempt starts after cancellation");
    }

    @Test
    void aResultBuiltWithoutAStopReasonInfersOne() {
        NameChangeResult limited =
                new NameChangeResult(NameChangeResult.Outcome.RATE_LIMITED, null, "slow down", Duration.ofSeconds(1));
        NameChangeResult refused = new NameChangeResult(NameChangeResult.Outcome.UNAUTHORIZED, null, "no", null);
        NameChangeResult taken = new NameChangeResult(NameChangeResult.Outcome.UNAVAILABLE, null, "taken", null);

        assertEquals(ClaimResult.StopReason.CLAIMED, new ClaimResult(true, 1, null).stopReason());
        assertEquals(ClaimResult.StopReason.RATE_LIMITED, new ClaimResult(false, 1, limited).stopReason());
        assertEquals(ClaimResult.StopReason.TERMINAL_FAILURE, new ClaimResult(false, 1, refused).stopReason());
        assertEquals(ClaimResult.StopReason.WINDOW_ELAPSED, new ClaimResult(false, 9, taken).stopReason());
        assertEquals(ClaimResult.StopReason.UNKNOWN, new ClaimResult(false, 0, null).stopReason());
    }
}

package lol.trq.alts.time;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The NTP-corrected clock against a loopback UDP responder. What these defend: reading the time never
 * waits on the network — it is read inside the last milliseconds of a scheduled claim — a server that does
 * not answer is retried on a backoff rather than on every read, a burst of reads starts one measurement,
 * and a datagram that is not a real server reply to this request cannot move the clock.
 */
class NtpTimeSourceTest {

    private static final long NTP_TO_UNIX_SECONDS = 2_208_988_800L;
    private static final long SKEW_MILLIS = 5_000L;

    private DatagramSocket responder;
    private Thread responderThread;
    private final AtomicInteger requests = new AtomicInteger();

    // What the responder does with each request; set by each test before it reads the clock.
    private volatile boolean answer = true;
    private volatile int mode = 4;
    private volatile int stratum = 2;
    private volatile int leap = 0;
    private volatile boolean echoOriginate = true;
    private volatile long replyDelayMillis;

    @BeforeEach
    void setUp() throws IOException {
        responder = new DatagramSocket(0, InetAddress.getLoopbackAddress());
        responderThread = new Thread(this::serve, "ntp-test-responder");
        responderThread.setDaemon(true);
        responderThread.start();
    }

    @AfterEach
    void tearDown() {
        responder.close();
    }

    private void serve() {
        byte[] buffer = new byte[48];
        while (!responder.isClosed()) {
            try {
                DatagramPacket request = new DatagramPacket(buffer, buffer.length);
                responder.receive(request);
                requests.incrementAndGet();
                if (!answer) {
                    continue;
                }
                if (replyDelayMillis > 0) {
                    Thread.sleep(replyDelayMillis);
                }
                byte[] reply = new byte[48];
                reply[0] = (byte) ((leap << 6) | (4 << 3) | mode);
                reply[1] = (byte) stratum;
                if (echoOriginate) {
                    System.arraycopy(buffer, 40, reply, 24, 8);
                }
                long serverNow = System.currentTimeMillis() + SKEW_MILLIS;
                writeTimestamp(reply, 32, serverNow);
                writeTimestamp(reply, 40, serverNow);
                responder.send(new DatagramPacket(reply, reply.length, request.getSocketAddress()));
            } catch (IOException | InterruptedException closed) {
                return;
            }
        }
    }

    private static void writeTimestamp(byte[] buffer, int offset, long millis) {
        long seconds = millis / 1000L + NTP_TO_UNIX_SECONDS;
        long fraction = ((millis % 1000L) * 0x1_0000_0000L) / 1000L;
        for (int i = 3; i >= 0; i--) {
            buffer[offset + i] = (byte) (seconds & 0xff);
            seconds >>>= 8;
        }
        for (int i = 3; i >= 0; i--) {
            buffer[offset + 4 + i] = (byte) (fraction & 0xff);
            fraction >>>= 8;
        }
    }

    /** A source pointed at the responder, with a short timeout and the given failure backoff. */
    private NtpTimeSource source(long retryBaseMillis) {
        return new NtpTimeSource(
                InetAddress.getLoopbackAddress().getHostAddress(),
                responder.getLocalPort(),
                Duration.ofMinutes(15),
                200,
                retryBaseMillis);
    }

    private static long skewOf(NtpTimeSource source) {
        return source.now().toEpochMilli() - System.currentTimeMillis();
    }

    private static void assertCorrected(NtpTimeSource source) {
        long skew = skewOf(source);
        assertTrue(Math.abs(skew - SKEW_MILLIS) < 500, "the clock is corrected by the server's offset, was " + skew);
    }

    @Test
    void anExplicitSyncMeasuresTheOffset() {
        NtpTimeSource source = source(5_000L);

        assertTrue(source.sync());

        assertTrue(source.synced());
        assertCorrected(source);
        assertTrue(Math.abs(source.offset().toMillis() - SKEW_MILLIS) < 500);
    }

    /** The regression this guards: every read before the first sync used to wait out DNS and a timeout. */
    @Test
    void readingTheClockNeverWaitsOnASilentServer() {
        answer = false;
        NtpTimeSource source = source(5_000L);

        long start = System.nanoTime();
        for (int i = 0; i < 10_000; i++) {
            source.now();
        }
        long elapsedMillis = Duration.ofNanos(System.nanoTime() - start).toMillis();

        assertTrue(elapsedMillis < 150, "ten thousand reads must not wait on the network, took " + elapsedMillis);
        assertFalse(source.synced());
        assertTrue(Math.abs(skewOf(source)) < 100, "with no measurement the OS clock is returned uncorrected");
    }

    @Test
    void aReadStartsTheFirstMeasurementInTheBackground() throws Exception {
        NtpTimeSource source = source(5_000L);

        source.now();
        for (int i = 0; i < 200 && !source.synced(); i++) {
            Thread.sleep(10);
        }

        assertTrue(source.synced(), "the first read kicks off a measurement without being asked");
        assertCorrected(source);
        source.now();
        Thread.sleep(50);
        assertEquals(1, requests.get(), "a fresh offset is not re-measured until the interval lapses");
    }

    @Test
    void aSilentServerIsRetriedOnABackoffNotOnEveryRead() throws Exception {
        answer = false;
        NtpTimeSource source = source(60_000L);

        long until = System.currentTimeMillis() + 600;
        while (System.currentTimeMillis() < until) {
            source.now();
            Thread.sleep(1);
        }

        assertEquals(1, requests.get(), "a failed measurement waits out its backoff before the next");
    }

    @Test
    void aFailedMeasurementIsRetriedOnceItsBackoffElapses() throws Exception {
        answer = false;
        NtpTimeSource source = source(50L);
        source.now();
        for (int i = 0; i < 200 && requests.get() < 1; i++) {
            Thread.sleep(10);
        }

        answer = true;
        for (int i = 0; i < 300 && !source.synced(); i++) {
            source.now();
            Thread.sleep(10);
        }

        assertTrue(source.synced(), "the source recovers by itself once the server answers again");
        assertCorrected(source);
    }

    @Test
    void aBurstOfConcurrentReadsStartsOneMeasurement() throws Exception {
        replyDelayMillis = 100;
        NtpTimeSource source = source(5_000L);
        CountDownLatch go = new CountDownLatch(1);
        List<Thread> readers = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            Thread reader = new Thread(() -> {
                try {
                    go.await();
                } catch (InterruptedException interrupted) {
                    return;
                }
                for (int read = 0; read < 2_000; read++) {
                    source.now();
                }
            });
            readers.add(reader);
            reader.start();
        }
        go.countDown();
        for (Thread reader : readers) {
            reader.join();
        }
        for (int i = 0; i < 200 && !source.synced(); i++) {
            Thread.sleep(10);
        }

        assertTrue(source.synced());
        assertEquals(1, requests.get(), "concurrent reads must not each open a socket");
    }

    @Test
    void aReplyThatIsNotAServerReplyIsRejected() {
        mode = 3; // a client-mode packet reflected back
        NtpTimeSource source = source(5_000L);

        assertFalse(source.sync());
        assertFalse(source.synced());
        assertTrue(Math.abs(skewOf(source)) < 100, "a rejected reply must not move the clock");
    }

    @Test
    void aKissOfDeathOrUnsynchronisedServerIsRejected() {
        NtpTimeSource source = source(5_000L);

        stratum = 0;
        assertFalse(source.sync(), "stratum 0 is a refusal, not a time");

        stratum = 16;
        assertFalse(source.sync(), "stratum 16 is unsynchronised");

        stratum = 2;
        leap = 3;
        assertFalse(source.sync(), "a server with its alarm bit set has no time to give");

        assertFalse(source.synced());
    }

    @Test
    void aReplyThatDoesNotEchoTheRequestIsRejected() {
        echoOriginate = false;
        NtpTimeSource source = source(5_000L);

        assertFalse(source.sync());
        assertTrue(Math.abs(skewOf(source)) < 100, "a datagram that answers no request must not move the clock");
    }

    @Test
    void aFailedSyncKeepsTheLastGoodOffset() {
        NtpTimeSource source = source(5_000L);
        assertTrue(source.sync());

        answer = false;
        assertFalse(source.sync());

        assertTrue(source.synced());
        assertCorrected(source);
    }
}

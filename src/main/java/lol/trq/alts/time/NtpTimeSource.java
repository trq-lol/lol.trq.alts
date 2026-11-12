package lol.trq.alts.time;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;

/**
 * A {@link TimeSource} corrected against an NTP server.
 *
 * <p>One clean protocol, one UDP round trip: the offset between the OS clock and the server's is
 * measured and applied, and re-measured on an interval. This is the library's only non-HTTP network
 * shape, and it is deliberately minimal — a single SNTP exchange with the standard four-timestamp offset
 * calculation, not an aggregator over a handful of web time APIs that each answer in a different JSON
 * shape and are slower than the drift they claim to fix.
 *
 * <p><strong>{@link #now()} never touches the network.</strong> It is the OS clock plus the last measured
 * offset — pure arithmetic — because it is read inside the final spin of a scheduled claim, where a DNS
 * lookup or a socket timeout turns a twenty-millisecond approach into seconds and misses the target.
 * Measurement happens off to the side: a {@code now()} that finds the offset due for a re-measure starts
 * one on the common pool and returns at once with what it already has. A failed measurement keeps the
 * last good offset (or zero, if none was ever obtained) and is retried on a growing backoff rather than
 * on every call — a claim should fire on a slightly-off clock rather than not at all. A caller that
 * wants the correction in hand before it schedules anything calls {@link #sync()} first, which does
 * block.
 *
 * <p>A reply is only believed if it is a server reply to this request: server mode, a real stratum, a
 * set clock, and the request's own random nonce echoed back, so a stray or forged datagram cannot move
 * the clock.
 *
 * @author trq
 * @since 1.0.0
 */
public final class NtpTimeSource implements TimeSource {

    /** Seconds between the NTP epoch (1900) and the Unix epoch (1970). */
    private static final long NTP_TO_UNIX_SECONDS = 2_208_988_800L;

    private static final int NTP_PORT = 123;
    private static final int NTP_PACKET_SIZE = 48;
    private static final int TIMEOUT_MILLIS = 3_000;

    /** The server-reply mode; anything else is not an answer to a client request. */
    private static final int MODE_SERVER = 4;

    /** The leap indicator a server sends while its own clock is unsynchronised. */
    private static final int LEAP_UNSYNCHRONISED = 3;

    /** Strata above this are unsynchronised by definition; stratum 0 is a kiss-of-death refusal. */
    private static final int MAX_STRATUM = 15;

    private static final int ORIGINATE_OFFSET = 24;
    private static final int RECEIVE_OFFSET = 32;
    private static final int TRANSMIT_OFFSET = 40;
    private static final int TIMESTAMP_SIZE = 8;

    private static final Duration DEFAULT_RESYNC = Duration.ofMinutes(15);

    /** First retry waits this long after a failed measurement; each further failure doubles it. */
    private static final long RETRY_BASE_MILLIS = 5_000L;

    /** Longest a failing server goes between attempts. */
    private static final long RETRY_MAX_MILLIS = 5 * 60_000L;

    private static final SecureRandom NONCES = new SecureRandom();

    private final String server;
    private final int port;
    private final long resyncNanos;
    private final int timeoutMillis;
    private final long retryBaseMillis;

    /** Serialises measurements, so two never overlap and write their offsets in either order. */
    private final ReentrantLock measuring = new ReentrantLock();

    /** Set while a background measurement is queued or running, so a burst of reads starts only one. */
    private final AtomicBoolean backgroundQueued = new AtomicBoolean();

    private volatile long offsetMillis;
    private volatile boolean synced;

    /** The {@link System#nanoTime()} reading at which the next measurement falls due. */
    private volatile long nextSyncNanos;

    /** Consecutive failed measurements. Read and written under {@link #measuring}. */
    private int failures;

    /**
     * Creates a source correcting against {@code pool.ntp.org}, re-syncing every 15 minutes.
     *
     * @since 1.0.0
     */
    public NtpTimeSource() {
        this("pool.ntp.org", DEFAULT_RESYNC);
    }

    /**
     * Creates a source correcting against a given server on a given interval.
     *
     * @param server the NTP server hostname
     * @param resyncInterval how often to re-measure the offset; null or non-positive means 15 minutes
     * @since 1.0.0
     */
    public NtpTimeSource(String server, Duration resyncInterval) {
        this(server, NTP_PORT, resyncInterval);
    }

    /**
     * Creates a source correcting against a server on a given port — for a host running its own time
     * server somewhere other than the standard port.
     *
     * @param server the NTP server hostname
     * @param port the UDP port the server answers on
     * @param resyncInterval how often to re-measure the offset; null or non-positive means 15 minutes
     * @since 0.12.0
     */
    public NtpTimeSource(String server, int port, Duration resyncInterval) {
        this(server, port, resyncInterval, TIMEOUT_MILLIS, RETRY_BASE_MILLIS);
    }

    // Exists so the timeout and the failure backoff can be exercised without waiting out the real ones.
    NtpTimeSource(String server, int port, Duration resyncInterval, int timeoutMillis, long retryBaseMillis) {
        if (server == null || server.isBlank()) {
            throw new IllegalArgumentException("server must not be blank");
        }
        if (port < 1 || port > 65_535) {
            throw new IllegalArgumentException("port out of range: " + port);
        }
        Duration interval = resyncInterval == null || resyncInterval.isNegative() || resyncInterval.isZero()
                ? DEFAULT_RESYNC
                : resyncInterval;
        this.server = server;
        this.port = port;
        this.resyncNanos = interval.toNanos();
        this.timeoutMillis = timeoutMillis;
        this.retryBaseMillis = retryBaseMillis;
        // Due immediately: the first read starts the first measurement, in the background.
        this.nextSyncNanos = System.nanoTime();
    }

    /**
     * Returns the OS clock corrected by the last measured offset. Never blocks and never touches the
     * network: when the offset is due for a re-measure this starts one in the background and returns
     * with the offset it already has, which is zero until the first measurement lands.
     *
     * @return now, corrected by the last known offset
     */
    @Override
    public Instant now() {
        if (System.nanoTime() - nextSyncNanos >= 0) {
            syncInBackground();
        }
        return Instant.ofEpochMilli(System.currentTimeMillis() + offsetMillis);
    }

    /**
     * Measures the offset now, blocking until the exchange finishes or times out, so a caller about to
     * schedule a time-critical claim has the correction in hand before the first {@link #now()}.
     *
     * <p>Measurements are serialised: a call made while another is in flight waits for it and then
     * measures in turn.
     *
     * @return true if the sync succeeded
     * @since 1.0.0
     */
    public boolean sync() {
        measuring.lock();
        try {
            return measureAndRecord();
        } finally {
            measuring.unlock();
        }
    }

    /**
     * Returns whether an offset has ever been measured. Until it has, {@link #now()} is the uncorrected
     * OS clock.
     *
     * @return true once a measurement has succeeded
     * @since 0.12.0
     */
    public boolean synced() {
        return synced;
    }

    /**
     * Returns the correction currently applied to the OS clock.
     *
     * @return the last measured offset, zero before the first successful measurement
     * @since 0.12.0
     */
    public Duration offset() {
        return Duration.ofMillis(offsetMillis);
    }

    /** Starts a measurement on the common pool unless one is already queued, running, or held by {@link #sync()}. */
    private void syncInBackground() {
        if (!backgroundQueued.compareAndSet(false, true)) {
            return;
        }
        try {
            CompletableFuture.runAsync(() -> {
                try {
                    if (measuring.tryLock()) {
                        try {
                            // Re-checked under the lock: a sync() that just finished already did this work.
                            if (System.nanoTime() - nextSyncNanos >= 0) {
                                measureAndRecord();
                            }
                        } finally {
                            measuring.unlock();
                        }
                    }
                } finally {
                    backgroundQueued.set(false);
                }
            });
        } catch (RuntimeException rejected) {
            backgroundQueued.set(false);
        }
    }

    /**
     * Runs one measurement and records its outcome: the offset and the next regular re-sync on success,
     * a backed-off retry on failure. Called with {@link #measuring} held.
     *
     * @return true if the measurement succeeded
     */
    private boolean measureAndRecord() {
        try {
            offsetMillis = measureOffset();
            synced = true;
            failures = 0;
            nextSyncNanos = System.nanoTime() + resyncNanos;
            return true;
        } catch (IOException | RuntimeException failed) {
            long delay = Math.min(retryBaseMillis << Math.min(failures, 6), RETRY_MAX_MILLIS);
            failures++;
            nextSyncNanos = System.nanoTime() + Duration.ofMillis(delay).toNanos();
            return false;
        }
    }

    /**
     * Runs one SNTP exchange and returns the offset to add to the local clock, by the standard
     * four-timestamp formula {@code ((receive - originate) + (transmit - destination)) / 2}.
     *
     * <p>The request's transmit field carries a random nonce rather than the local time: the server only
     * has to echo it, the local send time is kept here, and a reply that does not echo it was not an
     * answer to this request.
     *
     * @return the offset in milliseconds
     * @throws IOException if the exchange failed or the reply was not a valid server reply
     */
    private long measureOffset() throws IOException {
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(timeoutMillis);
            InetAddress address = InetAddress.getByName(server);
            // Connected, so a datagram from any other address or port is dropped before it is read.
            socket.connect(address, port);

            byte[] request = new byte[NTP_PACKET_SIZE];
            request[0] = 0b00_100_011; // leap 0, version 4, mode 3 (client)
            byte[] nonce = new byte[TIMESTAMP_SIZE];
            NONCES.nextBytes(nonce);
            System.arraycopy(nonce, 0, request, TRANSMIT_OFFSET, TIMESTAMP_SIZE);

            long originate = System.currentTimeMillis();
            socket.send(new DatagramPacket(request, request.length));

            byte[] reply = new byte[NTP_PACKET_SIZE];
            DatagramPacket response = new DatagramPacket(reply, reply.length);
            socket.receive(response);
            long destination = System.currentTimeMillis();

            validate(reply, response.getLength(), nonce);

            long receive = readTimestamp(reply, RECEIVE_OFFSET);
            long transmit = readTimestamp(reply, TRANSMIT_OFFSET);
            return ((receive - originate) + (transmit - destination)) / 2;
        }
    }

    /**
     * Rejects a datagram that is not a usable server reply to this request.
     *
     * @param reply the received bytes
     * @param length how many of them were received
     * @param nonce the value the request carried in its transmit field
     * @throws IOException if the reply is short, is not a server reply, comes from an unsynchronised or
     *     refusing server, or does not echo the request
     */
    private static void validate(byte[] reply, int length, byte[] nonce) throws IOException {
        if (length < NTP_PACKET_SIZE) {
            throw new IOException("short NTP reply");
        }
        int leap = (reply[0] >> 6) & 0x3;
        int mode = reply[0] & 0x7;
        int stratum = reply[1] & 0xff;
        if (mode != MODE_SERVER) {
            throw new IOException("NTP reply is not a server reply");
        }
        if (stratum == 0 || stratum > MAX_STRATUM || leap == LEAP_UNSYNCHRONISED) {
            throw new IOException("NTP server is unsynchronised or refused the request");
        }
        if (!Arrays.equals(reply, ORIGINATE_OFFSET, ORIGINATE_OFFSET + TIMESTAMP_SIZE, nonce, 0, TIMESTAMP_SIZE)) {
            throw new IOException("NTP reply does not answer this request");
        }
        boolean transmitSet = false;
        for (int i = TRANSMIT_OFFSET; i < TRANSMIT_OFFSET + TIMESTAMP_SIZE; i++) {
            transmitSet |= reply[i] != 0;
        }
        if (!transmitSet) {
            throw new IOException("NTP reply carries no transmit time");
        }
    }

    private static long readTimestamp(byte[] buffer, int offset) {
        long seconds = 0;
        for (int i = 0; i < 4; i++) {
            seconds = (seconds << 8) | (buffer[offset + i] & 0xffL);
        }
        long fraction = 0;
        for (int i = 4; i < 8; i++) {
            fraction = (fraction << 8) | (buffer[offset + i] & 0xffL);
        }
        long millis = (seconds - NTP_TO_UNIX_SECONDS) * 1000L;
        millis += (fraction * 1000L) / 0x1_0000_0000L;
        return millis;
    }
}

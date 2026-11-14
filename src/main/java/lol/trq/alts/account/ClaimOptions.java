package lol.trq.alts.account;

import java.time.Duration;
import java.util.Objects;
import lol.trq.alts.time.SystemTimeSource;
import lol.trq.alts.time.TimeSource;

/**
 * How a scheduled name claim paces itself around its target instant.
 *
 * <p>A final class rather than a record since 1.0.0, so a later setting is an addition and not a break:
 * start from {@link #defaults()} or {@link #of}, and derive a copy with {@link #withTimeSource}. Two options are
 * equal when every setting is.
 *
 * @author trq
 * @since 0.11.0
 */
public final class ClaimOptions {

    private final Duration leadTime;
    private final Duration window;
    private final Duration attemptSpacing;
    private final int concurrency;
    private final TimeSource timeSource;

    /** Validates the shape and fills a missing time source with the system clock. */
    private ClaimOptions(
            Duration leadTime, Duration window, Duration attemptSpacing, int concurrency, TimeSource timeSource) {
        if (concurrency < 1) {
            throw new IllegalArgumentException("concurrency must be at least 1");
        }
        this.leadTime = nonNegative(leadTime);
        this.window = window == null || window.isNegative() || window.isZero() ? Duration.ofSeconds(10) : window;
        this.attemptSpacing = nonNegative(attemptSpacing);
        this.concurrency = concurrency;
        this.timeSource = timeSource == null ? new SystemTimeSource() : timeSource;
    }

    /**
     * Returns sensible defaults: begin 300 ms early, try for 10 s, 8 ms between a worker's attempts, three
     * chains, system clock.
     *
     * @return the default options
     * @since 0.11.0
     */
    public static ClaimOptions defaults() {
        return of(Duration.ofMillis(300), Duration.ofSeconds(10), Duration.ofMillis(8), 3, new SystemTimeSource());
    }

    /**
     * Creates options with every setting given.
     *
     * @param leadTime how far before the target to begin firing; null or negative is zero
     * @param window how long to keep trying after the target before giving up; null, zero or negative is
     *     ten seconds
     * @param attemptSpacing the least gap between two attempts on one worker; null or negative is zero
     * @param concurrency how many attempt chains run in parallel; at least 1
     * @param timeSource the clock the schedule reads, or null for the system clock
     * @return the options
     * @throws IllegalArgumentException if {@code concurrency} is below 1
     * @since 1.0.0
     */
    public static ClaimOptions of(
            Duration leadTime, Duration window, Duration attemptSpacing, int concurrency, TimeSource timeSource) {
        return new ClaimOptions(leadTime, window, attemptSpacing, concurrency, timeSource);
    }

    /**
     * Returns how far before the target to begin firing, absorbing clock skew and request latency.
     *
     * @return the lead time, never negative
     * @since 0.11.0
     */
    public Duration leadTime() {
        return leadTime;
    }

    /**
     * Returns how long to keep trying after the target before giving up.
     *
     * @return the window, always positive
     * @since 0.11.0
     */
    public Duration window() {
        return window;
    }

    /**
     * Returns the least gap between two attempts on one worker.
     *
     * @return the spacing, never negative
     * @since 0.11.0
     */
    public Duration attemptSpacing() {
        return attemptSpacing;
    }

    /**
     * Returns how many attempt chains run in parallel.
     *
     * @return the concurrency, at least 1
     * @since 0.11.0
     */
    public int concurrency() {
        return concurrency;
    }

    /**
     * Returns the clock the schedule reads, for correcting OS drift.
     *
     * @return the time source, never {@code null}
     * @since 0.11.0
     */
    public TimeSource timeSource() {
        return timeSource;
    }

    /**
     * Returns a copy reading the given time source.
     *
     * @param value the time source
     * @return a copy with the time source replaced
     * @since 0.11.0
     */
    public ClaimOptions withTimeSource(TimeSource value) {
        return new ClaimOptions(leadTime, window, attemptSpacing, concurrency, value);
    }

    /**
     * Returns whether {@code o} holds the same settings; the time sources compare by their own equality.
     *
     * @param o the object to compare
     * @return true when every setting is equal
     * @since 0.11.0
     */
    @Override
    public boolean equals(Object o) {
        return o instanceof ClaimOptions other
                && concurrency == other.concurrency
                && leadTime.equals(other.leadTime)
                && window.equals(other.window)
                && attemptSpacing.equals(other.attemptSpacing)
                && timeSource.equals(other.timeSource);
    }

    /**
     * Returns a hash over every setting, consistent with {@link #equals(Object)}.
     *
     * @return the hash
     * @since 0.11.0
     */
    @Override
    public int hashCode() {
        return Objects.hash(leadTime, window, attemptSpacing, concurrency, timeSource);
    }

    /**
     * Returns every setting, in the form the record printed them.
     *
     * @return a description
     * @since 0.11.0
     */
    @Override
    public String toString() {
        return "ClaimOptions[leadTime=" + leadTime + ", window=" + window + ", attemptSpacing=" + attemptSpacing
                + ", concurrency=" + concurrency + ", timeSource=" + timeSource + "]";
    }

    private static Duration nonNegative(Duration value) {
        return value == null || value.isNegative() ? Duration.ZERO : value;
    }
}

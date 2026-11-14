package lol.trq.alts.bulk;

import java.time.Duration;
import java.util.Objects;
import java.util.Optional;

/**
 * How a bulk run should pace itself.
 *
 * <p>A final class rather than a record since 1.0.0, so a later setting is an addition and not a break:
 * start from {@link #defaults()} or {@link #of}, and derive copies with the {@code withX} methods. Two options are
 * equal when every setting is.
 *
 * @author trq
 * @since 0.9.0
 */
public final class BulkOptions {

    private final int concurrency;
    private final Duration minSpacing;
    private final int maxRetries;
    private final Duration retryBaseDelay;
    private final boolean stopOnRateLimit;
    private final Optional<String> routeTag;

    /**
     * Validates the shape, since a zero concurrency would hang the run and a negative delay is a bug.
     */
    private BulkOptions(
            int concurrency,
            Duration minSpacing,
            int maxRetries,
            Duration retryBaseDelay,
            boolean stopOnRateLimit,
            Optional<String> routeTag) {
        if (concurrency < 1) {
            throw new IllegalArgumentException("concurrency must be at least 1");
        }
        if (maxRetries < 0) {
            throw new IllegalArgumentException("maxRetries cannot be negative");
        }
        if (routeTag.isPresent() && routeTag.get().isBlank()) {
            throw new IllegalArgumentException("a route tag must not be blank");
        }
        this.concurrency = concurrency;
        this.minSpacing = nonNegative(minSpacing);
        this.maxRetries = maxRetries;
        this.retryBaseDelay = nonNegative(retryBaseDelay);
        this.stopOnRateLimit = stopOnRateLimit;
        this.routeTag = routeTag;
    }

    /**
     * Returns the defaults: four at a time, a quarter second apart, two retries growing from two
     * seconds, stopping if the service says to slow down.
     *
     * <p>They are deliberately unambitious. The failure this pacing exists to avoid is a source address
     * earning a longer ban, and the cost of being slower than necessary is a sweep that takes another
     * minute.
     *
     * @return the default options
     * @since 0.9.0
     */
    public static BulkOptions defaults() {
        return of(4, Duration.ofMillis(250), 2, Duration.ofSeconds(2), true);
    }

    /**
     * Creates options with every pacing setting given and no route tag.
     *
     * @param concurrency how many entries may be in flight at once; at least 1
     * @param minSpacing the least time between two entries starting; null or negative is zero
     * @param maxRetries how many times a retryable failure is retried, beyond the first attempt; not negative
     * @param retryBaseDelay the delay a retry grows from when the service asked for nothing specific; null or
     *     negative is zero
     * @param stopOnRateLimit whether a rate limit ends the run rather than being waited out
     * @return the options
     * @throws IllegalArgumentException if {@code concurrency} is below 1 or {@code maxRetries} is negative
     * @since 1.0.0
     */
    public static BulkOptions of(
            int concurrency, Duration minSpacing, int maxRetries, Duration retryBaseDelay, boolean stopOnRateLimit) {
        return new BulkOptions(concurrency, minSpacing, maxRetries, retryBaseDelay, stopOnRateLimit, Optional.empty());
    }

    /**
     * Returns how many entries may be in flight at once.
     *
     * @return the concurrency, at least 1
     * @since 0.9.0
     */
    public int concurrency() {
        return concurrency;
    }

    /**
     * Returns the least time between two entries <em>starting</em>.
     *
     * @return the spacing, never negative
     * @since 0.9.0
     */
    public Duration minSpacing() {
        return minSpacing;
    }

    /**
     * Returns how many times a retryable failure is retried, beyond the first attempt.
     *
     * @return the retry count, never negative
     * @since 0.9.0
     */
    public int maxRetries() {
        return maxRetries;
    }

    /**
     * Returns the delay a retry grows from when the service asked for nothing specific.
     *
     * @return the base delay, never negative
     * @since 0.9.0
     */
    public Duration retryBaseDelay() {
        return retryBaseDelay;
    }

    /**
     * Returns whether a rate limit ends the run rather than being waited out; a limit counts whether or not
     * the service said how long to wait.
     *
     * @return whether the run stops on a rate limit
     * @since 0.9.0
     */
    public boolean stopOnRateLimit() {
        return stopOnRateLimit;
    }

    /**
     * Returns the route tag an import's sign-ins carry, on every request, to the proxy provider; see
     * {@link #withRouteTag(String)}.
     *
     * @return the tag, or empty for none
     * @since 1.0.0
     */
    public Optional<String> routeTag() {
        return routeTag;
    }

    /**
     * Returns a copy running the given number of entries at once.
     *
     * @param value how many entries may be in flight
     * @return a copy with the concurrency replaced
     * @since 0.9.0
     */
    public BulkOptions withConcurrency(int value) {
        return new BulkOptions(value, minSpacing, maxRetries, retryBaseDelay, stopOnRateLimit, routeTag);
    }

    /**
     * Returns a copy that keeps going through a rate limit, waiting each one out: for as long as the
     * service asked, or on a growing delay when it named no wait. The whole run pauses for the wait, and
     * an entry that is still limited after {@code maxRetries} waits fails.
     *
     * <p>Worth knowing what that trades: continuing to send to a service that has asked you to stop is
     * how an address earns a longer ban than the one it is already serving.
     *
     * @return a copy that does not stop early
     * @since 0.9.0
     */
    public BulkOptions withoutStoppingOnRateLimit() {
        return new BulkOptions(concurrency, minSpacing, maxRetries, retryBaseDelay, false, routeTag);
    }

    /**
     * Returns a copy whose import signs every credential in through
     * {@code AltLoginService.routed(tag)}: every request of every entry, on every hop, reaches the proxy
     * provider with {@code tag} as its {@code NetworkScope.routeTag()}. For a host that pins accounts to
     * proxies and wants a batch of new accounts to sign in through one it chose. Only
     * {@code importCredentials} reads it; the runs over stored accounts name the account on every hop
     * instead.
     *
     * <p>{@code null} does not clear the tag: it throws. Options without a tag are the ones built without
     * this call.
     *
     * @param tag the route tag
     * @return a copy with the tag set
     * @throws NullPointerException if {@code tag} is null
     * @throws IllegalArgumentException if {@code tag} is blank
     * @since 1.0.0
     */
    public BulkOptions withRouteTag(String tag) {
        return new BulkOptions(concurrency, minSpacing, maxRetries, retryBaseDelay, stopOnRateLimit, Optional.of(tag));
    }

    /**
     * Returns whether {@code o} holds the same settings.
     *
     * @param o the object to compare
     * @return true when every setting is equal
     * @since 0.9.0
     */
    @Override
    public boolean equals(Object o) {
        return o instanceof BulkOptions other
                && concurrency == other.concurrency
                && maxRetries == other.maxRetries
                && stopOnRateLimit == other.stopOnRateLimit
                && minSpacing.equals(other.minSpacing)
                && retryBaseDelay.equals(other.retryBaseDelay)
                && routeTag.equals(other.routeTag);
    }

    /**
     * Returns a hash over every setting, consistent with {@link #equals(Object)}.
     *
     * @return the hash
     * @since 0.9.0
     */
    @Override
    public int hashCode() {
        return Objects.hash(concurrency, minSpacing, maxRetries, retryBaseDelay, stopOnRateLimit, routeTag);
    }

    /**
     * Returns every setting, in the form the record printed them.
     *
     * @return a description
     * @since 0.9.0
     */
    @Override
    public String toString() {
        return "BulkOptions[concurrency=" + concurrency + ", minSpacing=" + minSpacing + ", maxRetries="
                + maxRetries + ", retryBaseDelay=" + retryBaseDelay + ", stopOnRateLimit=" + stopOnRateLimit
                + ", routeTag=" + routeTag + "]";
    }

    private static Duration nonNegative(Duration value) {
        return value == null || value.isNegative() ? Duration.ZERO : value;
    }
}

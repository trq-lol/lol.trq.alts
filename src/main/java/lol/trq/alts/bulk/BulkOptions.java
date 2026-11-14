package lol.trq.alts.bulk;

import java.time.Duration;
import java.util.Optional;

/**
 * How a bulk run should pace itself.
 *
 * @param concurrency how many entries may be in flight at once
 * @param minSpacing the least time between two entries <em>starting</em>
 * @param maxRetries how many times a retryable failure is retried, beyond the first attempt
 * @param retryBaseDelay the delay a retry grows from when the service asked for nothing specific
 * @param stopOnRateLimit whether a rate limit ends the run rather than being waited out; a limit counts
 *     whether or not the service said how long to wait
 * @param routeTag the route tag an import's sign-ins carry, on every request, to the proxy provider, or
 *     empty for none; see {@link #withRouteTag(String)}. Added in 1.0.0
 * @author trq
 * @since 0.9.0
 */
public record BulkOptions(
        int concurrency,
        Duration minSpacing,
        int maxRetries,
        Duration retryBaseDelay,
        boolean stopOnRateLimit,
        Optional<String> routeTag) {

    /**
     * Validates the shape, since a zero concurrency would hang the run and a negative delay is a bug.
     *
     * @since 1.0.0
     */
    public BulkOptions {
        if (concurrency < 1) {
            throw new IllegalArgumentException("concurrency must be at least 1");
        }
        if (maxRetries < 0) {
            throw new IllegalArgumentException("maxRetries cannot be negative");
        }
        minSpacing = nonNegative(minSpacing);
        retryBaseDelay = nonNegative(retryBaseDelay);
        routeTag = routeTag == null ? Optional.empty() : routeTag;
        if (routeTag.isPresent() && routeTag.get().isBlank()) {
            throw new IllegalArgumentException("a route tag must not be blank");
        }
    }

    /**
     * Creates options with no route tag: the shape before the tag existed.
     *
     * @param concurrency how many entries may be in flight at once
     * @param minSpacing the least time between two entries starting
     * @param maxRetries how many times a retryable failure is retried, beyond the first attempt
     * @param retryBaseDelay the delay a retry grows from when the service asked for nothing specific
     * @param stopOnRateLimit whether a rate limit ends the run rather than being waited out
     * @since 0.9.0
     */
    public BulkOptions(
            int concurrency, Duration minSpacing, int maxRetries, Duration retryBaseDelay, boolean stopOnRateLimit) {
        this(concurrency, minSpacing, maxRetries, retryBaseDelay, stopOnRateLimit, Optional.empty());
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
        return new BulkOptions(4, Duration.ofMillis(250), 2, Duration.ofSeconds(2), true);
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
     * @param tag the route tag
     * @return a copy with the tag set
     * @throws NullPointerException if {@code tag} is null
     * @throws IllegalArgumentException if {@code tag} is blank
     * @since 1.0.0
     */
    public BulkOptions withRouteTag(String tag) {
        return new BulkOptions(concurrency, minSpacing, maxRetries, retryBaseDelay, stopOnRateLimit, Optional.of(tag));
    }

    private static Duration nonNegative(Duration value) {
        return value == null || value.isNegative() ? Duration.ZERO : value;
    }
}

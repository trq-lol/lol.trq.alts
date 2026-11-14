package lol.trq.alts.internal.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Optional;
import org.junit.jupiter.api.Test;

/** The bearer-token cache's expiry: renewed {@link TokenCache#SLACK_MILLIS} early, with no wrap-round. */
class TokenCacheTest {

    private static final byte[] HOST = new byte[32];
    private static final byte[] SUBJECT = new byte[] {1, 2, 3};
    private static final String ORIGIN = "https://vault.example:443";

    @Test
    void aTokenIsHandedOutUntilTheSlackBeforeItsExpiry() {
        TokenCache cache = new TokenCache();
        cache.put(HOST, ORIGIN, SUBJECT, "t", 1_000_000);
        assertEquals(Optional.of("t"), cache.get(HOST, ORIGIN, SUBJECT, 1_000_000 - TokenCache.SLACK_MILLIS - 1));
        assertTrue(cache.get(HOST, ORIGIN, SUBJECT, 1_000_000 - TokenCache.SLACK_MILLIS)
                .isEmpty());
    }

    @Test
    void anExpiryNearTheBottomOfTheRangeIsExpiredNotGoodForEver() {
        TokenCache cache = new TokenCache();
        // expiresAt minus the slack would wrap round to a far-future instant.
        for (long expiresAt :
                new long[] {Long.MIN_VALUE, Long.MIN_VALUE + 1, Long.MIN_VALUE + TokenCache.SLACK_MILLIS - 1}) {
            cache.put(HOST, ORIGIN, SUBJECT, "t", expiresAt);
            assertTrue(cache.get(HOST, ORIGIN, SUBJECT, 0).isEmpty(), "expired at " + expiresAt);
            assertTrue(cache.get(HOST, ORIGIN, SUBJECT, Long.MIN_VALUE).isEmpty(), "expired at " + expiresAt);
        }
    }

    @Test
    void anExpiryAtTheSlackBoundaryDoesNotWrap() {
        TokenCache cache = new TokenCache();
        cache.put(HOST, ORIGIN, SUBJECT, "t", Long.MIN_VALUE + TokenCache.SLACK_MILLIS);
        assertTrue(cache.get(HOST, ORIGIN, SUBJECT, Long.MIN_VALUE).isEmpty());
        assertTrue(cache.get(HOST, ORIGIN, SUBJECT, 0).isEmpty());
    }
}

package lol.trq.alts;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.EnumSet;
import java.util.Optional;
import java.util.Set;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.auth.XstsError;
import org.junit.jupiter.api.Test;

/** Pins the one failure value: its invariants, and what {@link AltsFailure#retryable()} promises. */
class AltsFailureTest {

    /** A failure whose stated wait, if any, ends at {@code retryAt}. */
    private static AltsFailure ending(Kind kind, Duration retryAfter, Instant retryAt) {
        return new AltsFailure(
                kind, "m", Optional.ofNullable(retryAfter), Optional.empty(), Optional.ofNullable(retryAt));
    }

    @Test
    void aNetworkFailureWithNoStatedWaitIsRetryable() {
        assertTrue(AltsFailure.of(Kind.NETWORK, "down").retryable());
    }

    @Test
    void aStatedWaitIsHonouredForEveryRetryableKind() {
        Instant now = Instant.now();
        for (Kind kind : new Kind[] {Kind.NETWORK, Kind.RATE_LIMITED}) {
            Duration fiveMinutes = Duration.ofMinutes(5);
            assertFalse(
                    ending(kind, fiveMinutes, now.plus(Duration.ofMinutes(1))).retryable(), kind + ": not yet");
            assertTrue(ending(kind, fiveMinutes, now.minusSeconds(1)).retryable(), kind + ": the wait has ended");
            assertTrue(ending(kind, fiveMinutes, now).retryable(), kind + ": at the instant it ends");
            assertFalse(
                    AltsFailure.of(kind, "m", Duration.ofMinutes(5)).retryable(),
                    kind + ": a wait stated just now has not ended");
            assertTrue(AltsFailure.of(kind, "m", Duration.ZERO).retryable(), kind + ": a zero wait ends at once");
        }
    }

    @Test
    void aRateLimitThatStatedNoWaitIsNotRetryable() {
        assertFalse(AltsFailure.rateLimited("slow down", null).retryable());
    }

    @Test
    void noOtherKindIsRetryable() {
        Set<Kind> retryable = EnumSet.of(Kind.NETWORK, Kind.RATE_LIMITED);
        for (Kind kind : Kind.values()) {
            if (!retryable.contains(kind)) {
                assertFalse(AltsFailure.of(kind, "m").retryable(), kind.name());
                assertFalse(ending(kind, Duration.ZERO, Instant.EPOCH).retryable(), kind + " with an ended wait");
            }
        }
    }

    @Test
    void aStatedWaitEndsThatLongAfterTheFailureIsMade() {
        Instant before = Instant.now();
        AltsFailure limited = AltsFailure.rateLimited("slow", Duration.ofSeconds(40));
        Instant after = Instant.now();

        assertEquals(Optional.of(Duration.ofSeconds(40)), limited.retryAfter());
        Instant end = limited.retryAt().orElseThrow();
        assertFalse(end.isBefore(before.plusSeconds(40)));
        assertFalse(end.isAfter(after.plusSeconds(40)));
    }

    @Test
    void aFailureWithNoStatedWaitRecordsNoTimeSoEqualityIgnoresWhenItWasMade() throws Exception {
        AltsFailure first = AltsFailure.of(Kind.NOT_FOUND, "none");
        Thread.sleep(5);
        AltsFailure second = AltsFailure.of(Kind.NOT_FOUND, "none");

        assertEquals(Optional.empty(), first.retryAt());
        assertEquals(first, second);
    }

    @Test
    void theFactoriesCarryWhatTheyWereGiven() {
        AltsFailure denied = AltsFailure.xboxDenied("denied", XstsError.CHILD_ACCOUNT);
        AltsFailure plain = AltsFailure.of(Kind.NOT_FOUND, "none");

        assertEquals(Kind.XBOX_DENIED, denied.kind());
        assertEquals(Optional.of(XstsError.CHILD_ACCOUNT), denied.xstsError());
        assertEquals(Optional.empty(), plain.retryAfter());
        assertEquals(Optional.empty(), plain.xstsError());
    }

    @Test
    void aRelabelledFailureKeepsEverythingButItsMessage() {
        AltsFailure original = ending(Kind.RATE_LIMITED, Duration.ofSeconds(3), Instant.EPOCH);
        AltsFailure relabelled = original.withMessage("Refresh: rate limited");
        assertEquals(
                new AltsFailure(
                        Kind.RATE_LIMITED,
                        "Refresh: rate limited",
                        original.retryAfter(),
                        original.xstsError(),
                        Optional.of(Instant.EPOCH)),
                relabelled);
    }

    @Test
    void anXboxReasonTravelsWithXboxDeniedOnly() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new AltsFailure(
                        Kind.UNAUTHORIZED, "m", Optional.empty(), Optional.of(XstsError.UNKNOWN), Optional.empty()));
    }

    @Test
    void theEndOfAWaitIsKnownExactlyWhenAWaitWasStated() {
        assertThrows(IllegalArgumentException.class, () -> ending(Kind.NETWORK, Duration.ofSeconds(1), null));
        assertThrows(IllegalArgumentException.class, () -> ending(Kind.NETWORK, null, Instant.now()));
    }

    @Test
    void aNegativeWaitAndAMissingComponentAreRefused() {
        assertThrows(
                IllegalArgumentException.class, () -> ending(Kind.RATE_LIMITED, Duration.ofSeconds(-1), Instant.now()));
        assertThrows(NullPointerException.class, () -> AltsFailure.of(null, "m"));
        assertThrows(NullPointerException.class, () -> AltsFailure.of(Kind.UNKNOWN, null));
        assertThrows(
                NullPointerException.class,
                () -> new AltsFailure(Kind.UNKNOWN, "m", Optional.empty(), Optional.empty(), null));
    }

    @Test
    void theExceptionCarriesTheFailureAndItsMessage() {
        AltsFailure failure = AltsFailure.of(Kind.STORAGE, "accounts.dat: could not be written");
        IOException cause = new IOException("C:/secret/path");
        AltsException exception = new AltsException(failure, cause);

        assertSame(failure, exception.failure());
        assertEquals(Kind.STORAGE, exception.kind());
        assertEquals(failure.message(), exception.getMessage());
        assertSame(cause, exception.getCause());
        assertEquals(Kind.CANCELLED, new AltsException(Kind.CANCELLED, "closed").kind());
        assertThrows(NullPointerException.class, () -> new AltsException((AltsFailure) null));
    }

    @Test
    void theKindSetIsTheOneTheChangelogDocuments() {
        assertEquals(
                java.util.List.of(
                        "NETWORK",
                        "RATE_LIMITED",
                        "UNAUTHORIZED",
                        "REAUTH_REQUIRED",
                        "NOT_ENTITLED",
                        "NOT_FOUND",
                        "XBOX_DENIED",
                        "DECLINED",
                        "TIMED_OUT",
                        "CANCELLED",
                        "INVALID_INPUT",
                        "CONFLICT",
                        "NOT_CONFIGURED",
                        "STORAGE",
                        "CRYPTO",
                        "PROTOCOL",
                        "UNKNOWN"),
                java.util.Arrays.stream(Kind.values()).map(Kind::name).toList());
    }

    /** A wait ending past the last instant there is ends at that instant rather than failing to build. */
    @Test
    void aStatedWaitBeyondTheLastInstantEndsAtIt() {
        AltsFailure failure = AltsFailure.rateLimited("slow down", Duration.ofSeconds(Long.MAX_VALUE));

        assertEquals(Optional.of(Duration.ofSeconds(Long.MAX_VALUE)), failure.retryAfter());
        assertEquals(Optional.of(Instant.MAX), failure.retryAt());
        assertFalse(failure.retryable());
    }
}

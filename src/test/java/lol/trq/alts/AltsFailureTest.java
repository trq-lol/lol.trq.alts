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

    private static AltsFailure at(Kind kind, Duration retryAfter, Instant at) {
        return new AltsFailure(kind, "m", Optional.ofNullable(retryAfter), Optional.empty(), at);
    }

    @Test
    void aNetworkFailureIsAlwaysRetryable() {
        assertTrue(AltsFailure.of(Kind.NETWORK, "down").retryable());
        assertTrue(at(Kind.NETWORK, Duration.ofHours(1), Instant.now()).retryable());
    }

    @Test
    void aRateLimitIsRetryableOnlyOnceItsStatedWaitHasPassed() {
        Instant now = Instant.now();
        assertFalse(at(Kind.RATE_LIMITED, Duration.ofMinutes(5), now).retryable(), "the wait has not passed");
        assertFalse(
                at(Kind.RATE_LIMITED, Duration.ofMinutes(5), now.minus(Duration.ofMinutes(4)))
                        .retryable(),
                "four of five minutes have passed");
        assertTrue(
                at(Kind.RATE_LIMITED, Duration.ofMinutes(5), now.minus(Duration.ofMinutes(6)))
                        .retryable(),
                "the wait has passed since the failure was recorded");
        assertTrue(at(Kind.RATE_LIMITED, Duration.ZERO, now).retryable(), "a zero wait has passed at once");
    }

    @Test
    void aRateLimitThatStatedNoWaitIsNotRetryable() {
        assertFalse(AltsFailure.rateLimited("slow down", null).retryable());
        assertFalse(at(Kind.RATE_LIMITED, null, Instant.EPOCH).retryable(), "however long ago it was recorded");
    }

    @Test
    void noOtherKindIsRetryable() {
        Set<Kind> retryable = EnumSet.of(Kind.NETWORK, Kind.RATE_LIMITED);
        for (Kind kind : Kind.values()) {
            if (!retryable.contains(kind)) {
                assertFalse(at(kind, Duration.ZERO, Instant.EPOCH).retryable(), kind.name());
            }
        }
    }

    @Test
    void theFactoriesRecordTheFailureNowWithWhatTheyWereGiven() {
        Instant before = Instant.now();
        AltsFailure limited = AltsFailure.rateLimited("slow", Duration.ofSeconds(40));
        AltsFailure denied = AltsFailure.xboxDenied("denied", XstsError.CHILD_ACCOUNT);
        AltsFailure plain = AltsFailure.of(Kind.NOT_FOUND, "none");

        assertEquals(Kind.RATE_LIMITED, limited.kind());
        assertEquals(Optional.of(Duration.ofSeconds(40)), limited.retryAfter());
        assertEquals(Kind.XBOX_DENIED, denied.kind());
        assertEquals(Optional.of(XstsError.CHILD_ACCOUNT), denied.xstsError());
        assertEquals(Optional.empty(), plain.retryAfter());
        assertEquals(Optional.empty(), plain.xstsError());
        assertFalse(plain.at().isBefore(before));
        assertFalse(plain.at().isAfter(Instant.now()));
    }

    @Test
    void aRelabelledFailureKeepsEverythingButItsMessage() {
        AltsFailure original = at(Kind.RATE_LIMITED, Duration.ofSeconds(3), Instant.EPOCH);
        AltsFailure relabelled = original.withMessage("Refresh: rate limited");
        assertEquals(
                new AltsFailure(
                        Kind.RATE_LIMITED,
                        "Refresh: rate limited",
                        original.retryAfter(),
                        original.xstsError(),
                        Instant.EPOCH),
                relabelled);
    }

    @Test
    void anXboxReasonTravelsWithXboxDeniedOnly() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new AltsFailure(
                        Kind.UNAUTHORIZED, "m", Optional.empty(), Optional.of(XstsError.UNKNOWN), Instant.now()));
    }

    @Test
    void aNegativeWaitAndAMissingComponentAreRefused() {
        assertThrows(
                IllegalArgumentException.class, () -> at(Kind.RATE_LIMITED, Duration.ofSeconds(-1), Instant.now()));
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
}

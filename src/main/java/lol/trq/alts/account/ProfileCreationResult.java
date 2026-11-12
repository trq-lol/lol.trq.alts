package lol.trq.alts.account;

import java.time.Duration;

/**
 * What creating a profile came to.
 *
 * <p>Like a name change, this is a mutation whose refusals are outcomes rather than errors: a taken name
 * and an account that owns nothing are both things a host shows the user, and they call for different
 * next steps.
 *
 * @param outcome the classified result
 * @param profile the new profile on success, or {@code null}
 * @param message a short human-readable description
 * @param retryAfter how long the service asked the caller to wait, or {@code null}
 * @author trq
 * @since 0.12.0
 */
public record ProfileCreationResult(Outcome outcome, PlayerProfile profile, String message, Duration retryAfter) {

    /**
     * How a profile creation ended.
     *
     * @author trq
     * @since 0.12.0
     */
    public enum Outcome {
        /** The profile was created; {@link ProfileCreationResult#profile()} carries it. */
        CREATED,

        /**
         * The name is not a valid Minecraft name — the wrong length or an illegal character. Decided
         * locally when the name could never be accepted, so no request is spent on it.
         */
        INVALID_NAME,

        /** The name is already taken. */
        DUPLICATE,

        /** The name is blocked or reserved and cannot be claimed. */
        NOT_ALLOWED,

        /** The account owns no Java edition, so it cannot have a profile. */
        NOT_ENTITLED,

        /** The token was refused. */
        UNAUTHORIZED,

        /** The service asked the caller to slow down; {@link ProfileCreationResult#retryAfter()} may say how long. */
        RATE_LIMITED,

        /** The service refused for another reason, or failed; the message carries what it said. */
        FAILED
    }

    /**
     * Returns whether the profile was created.
     *
     * @return true on success
     * @since 0.12.0
     */
    public boolean success() {
        return outcome == Outcome.CREATED;
    }
}

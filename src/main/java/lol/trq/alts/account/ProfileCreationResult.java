package lol.trq.alts.account;

import java.util.Objects;
import java.util.Optional;
import lol.trq.alts.AltsFailure;

/**
 * What creating a profile came to.
 *
 * <p>Like a name change, this is a mutation whose refusals are outcomes rather than errors: a taken name
 * and a blocked one are things a host shows the user. An account that owns nothing, a refused token, a
 * rate limit and an unreachable service are failures: {@link Outcome#FAILED}, with {@link #failure()}
 * saying which kind and carrying any stated wait.
 *
 * @param outcome the classified result
 * @param profile the new profile on success, or {@code null}
 * @param message a short description built by the library; on a failure, the failure's message
 * @param failure why the creation failed, present exactly when the outcome is {@link Outcome#FAILED};
 *     carried since 1.0.0 in place of the former wait
 * @author trq
 * @since 0.12.0
 */
public record ProfileCreationResult(
        Outcome outcome, PlayerProfile profile, String message, Optional<AltsFailure> failure) {

    /**
     * How a profile creation ended.
     *
     * @author trq
     * @since 0.12.0
     */
    public enum Outcome {
        /**
         * The profile was created; {@link ProfileCreationResult#profile()} carries it.
         *
         * @since 0.12.0
         */
        CREATED,

        /**
         * The name is not a valid Minecraft name — the wrong length or an illegal character. Decided
         * locally when the name could never be accepted, so no request is spent on it.
         *
         * @since 0.12.0
         */
        INVALID_NAME,

        /**
         * The name is already taken.
         *
         * @since 0.12.0
         */
        DUPLICATE,

        /**
         * The name is blocked or reserved and cannot be claimed.
         *
         * @since 0.12.0
         */
        NOT_ALLOWED,

        /**
         * The creation failed; {@link ProfileCreationResult#failure()} says why.
         *
         * @since 0.12.0
         */
        FAILED
    }

    /**
     * Checks that a failure is present exactly on {@link Outcome#FAILED}.
     *
     * @throws NullPointerException if {@code outcome} or {@code failure} is null
     * @throws IllegalArgumentException if the failure does not match the outcome
     * @since 1.0.0
     */
    public ProfileCreationResult {
        Objects.requireNonNull(outcome, "outcome");
        Objects.requireNonNull(failure, "failure");
        if ((outcome == Outcome.FAILED) != failure.isPresent()) {
            throw new IllegalArgumentException("a failure is carried by FAILED and by nothing else");
        }
    }

    /**
     * Creates a failed result whose message is the failure's.
     *
     * @param failure why the creation failed
     * @return the result
     * @since 1.0.0
     */
    public static ProfileCreationResult failed(AltsFailure failure) {
        return new ProfileCreationResult(Outcome.FAILED, null, failure.message(), Optional.of(failure));
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

package lol.trq.alts.account;

import java.util.Objects;
import java.util.Optional;
import lol.trq.alts.AltsFailure;

/**
 * What a name change came to.
 *
 * <p>The mutation's status carries the meaning: a 400 is a malformed or invalid name and a 403 is the
 * name being unavailable or the account on cooldown, which are outcomes a host shows the user. A refused
 * token, an account that owns no Java to rename, a rate limit and an unreachable service are failures:
 * {@link Outcome#FAILED}, with {@link #failure()} saying which kind and carrying any stated wait.
 *
 * @param outcome the classified result
 * @param profile the updated profile on success, or {@code null}
 * @param message a short description built by the library; on a failure, the failure's message
 * @param failure why the change failed, present exactly when the outcome is {@link Outcome#FAILED};
 *     carried since 1.0.0 in place of the former wait
 * @author trq
 * @since 0.11.0
 */
public record NameChangeResult(Outcome outcome, PlayerProfile profile, String message, Optional<AltsFailure> failure) {

    /**
     * How a name change ended.
     *
     * @author trq
     * @since 0.11.0
     */
    public enum Outcome {
        /**
         * The name was changed; {@link NameChangeResult#profile()} carries the updated profile.
         *
         * @since 0.11.0
         */
        CHANGED,

        /**
         * The name is malformed or invalid (too long, illegal characters).
         *
         * @since 0.11.0
         */
        INVALID_NAME,

        /**
         * The name is unavailable, or the account is within its name-change cooldown.
         *
         * @since 0.11.0
         */
        UNAVAILABLE,

        /**
         * The change failed; {@link NameChangeResult#failure()} says why.
         *
         * @since 0.11.0
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
    public NameChangeResult {
        Objects.requireNonNull(outcome, "outcome");
        Objects.requireNonNull(failure, "failure");
        if ((outcome == Outcome.FAILED) != failure.isPresent()) {
            throw new IllegalArgumentException("a failure is carried by FAILED and by nothing else");
        }
    }

    /**
     * Creates a failed result whose message is the failure's.
     *
     * @param failure why the change failed
     * @return the result
     * @since 1.0.0
     */
    public static NameChangeResult failed(AltsFailure failure) {
        return new NameChangeResult(Outcome.FAILED, null, failure.message(), Optional.of(failure));
    }

    /**
     * Returns whether the name was changed.
     *
     * @return true on success
     * @since 0.11.0
     */
    public boolean success() {
        return outcome == Outcome.CHANGED;
    }
}

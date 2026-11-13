package lol.trq.alts.auth;

import java.util.Objects;
import java.util.Optional;
import lol.trq.alts.AltsFailure;
import lol.trq.alts.model.AltAccount;

/**
 * What a sign-in came to: the account it produced, or the failure that stopped it.
 *
 * <p>Every sign-in route returns one; none of them throws at the caller or completes its future
 * exceptionally. A host branches on {@code failure().map(AltsFailure::kind)}; the message is for showing.
 *
 * @param account the signed-in account, or {@code null} when the sign-in failed
 * @param failure why the sign-in failed, or empty when it succeeded
 * @author trq
 * @since 1.0.0
 */
public record LoginResult(AltAccount account, Optional<AltsFailure> failure) {

    /**
     * Checks that a result is exactly one of a success with an account or a failure without one.
     *
     * @throws NullPointerException if {@code failure} is null, or a success carries no account
     * @throws IllegalArgumentException if a failure carries an account
     */
    public LoginResult {
        Objects.requireNonNull(failure, "failure");
        if (failure.isEmpty()) {
            Objects.requireNonNull(account, "a successful sign-in carries its account");
        } else if (account != null) {
            throw new IllegalArgumentException("a failed sign-in carries no account");
        }
    }

    /**
     * Creates a successful result.
     *
     * @param account the account that was signed in
     * @return the result
     * @since 1.0.0
     */
    public static LoginResult success(AltAccount account) {
        return new LoginResult(account, Optional.empty());
    }

    /**
     * Creates a failed result.
     *
     * @param failure why the sign-in failed
     * @return the result
     * @since 1.0.0
     */
    public static LoginResult failure(AltsFailure failure) {
        return new LoginResult(null, Optional.of(failure));
    }

    /**
     * Creates a failed result with a fresh failure of {@code kind}.
     *
     * @param kind what kind of failure it is
     * @param message a short description built by the library
     * @return the result
     * @since 1.0.0
     */
    public static LoginResult failure(AltsFailure.Kind kind, String message) {
        return failure(AltsFailure.of(kind, message));
    }

    /**
     * Returns whether the sign-in succeeded.
     *
     * @return true when there is no failure
     * @since 1.0.0
     */
    public boolean success() {
        return failure.isEmpty();
    }

    /**
     * Returns a short description to show: the failure's message, or a fixed phrase on success. Never
     * branch on it.
     *
     * @return the description
     * @since 1.0.0
     */
    public String message() {
        return failure.map(AltsFailure::message).orElse("Logged in successfully");
    }
}

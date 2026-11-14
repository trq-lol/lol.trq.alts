package lol.trq.alts.auth;

import java.util.Objects;
import java.util.Optional;
import lol.trq.alts.AltsFailure;
import lol.trq.alts.model.AltAccount;

/**
 * What an account is worth right now, without having logged into it.
 *
 * <p>The {@code account} carried back is the record as it now stands — renewed credentials included — so
 * a caller updates its own view from one place rather than reassembling it.
 *
 * <p>{@link #state()} says what the account is; {@link #failure()} says why it is not usable, in the
 * library's one failure model. A rate limit, for one, is the state {@link State#UNREACHABLE} with a
 * failure of kind {@link AltsFailure.Kind#RATE_LIMITED}, whose {@link AltsFailure#retryAfter()} carries
 * the wait when the service stated one.
 *
 * @param account the account this describes, possibly with freshly issued credentials
 * @param state the machine-readable outcome
 * @param failure why the account is not usable, or empty when it is; carried since 1.0.0 in place of the
 *     former reason, message and wait
 * @author trq
 * @since 0.8.0
 */
public record AccountStatus(AltAccount account, State state, Optional<AltsFailure> failure) {

    /**
     * What an account can be.
     *
     * @author trq
     * @since 0.8.0
     */
    public enum State {
        /**
         * The stored credentials work as they are.
         *
         * @since 0.8.0
         */
        VALID,

        /**
         * The credentials were spent and have been renewed; the account carries the new ones.
         *
         * @since 0.8.0
         */
        RENEWED,

        /**
         * The stored token is not usable, and renewal has not been attempted. The account holds a
         * refresh token, so {@link AltAccountService#refresh(AltAccount)} is the next step rather than a
         * fresh interactive login. Only a read-only {@link AltAccountService#check(AltAccount)} reports
         * this.
         *
         * @since 0.8.0
         */
        EXPIRED,

        /**
         * The credentials are permanently spent and the account needs a fresh interactive login. Any
         * refresh token held for it has been discarded.
         *
         * @since 0.8.0
         */
        REAUTH_REQUIRED,

        /**
         * The credentials authenticated, but the account cannot be played as it stands: it has no
         * Minecraft profile ({@link AltsFailure.Kind#NOT_ENTITLED}), or Xbox Live refused to authorize it
         * ({@link AltsFailure.Kind#XBOX_DENIED}). Neither retrying nor re-authenticating helps.
         *
         * @since 0.8.0
         */
        NOT_ENTITLED,

        /**
         * The service could not be reached, failed ({@link AltsFailure.Kind#NETWORK}), or is throttling
         * the caller ({@link AltsFailure.Kind#RATE_LIMITED}). Nothing was spent. An outage is worth a
         * retry; a rate limit is worth a wait, and the failure's kind says which.
         *
         * @since 0.8.0
         */
        UNREACHABLE,

        /**
         * Something else went wrong, which the library could not classify.
         *
         * @since 0.8.0
         */
        UNKNOWN
    }

    /**
     * Checks that a usable state carries no failure and every other state carries one.
     *
     * @throws NullPointerException if {@code state} or {@code failure} is null
     * @throws IllegalArgumentException if the failure does not match the state
     * @since 1.0.0
     */
    public AccountStatus {
        Objects.requireNonNull(state, "state");
        Objects.requireNonNull(failure, "failure");
        boolean usable = state == State.VALID || state == State.RENEWED;
        if (usable != failure.isEmpty()) {
            throw new IllegalArgumentException(
                    usable ? "a usable account carries no failure" : "an unusable account carries its failure");
        }
    }

    /**
     * Returns whether the account can be logged into as it stands.
     *
     * @return true if the state is {@link State#VALID} or {@link State#RENEWED}
     * @since 0.8.0
     */
    public boolean usable() {
        return state == State.VALID || state == State.RENEWED;
    }

    /**
     * Returns a short description to show: the failure's message, or a fixed phrase when the account is
     * usable. Never branch on it.
     *
     * @return the description
     * @since 0.8.0
     */
    public String message() {
        return failure.map(AltsFailure::message).orElse(state == State.RENEWED ? "Session renewed" : "Session is live");
    }

    /**
     * Creates a status for an account whose stored credentials work.
     *
     * @param account the account
     * @return a valid status
     * @since 0.8.0
     */
    public static AccountStatus valid(AltAccount account) {
        return new AccountStatus(account, State.VALID, Optional.empty());
    }

    /**
     * Creates a status for an account that was renewed.
     *
     * @param account the account carrying the freshly issued credentials
     * @return a renewed status
     * @since 0.8.0
     */
    public static AccountStatus renewed(AltAccount account) {
        return new AccountStatus(account, State.RENEWED, Optional.empty());
    }

    /**
     * Creates a status for an account that cannot be used as it stands.
     *
     * @param account the account this describes
     * @param state the outcome; not {@link State#VALID} or {@link State#RENEWED}
     * @param failure why the account is not usable
     * @return a failed status
     * @since 1.0.0
     */
    public static AccountStatus failure(AltAccount account, State state, AltsFailure failure) {
        return new AccountStatus(account, state, Optional.of(failure));
    }
}

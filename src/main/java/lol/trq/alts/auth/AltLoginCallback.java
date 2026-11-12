package lol.trq.alts.auth;

import lol.trq.alts.model.AltAccount;

/**
 * A functional callback for the outcome of asynchronous login operations, letting the client react to
 * successful authentications or display error messages without blocking the render thread.
 *
 * @author trq
 * @since 0.1.0
 */
@FunctionalInterface
public interface AltLoginCallback {

    /**
     * Invoked when a login operation has completed, regardless of whether it succeeded.
     *
     * @param result the result object containing the status, message, and account data
     */
    void onResult(LoginResult result);

    /**
     * Why a login attempt failed, in a form a host can branch on. Matching on the human-readable
     * message is not viable: it is subject to obfuscation and localization.
     *
     * @author trq
     * @since 0.6.0
     */
    enum FailureReason {
        /** The attempt succeeded; carried by every successful result. */
        NONE,

        /** The attempt failed for a reason the library cannot classify. */
        UNKNOWN,

        /**
         * The stored credentials are permanently spent and the account needs a fresh interactive
         * login. Any refresh token held for the account has been discarded.
         */
        REAUTH_REQUIRED,

        /** The supplied token was empty, malformed, or rejected as invalid. */
        INVALID_TOKEN,

        /** The attempt could not reach the authentication service, or the service failed. Retryable. */
        NETWORK,

        /** The flow requires host configuration that was not supplied. */
        NOT_CONFIGURED,

        /**
         * The credentials authenticated, but the account has no Minecraft profile — it does not own the
         * game, or it owns it and has never chosen a username. Retrying and re-authenticating are both
         * pointless; the account has to be entitled, or a name chosen, elsewhere.
         *
         * @since 0.8.0
         */
        NOT_ENTITLED,

        /**
         * A service answered that the caller is sending too many requests. The credential is untouched;
         * the remedy is to wait, or to send the request from a different address.
         *
         * @since 0.12.0
         */
        RATE_LIMITED,

        /**
         * The sign-in succeeded but Xbox Live refused to authorize the account. The result's
         * {@link LoginResult#xstsError()} says why, and each cause is something the user fixes at a
         * specific place rather than by retrying.
         *
         * @since 0.12.0
         */
        XBOX_DENIED,

        /**
         * The user refused the sign-in — declined the consent page, or declined the device-code
         * request.
         *
         * @since 0.12.0
         */
        DECLINED,

        /**
         * An interactive sign-in was not finished in time: the device code expired, or the browser
         * login was never completed. Starting again issues a fresh challenge.
         *
         * @since 0.12.0
         */
        TIMED_OUT
    }

    /**
     * An immutable representation of a login attempt's outcome.
     *
     * @param success whether the authentication was successful
     * @param message a descriptive message (success notification or error reason)
     * @param account the authenticated account object, or null if the attempt failed
     * @param reason the machine-readable cause, {@link FailureReason#NONE} on success; added in 0.6.0
     * @param xstsError why Xbox Live refused to authorize the account, or {@code null} when the attempt
     *     did not fail at that step; added in 0.12.0
     * @author trq
     * @since 0.1.0
     */
    record LoginResult(boolean success, String message, AltAccount account, FailureReason reason, XstsError xstsError) {

        /**
         * Creates a result that carries no Xbox Live refusal. This is the canonical constructor as it
         * stood before {@code xstsError} existed, kept so positional construction still compiles.
         *
         * @param success whether the authentication was successful
         * @param message a descriptive message
         * @param account the authenticated account object, or null if the attempt failed
         * @param reason the machine-readable cause
         * @since 0.12.0
         */
        public LoginResult(boolean success, String message, AltAccount account, FailureReason reason) {
            this(success, message, account, reason, null);
        }

        /**
         * Creates a successful login result.
         *
         * @param account the account that was successfully authenticated
         * @return a new result indicating success
         */
        public static LoginResult success(AltAccount account) {
            return new LoginResult(true, "Logged in successfully", account, FailureReason.NONE);
        }

        /**
         * Creates a failed login result with no classified cause.
         *
         * @param reason the reason why the authentication failed
         * @return a new result indicating an unclassified failure
         */
        public static LoginResult failure(String reason) {
            return failure(reason, FailureReason.UNKNOWN);
        }

        /**
         * Creates a failed login result carrying a machine-readable cause.
         *
         * @param message the human-readable reason why the authentication failed
         * @param cause the classified cause, for hosts that branch on the outcome
         * @return a new result indicating failure
         * @since 0.6.0
         */
        public static LoginResult failure(String message, FailureReason cause) {
            return new LoginResult(false, message, null, cause);
        }

        /**
         * Creates a failed login result carrying the reason Xbox Live refused the account.
         *
         * @param message the human-readable reason why the authentication failed
         * @param cause the classified cause, for hosts that branch on the outcome
         * @param xstsError why Xbox Live refused, or {@code null} when it did not
         * @return a new result indicating failure
         * @since 0.12.0
         */
        public static LoginResult failure(String message, FailureReason cause, XstsError xstsError) {
            return new LoginResult(false, message, null, cause, xstsError);
        }
    }
}

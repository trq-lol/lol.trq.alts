package lol.trq.alts;

import com.google.gson.annotations.SerializedName;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import lol.trq.alts.auth.XstsError;

/**
 * What went wrong, in the one form every part of the library reports it: a sign-in, a check or a
 * refresh, an account service, a bulk entry, a store.
 *
 * <p>A host branches on {@link #kind()}, never on {@link #message()}. The message is built by the
 * library for a person to read: it never repeats a transport exception's own text, never carries a
 * token, a cookie, a code or a filesystem path, and its wording may change in any release.
 *
 * <p>A failure appears in one of two places. Where the caller is expected to branch on the outcome
 * (a sign-in, an account's status, a name change, a profile creation, a name claim, a bulk entry) it is
 * carried by the result as an {@code Optional<AltsFailure>}. Everywhere else it is thrown, or completes a
 * future exceptionally, as an {@link AltsException} carrying it.
 *
 * <p>When the service stated a wait, {@link #retryAt()} is the instant it ends: the moment the failure
 * was made plus {@link #retryAfter()}. {@link #retryable()} compares it with the current time, so a
 * failure a host holds on to becomes retryable once the wait has passed, without the host keeping its
 * own clock beside it. A failure with no stated wait records no time, so two such failures with the same
 * kind and message are equal whenever they were made.
 *
 * @param kind what kind of failure this is; the thing to branch on
 * @param message a short description built by the library, safe to show and to log
 * @param retryAfter how long the service asked the caller to wait before trying again, when it said
 * @param xstsError why Xbox Live refused the account; present only on {@link Kind#XBOX_DENIED}
 * @param retryAt when the stated wait ends; present exactly when {@code retryAfter} is
 * @author trq
 * @since 1.0.0
 */
public record AltsFailure(
        @SerializedName("kind") Kind kind,
        @SerializedName("message") String message,
        @SerializedName("retryAfter") Optional<Duration> retryAfter,
        @SerializedName("xstsError") Optional<XstsError> xstsError,
        @SerializedName("retryAt") Optional<Instant> retryAt) {

    /**
     * What kind of failure happened. One enum for the whole library, so a host writes its {@code switch}
     * once; it ends in {@link #UNKNOWN} so a default branch covers a constant a later release adds.
     *
     * <p>Three of them must never be confused, because their remedies are opposite: a refusal
     * ({@link #UNAUTHORIZED}, {@link #REAUTH_REQUIRED}) says the credential is the problem; an
     * unreachable service ({@link #NETWORK}) says retry; a throttle ({@link #RATE_LIMITED}) says wait.
     * Sending the user through a browser sign-in to fix an outage, or retrying into a rate limit, is
     * what conflating them costs.
     *
     * @author trq
     * @since 1.0.0
     */
    public enum Kind {
        /**
         * The service could not be reached, the connection failed or timed out, or it answered with a
         * server error ({@code 5xx}, {@code 408}). Nothing was spent; retrying is the remedy.
         */
        NETWORK,

        /**
         * The service answered that the caller is sending too many requests ({@code 429}). Nothing was
         * spent; the remedy is to wait, for {@link AltsFailure#retryAfter()} when the service said how
         * long, or to send from a different address.
         */
        RATE_LIMITED,

        /**
         * The credential was refused, or is empty or malformed: a token the service answered {@code 401}
         * or {@code 403} to, a cookie that produced no sign-in. A stored refresh token, if there is one,
         * may still renew the account.
         */
        UNAUTHORIZED,

        /**
         * The credential is permanently spent (the token endpoint stated {@code invalid_grant}) and a
         * fresh interactive sign-in is the only remedy. Where the library held it for a stored account,
         * the refresh token has been discarded.
         */
        REAUTH_REQUIRED,

        /**
         * The credential authenticated, but the account has no Minecraft profile or does not own the
         * game. Neither retrying nor signing in again changes it.
         */
        NOT_ENTITLED,

        /** The thing asked for does not exist ({@code 404}): no such player, no such resource. */
        NOT_FOUND,

        /**
         * The sign-in succeeded but Xbox Live refused to authorize the account;
         * {@link AltsFailure#xstsError()} says why, and each cause is fixed by the user at a specific
         * place rather than by retrying.
         */
        XBOX_DENIED,

        /** The user refused an interactive sign-in: declined the consent page or the device code. */
        DECLINED,

        /**
         * An interactive sign-in was not finished in time: the device code expired, or the browser
         * sign-in was never completed. Starting again issues a fresh challenge.
         */
        TIMED_OUT,

        /**
         * The operation was stopped on the caller's side rather than failing: the host cancelled it, the
         * runtime was closed, or the executor it was to run on refused it. Retrying on the same runtime
         * does not help once it is closed.
         */
        CANCELLED,

        /**
         * What the caller supplied could not be used, and nothing was sent: an unreadable credential
         * text, a skin that is not a skin, an argument out of range.
         */
        INVALID_INPUT,

        /**
         * The request conflicts with the current state: a service answered {@code 409}, or a store file
         * is held by another runtime, in this process or another.
         */
        CONFLICT,

        /**
         * The operation needs host configuration that was not supplied, such as Microsoft sign-in without
         * a {@code MicrosoftAuthConfig}, or a device-code sign-in without a prompt.
         */
        NOT_CONFIGURED,

        /** A store file could not be read or written. */
        STORAGE,

        /** A cryptographic operation failed: a key did not unwrap, a ciphertext did not authenticate. */
        CRYPTO,

        /**
         * A service answered with something that is not what its protocol promises: a body that is not
         * JSON, a field missing or of the wrong type.
         */
        PROTOCOL,

        /** A failure the library could not classify. */
        UNKNOWN
    }

    /**
     * Checks the components: everything is required, an Xbox Live reason only travels with
     * {@link Kind#XBOX_DENIED}, and the end of a wait is known exactly when a wait was stated.
     *
     * @throws NullPointerException if a component is null
     * @throws IllegalArgumentException if {@code xstsError} is present on another kind, {@code retryAfter}
     *     is negative, or {@code retryAt} is present without {@code retryAfter} or absent with it
     */
    public AltsFailure {
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(message, "message");
        Objects.requireNonNull(retryAfter, "retryAfter");
        Objects.requireNonNull(xstsError, "xstsError");
        Objects.requireNonNull(retryAt, "retryAt");
        if (xstsError.isPresent() && kind != Kind.XBOX_DENIED) {
            throw new IllegalArgumentException("an Xbox Live reason belongs to XBOX_DENIED only");
        }
        if (retryAfter.isPresent() && retryAfter.get().isNegative()) {
            throw new IllegalArgumentException("a stated wait is not negative");
        }
        if (retryAt.isPresent() != retryAfter.isPresent()) {
            throw new IllegalArgumentException("the end of a wait is known exactly when a wait was stated");
        }
    }

    /**
     * Builds a failure whose stated wait, if any, starts now.
     *
     * @param kind the kind
     * @param message the message
     * @param retryAfter the stated wait, or {@code null}
     * @param xstsError the Xbox Live reason, or {@code null}
     * @return the failure
     */
    private static AltsFailure made(Kind kind, String message, Duration retryAfter, XstsError xstsError) {
        Optional<Duration> wait = Optional.ofNullable(retryAfter);
        return new AltsFailure(
                kind,
                message,
                wait,
                Optional.ofNullable(xstsError),
                wait.map(stated -> Instant.now().plus(stated)));
    }

    /**
     * Creates a failure of {@code kind} with no stated wait and no Xbox Live reason.
     *
     * @param kind what kind of failure it is
     * @param message a short description built by the library
     * @return the failure
     * @since 1.0.0
     */
    public static AltsFailure of(Kind kind, String message) {
        return made(kind, message, null, null);
    }

    /**
     * Creates a {@link Kind#RATE_LIMITED} failure; a stated wait starts now.
     *
     * @param message a short description built by the library
     * @param retryAfter how long the service asked the caller to wait, or {@code null} when it did not say
     * @return the failure
     * @since 1.0.0
     */
    public static AltsFailure rateLimited(String message, Duration retryAfter) {
        return made(Kind.RATE_LIMITED, message, retryAfter, null);
    }

    /**
     * Creates a failure of {@code kind} that may carry a stated wait, which starts now. A server error can
     * state one as well as a throttle.
     *
     * @param kind what kind of failure it is
     * @param message a short description built by the library
     * @param retryAfter how long the service asked the caller to wait, or {@code null} when it did not say
     * @return the failure
     * @since 1.0.0
     */
    public static AltsFailure of(Kind kind, String message, Duration retryAfter) {
        return made(kind, message, retryAfter, null);
    }

    /**
     * Creates an {@link Kind#XBOX_DENIED} failure.
     *
     * @param message a short description built by the library
     * @param error why Xbox Live refused the account
     * @return the failure
     * @since 1.0.0
     */
    public static AltsFailure xboxDenied(String message, XstsError error) {
        return made(Kind.XBOX_DENIED, message, null, Objects.requireNonNull(error, "error"));
    }

    /**
     * Returns the same failure under another message, for a caller that adds context (the route's name,
     * say) to a failure a lower layer classified. Kind, wait, end of the wait and Xbox Live reason are
     * kept.
     *
     * @param message the new message, built by the library
     * @return the relabelled failure
     * @since 1.0.0
     */
    public AltsFailure withMessage(String message) {
        return new AltsFailure(kind, message, retryAfter, xstsError, retryAt);
    }

    /**
     * Returns whether trying the same thing again, unchanged, may succeed now.
     *
     * <p>A stated wait is honoured for every kind that can be retried: when {@link #retryAt()} is present,
     * {@link Kind#NETWORK} and {@link Kind#RATE_LIMITED} are retryable once now is at or past it. With no
     * stated wait, {@link Kind#NETWORK} is retryable, and {@link Kind#RATE_LIMITED} is not, since retrying
     * into an unknown limit is how a short limit becomes a long one, and a host picks its own back-off for
     * it. Every other kind is not: the credential, the input, the configuration or the user's choice has
     * to change first.
     *
     * @return true when an unchanged retry may now succeed
     * @since 1.0.0
     */
    public boolean retryable() {
        return switch (kind) {
            case NETWORK, RATE_LIMITED ->
                retryAt.map(end -> !Instant.now().isBefore(end)).orElse(kind == Kind.NETWORK);
            default -> false;
        };
    }
}

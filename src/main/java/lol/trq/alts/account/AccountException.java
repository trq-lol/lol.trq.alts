package lol.trq.alts.account;

import java.io.Serial;
import java.time.Duration;

/**
 * Thrown when an account-services call fails in a way the caller should see rather than a {@code null}
 * papering over it — a refused token, a malformed request, an unreachable service.
 *
 * <p>Carries the HTTP status when there was one ({@code 0} otherwise), so a caller can branch on a 401
 * (re-auth) versus a 429 (back off) versus a transport failure without matching a message string.
 *
 * @author trq
 * @since 1.0.0
 */
public class AccountException extends Exception {

    @Serial
    private static final long serialVersionUID = 1L;

    /** The HTTP status, or zero when the failure was not an HTTP response. */
    private final int status;

    /** How long the service asked the caller to wait, or null. */
    private final Duration retryAfter;

    /**
     * Creates an exception carrying an HTTP status.
     *
     * @param message the failure description
     * @param status the HTTP status, or {@code 0} when the failure was not an HTTP response
     * @since 1.0.0
     */
    public AccountException(String message, int status) {
        this(message, status, null);
    }

    /**
     * Creates an exception carrying an HTTP status and the wait the service asked for.
     *
     * @param message the failure description
     * @param status the HTTP status, or {@code 0} when the failure was not an HTTP response
     * @param retryAfter how long the service asked the caller to wait, or {@code null}
     * @since 0.12.0
     */
    public AccountException(String message, int status, Duration retryAfter) {
        super(message);
        this.status = status;
        this.retryAfter = retryAfter;
    }

    /**
     * Creates an exception wrapping an underlying failure.
     *
     * @param message the failure description
     * @param cause the underlying failure
     * @since 1.0.0
     */
    public AccountException(String message, Throwable cause) {
        super(message, cause);
        this.status = 0;
        this.retryAfter = null;
    }

    /**
     * Returns the HTTP status this failure carried, or {@code 0} when it was not an HTTP response.
     *
     * @return the status
     * @since 1.0.0
     */
    public int status() {
        return status;
    }

    /**
     * Returns whether the token was refused (401 or 403), so the account needs re-authenticating.
     *
     * @return true if the status is 401 or 403
     * @since 1.0.0
     */
    public boolean tokenRefused() {
        return status == 401 || status == 403;
    }

    /**
     * Returns whether the service asked the caller to slow down (429).
     *
     * @return true if the status is 429
     * @since 1.0.0
     */
    public boolean rateLimited() {
        return status == 429;
    }

    /**
     * Returns whether the service answered that the thing asked for does not exist (404). On the profile
     * read that is an account with no Minecraft profile — the token is fine and re-authenticating will
     * not change the answer.
     *
     * @return true if the status is 404
     * @since 0.12.0
     */
    public boolean notFound() {
        return status == 404;
    }

    /**
     * Returns how long the service asked the caller to wait before trying again, when it said.
     *
     * @return the stated wait, or {@code null} when none was given
     * @since 0.12.0
     */
    public Duration retryAfter() {
        return retryAfter;
    }
}

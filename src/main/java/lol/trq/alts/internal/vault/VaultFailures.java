package lol.trq.alts.internal.vault;

import java.io.Serial;
import java.time.Duration;
import java.util.Optional;
import java.util.Set;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure;
import lol.trq.alts.AltsFailure.Kind;

/**
 * The failures of the vault client. Every message is built here from a fixed phrase: none quotes a host's
 * answer, an input, a key or a plaintext.
 *
 * <p>A host refusal is reported by its status and, when it is one of the codes of AVP SPEC 10.4, by that
 * code. The human-readable {@code error} of the error object is never parsed and never shown, and a code
 * outside the table is treated as absent. The status and code travel as the exception's {@linkplain
 * Refusal cause}, so the client can decide a retry from them.
 *
 * <ul>
 *   <li>{@code 400} and any unlisted {@code 4xx}: {@link Kind#PROTOCOL}.
 *   <li>{@code 401}, {@code 403}: {@link Kind#UNAUTHORIZED}.
 *   <li>{@code 404}: {@link Kind#NOT_FOUND}.
 *   <li>{@code 409}: {@link Kind#CONFLICT}.
 *   <li>{@code 413}: {@link Kind#INVALID_INPUT}.
 *   <li>{@code 422}: {@link Kind#NETWORK}, since the host is still fetching what it lacks.
 *   <li>{@code 429}: {@link Kind#RATE_LIMITED}, with the stated {@code Retry-After}.
 *   <li>{@code 408} and {@code 5xx}: {@link Kind#NETWORK}.
 * </ul>
 *
 * @author trq
 * @since 1.0.0
 */
public final class VaultFailures {

    private static final String PREFIX = "Vault: ";

    /** The machine codes of SPEC 10.4, the only ones a client reads. */
    static final Set<String> CODES = Set.of(
            "bad_request",
            "unauthorized",
            "forbidden",
            "policy_denied",
            "not_hosted",
            "not_found",
            "duplicate_repo",
            "too_many_heads",
            "manifest_conflict",
            "missing_parents",
            "quota_exceeded",
            "too_large");

    /** The message of a refused write because the clock cannot advance (an impossible member timestamp). */
    static final String IMPOSSIBLE_TIMESTAMP = PREFIX
            + "the vault holds an impossible timestamp from a member, so no later write can be stamped; a member"
            + " wrote the largest stamp there is, and writes stay refused until the owner removes the entry";

    private VaultFailures() {}

    /**
     * A host's refusal: its status and its SPEC 10.4 code, never its text. Carried as the cause of the
     * {@link AltsException} the client reports, so a retry can be decided from it.
     */
    public static final class Refusal extends Exception {

        @Serial
        private static final long serialVersionUID = 1L;

        /** The HTTP status of the refusal. */
        private final int status;

        /** The SPEC 10.4 code from the table, or null. */
        private final String code;

        Refusal(int status, String code) {
            super("vault host answered " + status + (code == null ? "" : " " + code), null, false, false);
            this.status = status;
            this.code = code;
        }

        /**
         * The HTTP status.
         *
         * @return the status
         */
        public int status() {
            return status;
        }

        /**
         * The SPEC 10.4 code, when the host sent one from the table.
         *
         * @return the code, or empty
         */
        public Optional<String> code() {
            return Optional.ofNullable(code);
        }
    }

    /**
     * The failure a host's non-2xx answer maps to.
     *
     * @param status the HTTP status
     * @param code the code from the error object, or {@code null}; kept only if it is in the table
     * @param retryAfter the stated wait, or {@code null}
     * @param what what was asked of the host, a fixed phrase
     * @return the exception, whose cause is the {@link Refusal}
     */
    static AltsException refused(int status, String code, Duration retryAfter, String what) {
        String known = code != null && CODES.contains(code) ? code : null;
        String said = " (" + status + (known == null ? "" : " " + known) + ")";
        AltsFailure failure =
                switch (status) {
                    case 401, 403 -> AltsFailure.of(Kind.UNAUTHORIZED, PREFIX + "the host refused " + what + said);
                    case 404 -> AltsFailure.of(Kind.NOT_FOUND, PREFIX + "the host does not hold " + what + said);
                    case 409 ->
                        AltsFailure.of(Kind.CONFLICT, PREFIX + what + " conflicts with the host's state" + said);
                    case 413 ->
                        AltsFailure.of(Kind.INVALID_INPUT, PREFIX + what + " is larger than the host takes" + said);
                    case 422 ->
                        AltsFailure.of(
                                Kind.NETWORK, PREFIX + "the host is still fetching what " + what + " needs" + said);
                    case 429 ->
                        AltsFailure.rateLimited(PREFIX + "the host is rate limiting " + what + said, retryAfter);
                    case 408 ->
                        AltsFailure.of(Kind.NETWORK, PREFIX + "the host timed out on " + what + said, retryAfter);
                    default ->
                        status >= 500
                                ? AltsFailure.of(Kind.NETWORK, PREFIX + "the host failed on " + what + said, retryAfter)
                                : AltsFailure.of(
                                        Kind.PROTOCOL, PREFIX + "the host refused " + what + " as malformed" + said);
                };
        return new AltsException(failure, new Refusal(status, known));
    }

    /**
     * The host refusal behind a failure, if it is one.
     *
     * @param e the failure
     * @return the refusal, or empty
     */
    static Optional<Refusal> refusal(AltsException e) {
        return e.getCause() instanceof Refusal r ? Optional.of(r) : Optional.empty();
    }

    /**
     * Whether a failure is a host refusal with the given code.
     *
     * @param e the failure
     * @param code a SPEC 10.4 code
     * @return whether it is
     */
    static boolean hasCode(AltsException e, String code) {
        return refusal(e).flatMap(Refusal::code).filter(code::equals).isPresent();
    }

    /**
     * A host item, a host's answer, or a signature that does not check: a host that is not following the
     * protocol, or a forgery.
     *
     * @param what a fixed description
     * @return the exception, of kind {@link Kind#PROTOCOL}
     */
    static AltsException protocol(String what) {
        return new AltsException(Kind.PROTOCOL, PREFIX + what);
    }

    /**
     * A key that does not unwrap or a ciphertext that does not open.
     *
     * @param what a fixed description
     * @return the exception, of kind {@link Kind#CRYPTO}
     */
    static AltsException crypto(String what) {
        return new AltsException(Kind.CRYPTO, PREFIX + what);
    }

    /**
     * Something the caller asked for that this device cannot do: an owner operation on a member's device,
     * removing the owner, inviting a current member.
     *
     * @param what a fixed description
     * @return the exception, of kind {@link Kind#INVALID_INPUT}
     */
    static AltsException invalid(String what) {
        return new AltsException(Kind.INVALID_INPUT, PREFIX + what);
    }

    /**
     * The host could not be reached or its answer could not be read.
     *
     * @param what a fixed description
     * @param cause the transport failure, kept for deliberate logging only
     * @return the exception, of kind {@link Kind#NETWORK}
     */
    static AltsException network(String what, Throwable cause) {
        return new AltsException(AltsFailure.of(Kind.NETWORK, PREFIX + what), cause);
    }

    /**
     * The operation was stopped on this side: the runtime closed, the executor refused it, or the thread
     * was interrupted.
     *
     * @param what a fixed description
     * @param cause the underlying failure, or {@code null}
     * @return the exception, of kind {@link Kind#CANCELLED}
     */
    static AltsException cancelled(String what, Throwable cause) {
        return new AltsException(AltsFailure.of(Kind.CANCELLED, PREFIX + what), cause);
    }
}

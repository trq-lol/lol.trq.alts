package lol.trq.alts;

import java.io.Serial;
import java.util.Objects;

/**
 * The one exception the library throws for a failure, and the only one a library future completes
 * with exceptionally (inside the JDK's {@link java.util.concurrent.CompletionException}).
 *
 * <p>Branch on {@code failure().kind()}. The message is {@link AltsFailure#message()}: built by the
 * library, never a transport exception's text, a token or a path. The underlying failure, where there
 * was one, is kept as the {@linkplain #getCause() cause} for a host that wants to log it deliberately;
 * its own message may quote a credential, so it is never shown.
 *
 * <p>Java serialization does not carry the {@link AltsFailure}: an instance is not serializable.
 *
 * @author trq
 * @since 1.0.0
 */
public final class AltsException extends RuntimeException {

    @Serial
    private static final long serialVersionUID = 1L;

    /** What went wrong. Not serializable: {@link AltsFailure} holds {@link java.util.Optional}s. */
    @SuppressWarnings("serial")
    private final AltsFailure failure;

    /**
     * Creates an exception carrying {@code failure}.
     *
     * @param failure what went wrong
     * @throws NullPointerException if {@code failure} is null
     * @since 1.0.0
     */
    public AltsException(AltsFailure failure) {
        this(failure, null);
    }

    /**
     * Creates an exception carrying {@code failure} and the underlying failure it was classified from.
     *
     * @param failure what went wrong
     * @param cause the underlying failure, or {@code null}
     * @throws NullPointerException if {@code failure} is null
     * @since 1.0.0
     */
    public AltsException(AltsFailure failure, Throwable cause) {
        super(Objects.requireNonNull(failure, "failure").message(), cause);
        this.failure = failure;
    }

    /**
     * Creates an exception carrying a fresh failure of {@code kind}.
     *
     * @param kind what kind of failure it is
     * @param message a short description built by the library
     * @since 1.0.0
     */
    public AltsException(AltsFailure.Kind kind, String message) {
        this(AltsFailure.of(kind, message));
    }

    /**
     * Returns what went wrong.
     *
     * @return the failure, never {@code null}
     * @since 1.0.0
     */
    public AltsFailure failure() {
        return failure;
    }

    /**
     * Returns the kind of failure, shorthand for {@code failure().kind()}.
     *
     * @return the kind
     * @since 1.0.0
     */
    public AltsFailure.Kind kind() {
        return failure.kind();
    }
}

package lol.trq.alts.net;

import com.google.gson.JsonParseException;
import java.io.IOException;
import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeoutException;
import javax.net.ssl.SSLException;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure;

/**
 * Describes and classifies a failure that came out of the transport or the JDK without repeating that
 * failure's own message.
 *
 * <p>An exception the library did not write says whatever its author chose to put in it, and the JDK
 * routinely puts the offending input there: a rejected header value, an address that did not parse, a
 * path. In this library those inputs are access tokens, sign-in addresses carrying codes, and files
 * under a home directory, and a failure message travels into a host's UI and its log. So a message that
 * can reach a host is built from the failure's <em>kind</em> alone, and the original stays reachable as
 * the cause for a host that wants to log it deliberately.
 *
 * @author trq
 * @since 0.12.0
 */
public final class FailureText {

    /** How many layers of asynchronous wrapping are looked through before giving up. */
    private static final int MAX_UNWRAP = 16;

    private FailureText() {}

    /**
     * Returns a fixed phrase for the kind of failure {@code failure} is. The phrase never contains any
     * part of the failure's own message, except that an {@link AltsException}, whose message the
     * library built, is described by that message.
     *
     * @param failure the failure to describe, or null
     * @return a short description safe to show and to log
     * @since 0.12.0
     */
    public static String of(Throwable failure) {
        Throwable cause = unwrap(failure);
        if (cause instanceof AltsException classified) {
            return classified.failure().message();
        }
        if (cause instanceof TransportClosedException
                || cause instanceof RejectedExecutionException
                || cause instanceof CancellationException) {
            return "the runtime is closed or the operation was cancelled";
        }
        if (cause instanceof JsonParseException) {
            return "unreadable response";
        }
        if (cause instanceof SocketTimeoutException || cause instanceof TimeoutException) {
            return "timed out";
        }
        if (cause instanceof UnknownHostException) {
            return "host could not be resolved";
        }
        if (cause instanceof ConnectException || cause instanceof NoRouteToHostException) {
            return "connection refused";
        }
        if (cause instanceof SSLException) {
            return "secure connection failed";
        }
        if (cause instanceof IOException) {
            return "connection failed";
        }
        if (cause instanceof IllegalArgumentException) {
            return "invalid request";
        }
        return "unexpected error";
    }

    /**
     * Returns the {@link AltsFailure.Kind} a failure that came out of the transport, the JDK or a stage
     * of the library is. An {@link AltsException} anywhere in the asynchronous wrapping keeps its own
     * kind; the runtime having closed, an executor refusing the task, and a cancellation are
     * {@link AltsFailure.Kind#CANCELLED}; any other I/O failure (refused, reset, timed out, unresolvable,
     * a failed TLS handshake, a proxy that named no route) is {@link AltsFailure.Kind#NETWORK}; a JSON
     * body that would not parse is {@link AltsFailure.Kind#PROTOCOL}; an argument the transport refused
     * (a header holding a control character, an address that does not parse) is
     * {@link AltsFailure.Kind#INVALID_INPUT}; anything else is {@link AltsFailure.Kind#UNKNOWN}.
     *
     * @param failure the failure to classify, or null
     * @return its kind
     * @since 1.0.0
     */
    public static AltsFailure.Kind kindOf(Throwable failure) {
        Throwable cause = unwrap(failure);
        if (cause instanceof AltsException classified) {
            return classified.kind();
        }
        if (cause instanceof TransportClosedException
                || cause instanceof RejectedExecutionException
                || cause instanceof CancellationException) {
            return AltsFailure.Kind.CANCELLED;
        }
        if (cause instanceof IOException || cause instanceof TimeoutException) {
            return AltsFailure.Kind.NETWORK;
        }
        if (cause instanceof JsonParseException) {
            return AltsFailure.Kind.PROTOCOL;
        }
        if (cause instanceof IllegalArgumentException) {
            return AltsFailure.Kind.INVALID_INPUT;
        }
        return AltsFailure.Kind.UNKNOWN;
    }

    /**
     * Returns {@code failure} as the one exception the library lets out: the {@link AltsException}
     * already inside it, when a stage classified it, or a new one of {@link #kindOf(Throwable)}'s kind
     * whose message is {@code context}, a colon and {@link #of(Throwable)}'s fixed phrase. The original
     * stays reachable as the cause, and none of its own text reaches the message.
     *
     * @param context what was being done, for the message: a step's or a request's name, never a URL
     *     with a query, a token or a path
     * @param failure the failure to convert
     * @return the exception to throw or to complete a future with
     * @since 1.0.0
     */
    public static AltsException toException(String context, Throwable failure) {
        Throwable cause = unwrap(failure);
        if (cause instanceof AltsException classified) {
            return classified;
        }
        return new AltsException(AltsFailure.of(kindOf(cause), context + ": " + of(cause)), cause);
    }

    /**
     * Returns the {@link AltsFailure} {@link #toException(String, Throwable)} would carry.
     *
     * @param context what was being done, for the message
     * @param failure the failure to convert
     * @return the failure
     * @since 1.0.0
     */
    public static AltsFailure toFailure(String context, Throwable failure) {
        return toException(context, failure).failure();
    }

    /**
     * Returns the failure inside however many layers of {@link CompletionException} and
     * {@link ExecutionException} wrap it.
     *
     * @param failure the outermost failure, or null
     * @return the innermost wrapped failure, or {@code failure} itself
     */
    private static Throwable unwrap(Throwable failure) {
        Throwable cause = failure;
        for (int depth = 0;
                depth < MAX_UNWRAP
                        && (cause instanceof CompletionException || cause instanceof ExecutionException)
                        && cause.getCause() != null;
                depth++) {
            cause = cause.getCause();
        }
        return cause;
    }
}

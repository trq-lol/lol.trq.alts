package lol.trq.alts.net;

import java.io.IOException;
import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;
import javax.net.ssl.SSLException;

/**
 * Describes a failure that came out of the transport or the JDK without repeating that failure's own
 * message.
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
     * part of the failure's own message.
     *
     * @param failure the failure to describe, or null
     * @return a short description safe to show and to log
     * @since 0.12.0
     */
    public static String of(Throwable failure) {
        Throwable cause = failure;
        for (int depth = 0;
                depth < MAX_UNWRAP
                        && (cause instanceof CompletionException || cause instanceof ExecutionException)
                        && cause.getCause() != null;
                depth++) {
            cause = cause.getCause();
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
}

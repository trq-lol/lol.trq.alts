package lol.trq.alts.internal.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;

import com.google.gson.JsonSyntaxException;
import java.io.IOException;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.RejectedExecutionException;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure.Kind;
import org.junit.jupiter.api.Test;

/**
 * Pins how a failure from the transport or the JDK becomes an {@link AltsException}: by its type, never
 * its message, and with none of its own text in what a host sees.
 */
class FailureClassificationTest {

    private static final String SECRET = "eyJsecret-token D:/data/someone/accounts.dat";

    @Test
    void eachTransportFailureMapsToItsKind() {
        assertEquals(Kind.NETWORK, FailureText.kindOf(new ConnectException(SECRET)));
        assertEquals(Kind.NETWORK, FailureText.kindOf(new SocketTimeoutException(SECRET)));
        assertEquals(Kind.NETWORK, FailureText.kindOf(new IOException(SECRET)));
        assertEquals(Kind.CANCELLED, FailureText.kindOf(new TransportClosedException(null)));
        assertEquals(Kind.CANCELLED, FailureText.kindOf(new RejectedExecutionException(SECRET)));
        assertEquals(Kind.CANCELLED, FailureText.kindOf(new CancellationException(SECRET)));
        assertEquals(Kind.PROTOCOL, FailureText.kindOf(new JsonSyntaxException(SECRET)));
        assertEquals(Kind.INVALID_INPUT, FailureText.kindOf(new IllegalArgumentException(SECRET)));
        assertEquals(Kind.UNKNOWN, FailureText.kindOf(new IllegalStateException(SECRET)));
    }

    @Test
    void aClassifiedFailureKeepsItsKindThroughAsynchronousWrapping() {
        AltsException classified = new AltsException(Kind.XBOX_DENIED, "denied");
        Throwable wrapped = new CompletionException(new ExecutionException(new CompletionException(classified)));

        assertEquals(Kind.XBOX_DENIED, FailureText.kindOf(wrapped));
        assertSame(classified, FailureText.toException("ignored", wrapped));
    }

    @Test
    void aConvertedFailureCarriesNoneOfTheOriginalText() {
        for (Throwable failure : new Throwable[] {
            new ConnectException(SECRET),
            new IOException(SECRET),
            new IllegalArgumentException(SECRET),
            new JsonSyntaxException(SECRET),
            new RejectedExecutionException(SECRET),
            new CompletionException(new SocketTimeoutException(SECRET)),
            new RuntimeException(SECRET)
        }) {
            AltsException converted = FailureText.toException("Profile fetch", failure);
            assertFalse(converted.getMessage().contains("secret"), converted.getMessage());
            assertFalse(converted.getMessage().contains("someone"), converted.getMessage());
            assertSame(
                    failure instanceof CompletionException ? failure.getCause() : failure,
                    converted.getCause(),
                    "the original is kept as the cause");
        }
    }
}

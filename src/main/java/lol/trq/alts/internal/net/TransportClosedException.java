package lol.trq.alts.internal.net;

import java.io.IOException;
import java.io.Serial;

/**
 * The transport's own signal that its runtime is closed, so the classifier can tell it from a
 * connection that failed without reading a message. Package-private: what leaves the library is an
 * {@link lol.trq.alts.AltsException} of kind {@link lol.trq.alts.AltsFailure.Kind#CANCELLED}.
 *
 * @author trq
 * @since 1.0.0
 */
final class TransportClosedException extends IOException {

    @Serial
    private static final long serialVersionUID = 1L;

    TransportClosedException(Throwable cause) {
        super("the runtime is closed", cause);
    }
}

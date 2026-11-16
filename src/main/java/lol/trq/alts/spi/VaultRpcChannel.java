package lol.trq.alts.spi;

import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;

/**
 * Host seam that carries the vault's unary calls to an AVP host over the gRPC profile (AVP SPEC 10.3).
 * Optional: without one, a vault host mapped to a {@code grpc://} or {@code grpcs://} address cannot be
 * reached and its connection fails with {@code NOT_CONFIGURED}. The library ships no gRPC client of its own;
 * a host adapts its own gRPC runtime with a byte-array marshaller, and may route the call through any tunnel
 * or gateway it likes. The library frames each request and verifies each answer exactly as over HTTP/JSON:
 * a channel moves bytes and learns nothing it could not see on the wire.
 *
 * <p>The contract:
 *
 * <ul>
 *   <li>{@code method} is the gRPC full method name without a leading slash, {@code avp.Vault/Push}, the
 *       form a gRPC runtime's full method name takes. {@code metadata} carries {@code authorization} on an
 *       authenticated call and nothing else; it holds the bearer token, a credential the channel must not log.
 *   <li>Passing {@code deadline} to the call is the channel's job. The library cancels the returned future
 *       ({@code cancel(true)}) when the deadline plus one second has passed, when the calling thread is
 *       interrupted, and when the runtime closes; the channel should cancel its call when that happens.
 *   <li>The library calls {@code unary} on one of the runtime's executor threads and waits there, so the
 *       channel completes the future from its own threads, never from a task queued on that executor.
 *   <li>{@link Reply#trailers()} are the response headers and trailers merged: keys lowercase ASCII, one value
 *       per key, the last one winning, no {@code -bin} keys. {@link Reply#status} normalizes the map it is
 *       given that way.
 *   <li>The channel enforces its own inbound message limit, and that limit MUST be at least 16 MiB, the
 *       largest answer a vault host may send (a pull of a large repository reaches it). gRPC runtimes default
 *       lower (grpc-java's {@code maxInboundMessageSize} is 4 MiB): a reply over the channel's limit fails
 *       locally with {@code RESOURCE_EXHAUSTED}, which the library reports as {@code too_large}, so the call
 *       can never succeed. The library also refuses a reply message over 16 MiB as a protocol failure, but
 *       only once the bytes are in memory.
 *   <li>The runtime never closes a channel: the host owns its lifecycle. The factory set with {@code
 *       AltsRuntime.Builder#vaultRpcChannel} runs at most once per mapped address per runtime, and the runtime
 *       keeps that channel until it closes, when it forgets it without closing it.
 * </ul>
 *
 * <p>A future that completes exceptionally, a channel that throws, and the statuses {@code CANCELLED}, {@code
 * DEADLINE_EXCEEDED} and {@code UNAVAILABLE} are {@code NETWORK}; a {@code RESOURCE_EXHAUSTED} whose message
 * is not {@code quota_exceeded} is {@code too_large} ({@code INVALID_INPUT}), never a rate limit; a status outside the profile's table
 * ({@code UNKNOWN}, {@code UNIMPLEMENTED}, {@code INTERNAL}, {@code DATA_LOSS} and the like) is {@code
 * PROTOCOL}, since the host does not speak the profile; a {@code null} future or reply is {@code PROTOCOL}.
 *
 * @author trq
 * @since 1.1.0
 */
@FunctionalInterface
public interface VaultRpcChannel {

    /**
     * Starts one unary call.
     *
     * @param method the full method name without a leading slash, {@code avp.Vault/Pull}
     * @param request the encoded request message
     * @param metadata the request metadata: {@code authorization} on an authenticated call, else empty
     * @param deadline the deadline to give the call
     * @return the call's outcome; never {@code null}
     * @since 1.1.0
     */
    CompletableFuture<Reply> unary(String method, byte[] request, Map<String, String> metadata, Duration deadline);

    /**
     * The outcome of one call: the response message on {@code OK}, else the status code, its message and the
     * trailers. A value: equal replies have equal parts, and {@link #toString()} leaves the message bytes out.
     *
     * @since 1.1.0
     */
    final class Reply {

        private static final byte[] NONE = new byte[0];

        private final int code;
        private final byte[] message;
        private final String statusMessage;
        private final Map<String, String> trailers;

        private Reply(int code, byte[] message, String statusMessage, Map<String, String> trailers) {
            this.code = code;
            this.message = message;
            this.statusMessage = statusMessage;
            this.trailers = trailers;
        }

        /**
         * A successful call.
         *
         * @param message the response message, copied
         * @return the reply
         * @since 1.1.0
         */
        public static Reply ok(byte[] message) {
            Objects.requireNonNull(message, "message");
            return new Reply(0, message.clone(), "", Map.of());
        }

        /**
         * A call that ended with a status other than {@code OK}.
         *
         * @param code the gRPC status code, {@code 1} to {@code 16}
         * @param message the status message, or {@code null} for none; under the AVP profile a refusal's message
         *     is its SPEC 10.4 code
         * @param trailers the response headers and trailers, or {@code null} for none; keys are lower-cased, and
         *     a {@code -bin} key, a key that is not ASCII and a value that is not printable ASCII are dropped
         * @return the reply
         * @throws IllegalArgumentException if {@code code} is {@code 0} (use {@link #ok}) or outside {@code 1}
         *     to {@code 16}
         * @since 1.1.0
         */
        public static Reply status(int code, String message, Map<String, String> trailers) {
            if (code < 1 || code > 16) {
                throw new IllegalArgumentException("a gRPC status other than OK is 1 to 16");
            }
            Map<String, String> kept = new LinkedHashMap<>();
            if (trailers != null) {
                for (Map.Entry<String, String> e : trailers.entrySet()) {
                    String key = e.getKey();
                    String value = e.getValue();
                    if (key == null || value == null || !ascii(key) || !ascii(value)) {
                        continue;
                    }
                    String lower = key.toLowerCase(Locale.ROOT);
                    if (lower.endsWith("-bin")) {
                        continue;
                    }
                    kept.remove(lower);
                    kept.put(lower, value);
                }
            }
            return new Reply(code, NONE, message == null ? "" : message, Collections.unmodifiableMap(kept));
        }

        private static boolean ascii(String s) {
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                if (c < 0x20 || c > 0x7e) {
                    return false;
                }
            }
            return true;
        }

        /**
         * Whether the call succeeded.
         *
         * @return whether the status is {@code OK}
         * @since 1.1.0
         */
        public boolean isOk() {
            return code == 0;
        }

        /**
         * The response message of a successful call.
         *
         * @return a copy of the message; empty for a failed call
         * @since 1.1.0
         */
        public byte[] message() {
            return message.clone();
        }

        /**
         * The gRPC status code.
         *
         * @return {@code 0} for {@code OK}, else {@code 1} to {@code 16}
         * @since 1.1.0
         */
        public int code() {
            return code;
        }

        /**
         * The status message.
         *
         * @return the message; empty for a successful call or a status without one
         * @since 1.1.0
         */
        public String statusMessage() {
            return statusMessage;
        }

        /**
         * The response headers and trailers, merged and normalized.
         *
         * @return an unmodifiable map; empty for a successful call
         * @since 1.1.0
         */
        public Map<String, String> trailers() {
            return trailers;
        }

        /**
         * Compares every part, the message bytes included.
         *
         * @param o the other object
         * @return whether it is an equal reply
         * @since 1.1.0
         */
        @Override
        public boolean equals(Object o) {
            return o instanceof Reply r
                    && code == r.code
                    && Arrays.equals(message, r.message)
                    && statusMessage.equals(r.statusMessage)
                    && trailers.equals(r.trailers);
        }

        /**
         * Hashes every part.
         *
         * @return the hash
         * @since 1.1.0
         */
        @Override
        public int hashCode() {
            return Objects.hash(code, Arrays.hashCode(message), statusMessage, trailers);
        }

        /**
         * Names the outcome and the message size, never the message bytes or the trailer values.
         *
         * @return a description
         * @since 1.1.0
         */
        @Override
        public String toString() {
            return isOk()
                    ? "Reply[OK, " + message.length + " bytes]"
                    : "Reply[status=" + code + ", trailers=" + trailers.keySet() + "]";
        }
    }
}

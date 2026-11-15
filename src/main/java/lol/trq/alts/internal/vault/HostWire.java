package lol.trq.alts.internal.vault;

import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import lol.trq.alts.AltsException;

/**
 * How a {@link HostClient} reaches its host: one AVP client operation in, one answer out. The client keeps
 * every rule of the protocol (discovery, tokens, the 401 re-mint, the {@code missing_parents} retry, the
 * verification of what comes back); a wire only frames the request for one transport profile of SPEC 10 and
 * reduces the answer to a status, a SPEC 10.4 code and a JSON body, so the profiles share one code path.
 *
 * <p>A wire throws an {@link AltsException} for what is not an answer: {@code NETWORK} when the host cannot be
 * reached or its answer cannot be read, {@code CANCELLED} when the runtime closed or the thread was
 * interrupted, {@code PROTOCOL} for an answer the profile does not allow. A refusal is an {@link Answer}.
 *
 * @author trq
 * @since 1.1.0
 */
public interface HostWire {

    /** The client operations of SPEC 10.1, discovery and authentication included. */
    enum Op {
        /** {@code GET /.well-known/avp}, or {@code GetHostInfo}. */
        DISCOVERY,
        /** The sign-in challenge. */
        CHALLENGE,
        /** The challenge exchanged for a bearer token. */
        TOKEN,
        /** A new repository. */
        CREATE_REPO,
        /** A pull. */
        PULL,
        /** A push of one commit. */
        PUSH,
        /** A new owner-signed manifest state. */
        PUBLISH_MANIFEST,
        /** A signed leave request. */
        LEAVE,
        /** A request that this host carry a repository. */
        PREPARE_JOIN
    }

    /**
     * One answer.
     *
     * @param status the HTTP status, or for gRPC the HTTP status SPEC 10.4 pairs with the outcome, so a refusal
     *     is classified the same way over either profile
     * @param code the SPEC 10.4 code, when the host named one from the table
     * @param retryAfter the wait the host stated, or {@code null}
     * @param body the answer on success; {@link JsonNull} on a refusal
     */
    record Answer(int status, Optional<String> code, Duration retryAfter, JsonElement body) {

        /** Checks the parts. */
        public Answer {
            Objects.requireNonNull(code, "code");
            Objects.requireNonNull(body, "body");
        }

        /**
         * Whether the host did what was asked.
         *
         * @return whether the status is a 2xx
         */
        public boolean ok() {
            return status >= 200 && status < 300;
        }
    }

    /**
     * Sends one operation. Blocks: run it on the transport's executor.
     *
     * @param op the operation
     * @param repoId the repository of a repository-scoped operation ({@code PULL}, {@code PUSH}, {@code
     *     PUBLISH_MANIFEST}, {@code LEAVE}), else {@code null}
     * @param body the request body in the HTTP/JSON profile's shape, or {@code null} for discovery
     * @param bearer the bearer token, or {@code null} for discovery, the challenge and the token exchange
     * @return the answer, a refusal included
     * @throws AltsException of kind {@code NETWORK}, {@code CANCELLED} or {@code PROTOCOL} when there is no
     *     answer to give
     */
    Answer call(Op op, String repoId, JsonObject body, String bearer);

    /**
     * The origin a token minted through this wire is bound to: {@code scheme://host:port}, lower-cased, with
     * the default port spelled out.
     *
     * @return the origin
     */
    String origin();

    /**
     * The profile this wire speaks, for descriptions: {@code http-json} or {@code grpc}.
     *
     * @return the profile name
     */
    String describe();
}

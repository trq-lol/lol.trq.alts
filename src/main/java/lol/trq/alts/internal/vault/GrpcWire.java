package lol.trq.alts.internal.vault;

import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import java.net.URI;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import lol.trq.alts.AltsException;
import lol.trq.alts.internal.net.HttpTransport;
import lol.trq.alts.internal.vault.rpc.ProtoJson;
import lol.trq.alts.spi.VaultRpcChannel;
import lol.trq.alts.spi.VaultRpcChannel.Reply;

/**
 * The gRPC profile (SPEC 10.3) over a host-supplied {@link VaultRpcChannel}: each operation is the {@code
 * avp.Vault} RPC SPEC 10.3 pairs with it, its body is the HTTP/JSON body encoded by {@link ProtoJson} (a
 * pull adds its {@code repoId}, which HTTP carries in the path), and the answer is decoded back to the same
 * JSON, so the client verifies it exactly as over HTTP.
 *
 * <p>A refusal's status message is its SPEC 10.4 code when it is one, and the answer carries the HTTP status
 * the table pairs with that code; otherwise the gRPC status falls back to its canonical HTTP status. {@code
 * CANCELLED}, {@code DEADLINE_EXCEEDED} and {@code UNAVAILABLE} and a failed future are {@code NETWORK}; any
 * other status is {@code PROTOCOL}. A closed runtime is {@code CANCELLED}.
 *
 * <p>{@link #call} runs on the calling thread, already the transport's executor: it starts the call on the
 * channel, submits nothing, and waits for the deadline plus one second, cancelling the channel's future on a
 * timeout, an interrupt or the runtime's close.
 *
 * @author trq
 * @since 1.1.0
 */
public final class GrpcWire implements HostWire {

    /** The deadline of a call, the HTTP profile's read timeout. */
    static final Duration DEADLINE = Duration.ofSeconds(30);

    /** How long past the deadline the wire waits for the channel before it gives up on the call. */
    static final Duration GRACE = Duration.ofSeconds(1);

    /** The HTTP status of each SPEC 10.4 code. */
    static final Map<String, Integer> AVP_STATUS = Map.ofEntries(
            Map.entry("bad_request", 400),
            Map.entry("unauthorized", 401),
            Map.entry("forbidden", 403),
            Map.entry("policy_denied", 403),
            Map.entry("not_hosted", 403),
            Map.entry("not_found", 404),
            Map.entry("duplicate_repo", 409),
            Map.entry("too_many_heads", 409),
            Map.entry("manifest_conflict", 409),
            Map.entry("missing_parents", 422),
            Map.entry("quota_exceeded", 429),
            Map.entry("too_large", 413));

    private record Rpc(String method, String request, String response) {}

    private final HttpTransport transport;
    private final VaultRpcChannel channel;
    private final String origin;
    private final Duration deadline;

    /**
     * A wire to the host at {@code target} through {@code channel}.
     *
     * @param transport the runtime's transport: whether it is closed
     * @param target the mapped address, {@code grpc://host[:port]} or {@code grpcs://host[:port]}
     * @param channel the host's channel for that address
     * @throws AltsException of kind {@code INVALID_INPUT} if {@code target} is not a grpc or grpcs URL with a
     *     host
     */
    public GrpcWire(HttpTransport transport, URI target, VaultRpcChannel channel) {
        this(transport, target, channel, DEADLINE);
    }

    GrpcWire(HttpTransport transport, URI target, VaultRpcChannel channel, Duration deadline) {
        this.transport = Objects.requireNonNull(transport, "transport");
        this.channel = Objects.requireNonNull(channel, "channel");
        this.deadline = Objects.requireNonNull(deadline, "deadline");
        String scheme = target.getScheme();
        if (target.getHost() == null || !("grpcs".equalsIgnoreCase(scheme) || "grpc".equalsIgnoreCase(scheme))) {
            throw VaultFailures.invalid("a gRPC vault host address is a grpc or grpcs URL with a host");
        }
        this.origin = HostClient.origin(target);
    }

    private static Rpc rpc(Op op) {
        return switch (op) {
            case DISCOVERY -> new Rpc("avp.Vault/GetHostInfo", "avp.HostInfoRequest", "avp.HostInfo");
            case CHALLENGE -> new Rpc("avp.Vault/Challenge", "avp.ChallengeRequest", "avp.AuthChallenge");
            case TOKEN -> new Rpc("avp.Vault/Token", "avp.TokenRequest", "avp.AuthToken");
            case CREATE_REPO -> new Rpc("avp.Vault/CreateRepo", "avp.CreateRepoRequest", "avp.SignedManifest");
            case PULL -> new Rpc("avp.Vault/Pull", "avp.PullRequest", "avp.PullResponse");
            case PUSH -> new Rpc("avp.Vault/Push", "avp.PushRequest", "avp.PushResponse");
            case PUBLISH_MANIFEST ->
                new Rpc("avp.Vault/PublishManifest", "avp.PublishManifestRequest", "avp.SignedManifest");
            case LEAVE -> new Rpc("avp.Vault/Leave", "avp.LeaveRequest", "avp.LeaveResponse");
            case PREPARE_JOIN -> new Rpc("avp.Vault/PrepareJoin", "avp.PrepareJoinRequest", "avp.Acceptance");
        };
    }

    @Override
    public Answer call(Op op, String repoId, JsonObject body, String bearer) {
        Rpc rpc = rpc(op);
        JsonObject message = body == null ? new JsonObject() : body.deepCopy();
        if (op == Op.PULL) {
            message.addProperty("repoId", Objects.requireNonNull(repoId, "repoId"));
        }
        byte[] request = ProtoJson.encode(rpc.request(), message);
        Map<String, String> metadata = bearer == null ? Map.of() : Map.of("authorization", "Bearer " + bearer);
        Reply reply = exchange(rpc.method(), request, metadata);
        if (reply.isOk()) {
            byte[] bytes = reply.message();
            if (bytes.length > HostClient.MAX_BODY_BYTES) {
                throw VaultFailures.protocol("the host's answer is larger than a vault answer may be");
            }
            return new Answer(200, Optional.empty(), null, ProtoJson.decode(rpc.response(), bytes));
        }
        return refusal(reply);
    }

    private Reply exchange(String method, byte[] request, Map<String, String> metadata) {
        if (transport.isClosed()) {
            throw VaultFailures.cancelled("the runtime is closed", null);
        }
        CompletableFuture<Reply> pending;
        try {
            pending = channel.unary(method, request, metadata, deadline);
        } catch (RuntimeException failure) {
            throw VaultFailures.network("the host could not be reached, or its answer could not be read", failure);
        }
        if (pending == null) {
            throw VaultFailures.protocol("the gRPC channel started no call");
        }
        AutoCloseable onClose = transport.whenClosed(() -> pending.cancel(true));
        try {
            Reply reply = pending.get(saturatedMillis(deadline.plus(GRACE)), TimeUnit.MILLISECONDS);
            if (reply == null) {
                throw VaultFailures.protocol("the gRPC channel answered with no reply");
            }
            return reply;
        } catch (InterruptedException interrupted) {
            pending.cancel(true);
            Thread.currentThread().interrupt();
            throw VaultFailures.cancelled("interrupted", interrupted);
        } catch (TimeoutException late) {
            pending.cancel(true);
            if (transport.isClosed()) {
                throw VaultFailures.cancelled("the runtime is closed", late);
            }
            throw VaultFailures.network("the host did not answer in time", late);
        } catch (CancellationException | ExecutionException failed) {
            if (transport.isClosed()) {
                throw VaultFailures.cancelled("the runtime is closed", failed);
            }
            throw VaultFailures.network("the host could not be reached, or its answer could not be read", failed);
        } finally {
            try {
                onClose.close();
            } catch (Exception impossible) {
                // Unregistering removes the action from a set; it does not fail.
            }
        }
    }

    private static long saturatedMillis(Duration d) {
        return HttpTransport.saturatedMillis(d);
    }

    private static Answer refusal(Reply reply) {
        String message = reply.statusMessage();
        Duration retryAfter = retryAfter(reply.trailers().get("retry-after"));
        Integer coded = AVP_STATUS.get(message);
        if (coded != null) {
            return new Answer(coded, Optional.of(message), retryAfter, JsonNull.INSTANCE);
        }
        int status =
                switch (reply.code()) {
                    case 16 -> 401;
                    case 7 -> 403;
                    case 5 -> 404;
                    case 6, 9 -> 409;
                    case 8 -> 429;
                    case 3 -> 400;
                    case 1, 4, 14 ->
                        throw VaultFailures.network(
                                "the host could not be reached, or its answer could not be read", null);
                    default ->
                        throw VaultFailures.protocol("the host answered with a status the gRPC profile does not use");
                };
        return new Answer(status, Optional.empty(), retryAfter, JsonNull.INSTANCE);
    }

    /** The {@code retry-after} trailer as decimal seconds (SPEC 12.2), or {@code null}. */
    private static Duration retryAfter(String value) {
        if (value == null || value.isEmpty() || value.length() > 9) {
            return null;
        }
        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) < '0' || value.charAt(i) > '9') {
                return null;
            }
        }
        return Duration.ofSeconds(Long.parseLong(value));
    }

    @Override
    public String origin() {
        return origin;
    }

    @Override
    public String describe() {
        return "grpc";
    }

    @Override
    public String toString() {
        return "GrpcWire[" + origin + "]";
    }
}

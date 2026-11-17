package lol.trq.alts.internal.vault;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import lol.trq.alts.internal.avp.AvpJson;
import lol.trq.alts.internal.net.HttpTransport;
import lol.trq.alts.internal.vault.rpc.ProtoJson;
import lol.trq.alts.net.NetworkScope;
import lol.trq.alts.spi.VaultRpcChannel;

/**
 * A {@link VaultRpcChannel} for tests that plays a gRPC front end: it decodes each request with {@link
 * ProtoJson}, forwards it to a {@link TestAvpHost} over HTTP/JSON on the route SPEC 10.3 pairs with the RPC,
 * and encodes the answer, or maps the refusal to the gRPC status of SPEC 10.3 with the code as the status
 * message, {@code avp-error-detail} and {@code retry-after}. It completes every call on its own threads, as a
 * gRPC runtime does.
 */
public final class GrpcGatewayChannel implements VaultRpcChannel, AutoCloseable {

    /** One call as the channel received it. */
    public record Call(String method, Map<String, String> metadata, Duration deadline) {}

    private record Route(String path, String request, String response) {}

    private static final Map<String, Route> ROUTES = Map.of(
            "avp.Vault/GetHostInfo", new Route("/.well-known/avp", "avp.HostInfoRequest", "avp.HostInfo"),
            "avp.Vault/Challenge",
                    new Route("/api/auth/keypair/challenge", "avp.ChallengeRequest", "avp.AuthChallenge"),
            "avp.Vault/Token", new Route("/api/auth/keypair/token", "avp.TokenRequest", "avp.AuthToken"),
            "avp.Vault/CreateRepo", new Route("/v1/repos", "avp.CreateRepoRequest", "avp.SignedManifest"),
            "avp.Vault/Pull", new Route("pull", "avp.PullRequest", "avp.PullResponse"),
            "avp.Vault/Push", new Route("push", "avp.PushRequest", "avp.PushResponse"),
            "avp.Vault/PublishManifest", new Route("manifest", "avp.PublishManifestRequest", "avp.SignedManifest"),
            "avp.Vault/Leave", new Route("leave", "avp.LeaveRequest", "avp.LeaveResponse"),
            "avp.Vault/PrepareJoin", new Route("/v1/prepare-join", "avp.PrepareJoinRequest", "avp.Acceptance"));

    private final URI base;
    private final ExecutorService threads =
            lol.trq.alts.TestExecutors.perTask(Thread.ofVirtual().factory());
    private final HttpTransport http = new HttpTransport(null, threads);
    private final List<Call> calls = new ArrayList<>();

    public GrpcGatewayChannel(TestAvpHost host) {
        this.base = host.base();
    }

    public List<Call> calls() {
        synchronized (calls) {
            return List.copyOf(calls);
        }
    }

    public long count(String method) {
        return calls().stream().filter(c -> c.method().equals(method)).count();
    }

    @Override
    public CompletableFuture<Reply> unary(
            String method, byte[] request, Map<String, String> metadata, Duration deadline) {
        synchronized (calls) {
            calls.add(new Call(method, Map.copyOf(metadata), deadline));
        }
        return CompletableFuture.supplyAsync(() -> forward(method, request, metadata), threads);
    }

    private Reply forward(String method, byte[] request, Map<String, String> metadata) {
        Route route = ROUTES.get(method);
        if (route == null) {
            return Reply.status(12, "", Map.of());
        }
        JsonObject body = ProtoJson.decode(route.request(), request);
        String path = route.path();
        if (!path.startsWith("/")) {
            String repoId =
                    switch (route.path()) {
                        case "pull" -> body.remove("repoId").getAsString();
                        case "push" ->
                            body.getAsJsonObject("commit").get("repoId").getAsString();
                        case "manifest" ->
                            body.getAsJsonObject("manifest")
                                    .getAsJsonObject("state")
                                    .get("repoId")
                                    .getAsString();
                        default -> body.get("repoId").getAsString();
                    };
            path = HostClient.repoPath(repoId, route.path());
        }
        String auth = metadata.get("authorization");
        boolean discovery = method.equals("avp.Vault/GetHostInfo");
        HttpTransport.RawResponse answer;
        try {
            answer = http.exchange(
                    discovery ? "GET" : "POST",
                    base + path,
                    discovery ? null : "application/json",
                    auth == null ? null : Map.of("Authorization", auth),
                    discovery ? null : AvpJson.write(body),
                    HostClient.MAX_BODY_BYTES,
                    NetworkScope.of(NetworkScope.Purpose.VAULT));
        } catch (Exception unreachable) {
            return Reply.status(14, "", Map.of());
        }
        if (answer.status() == 200) {
            JsonObject json = AvpJson.object(AvpJson.parse(answer.body()), "answer");
            return Reply.ok(ProtoJson.encode(route.response(), json));
        }
        String code = "";
        Map<String, String> trailers = new LinkedHashMap<>();
        try {
            JsonElement e = AvpJson.parse(answer.body());
            if (e.isJsonObject() && e.getAsJsonObject().has("code")) {
                code = e.getAsJsonObject().get("code").getAsString();
                if (e.getAsJsonObject().has("detail")) {
                    trailers.put(
                            "avp-error-detail",
                            e.getAsJsonObject().get("detail").getAsString());
                }
            }
        } catch (RuntimeException bare) {
            // a bare error: the status alone
        }
        if (answer.retryAfter() != null) {
            trailers.put("retry-after", Long.toString(answer.retryAfter().toSeconds()));
        }
        return Reply.status(grpcStatus(code, answer.status()), code, trailers);
    }

    /** The gRPC status SPEC 10.3 pairs with an AVP code, or with the HTTP status of a refusal without one. */
    static int grpcStatus(String code, int status) {
        return switch (code) {
            case "bad_request" -> 3;
            case "unauthorized" -> 16;
            case "forbidden", "policy_denied", "not_hosted" -> 7;
            case "not_found" -> 5;
            case "duplicate_repo" -> 6;
            case "too_many_heads", "manifest_conflict", "missing_parents" -> 9;
            case "quota_exceeded", "too_large" -> 8;
            default ->
                switch (status) {
                    case 400 -> 3;
                    case 401 -> 16;
                    case 403 -> 7;
                    case 404 -> 5;
                    case 409, 422 -> 9;
                    case 413, 429 -> 8;
                    default -> status >= 500 ? 14 : 2;
                };
        };
    }

    @Override
    public void close() {
        http.close();
        threads.shutdownNow();
    }

    @Override
    public String toString() {
        return "GrpcGatewayChannel[" + base + "]";
    }
}

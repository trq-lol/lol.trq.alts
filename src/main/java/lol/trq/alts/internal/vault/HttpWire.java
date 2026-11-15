package lol.trq.alts.internal.vault;

import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import java.net.URI;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import lol.trq.alts.AltsException;
import lol.trq.alts.internal.avp.AvpJson;
import lol.trq.alts.internal.net.HttpTransport;
import lol.trq.alts.net.NetworkScope;

/**
 * The HTTP/JSON profile (SPEC 10.2): each operation on its route under the host's base URL, through the
 * runtime's {@link HttpTransport} under {@link NetworkScope.Purpose#VAULT}, every answer read up to {@link
 * HostClient#MAX_BODY_BYTES}. A refusal is reduced to its status, its SPEC 10.4 code and its {@code
 * Retry-After}; the host's {@code error} text is never read.
 *
 * @author trq
 * @since 1.1.0
 */
public final class HttpWire implements HostWire {

    private static final NetworkScope SCOPE = NetworkScope.of(NetworkScope.Purpose.VAULT);

    private final HttpTransport transport;
    private final String root;
    private final String origin;

    /**
     * A wire to the host at {@code base}.
     *
     * @param transport the runtime's transport
     * @param base the host's base URL, {@code http(s)://host[:port]}
     * @throws AltsException of kind {@code INVALID_INPUT} if {@code base} is not an http or https URL with a host
     */
    public HttpWire(HttpTransport transport, URI base) {
        this.transport = Objects.requireNonNull(transport, "transport");
        String scheme = base.getScheme();
        if (base.getHost() == null || !("https".equalsIgnoreCase(scheme) || "http".equalsIgnoreCase(scheme))) {
            throw VaultFailures.invalid("a vault host address is an http or https URL with a host");
        }
        String r = base.toString();
        while (r.endsWith("/")) {
            r = r.substring(0, r.length() - 1);
        }
        this.root = r;
        this.origin = HostClient.origin(base);
    }

    @Override
    public Answer call(Op op, String repoId, JsonObject body, String bearer) {
        String path =
                switch (op) {
                    case DISCOVERY -> "/.well-known/avp";
                    case CHALLENGE -> "/api/auth/keypair/challenge";
                    case TOKEN -> "/api/auth/keypair/token";
                    case CREATE_REPO -> "/v1/repos";
                    case PULL -> HostClient.repoPath(repoId, "pull");
                    case PUSH -> HostClient.repoPath(repoId, "push");
                    case PUBLISH_MANIFEST -> HostClient.repoPath(repoId, "manifest");
                    case LEAVE -> HostClient.repoPath(repoId, "leave");
                    case PREPARE_JOIN -> "/v1/prepare-join";
                };
        HttpTransport.RawResponse answer = op == Op.DISCOVERY
                ? exchange("GET", root + path, null, null)
                : exchange(
                        "POST",
                        root + path,
                        AvpJson.write(body),
                        bearer == null ? null : Map.of("Authorization", "Bearer " + bearer));
        int status = answer.status();
        if (status >= 200 && status < 300) {
            return new Answer(status, Optional.empty(), answer.retryAfter(), AvpJson.parse(answer.body()));
        }
        return new Answer(status, code(answer.body()), answer.retryAfter(), JsonNull.INSTANCE);
    }

    @Override
    public String origin() {
        return origin;
    }

    @Override
    public String describe() {
        return "http-json";
    }

    private HttpTransport.RawResponse exchange(String method, String url, byte[] body, Map<String, String> headers) {
        try {
            return transport.exchange(
                    method,
                    url,
                    body == null ? null : "application/json",
                    headers,
                    body,
                    HostClient.MAX_BODY_BYTES,
                    SCOPE);
        } catch (IllegalArgumentException unbuildable) {
            // A minted token is checked before it is ever sent (HostClient#headerSafe), so what is left is a
            // request the transport could not build from the client's own parts. Its text is never quoted.
            throw VaultFailures.invalid("the request to the vault host could not be built");
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw VaultFailures.cancelled("interrupted", interrupted);
        } catch (Exception failure) {
            if (transport.isClosed()) {
                throw VaultFailures.cancelled("the runtime is closed", failure);
            }
            throw VaultFailures.network("the host could not be reached, or its answer could not be read", failure);
        }
    }

    /** The SPEC 10.4 code of an error object, when it is one from the table; a bare error has none. */
    private static Optional<String> code(byte[] body) {
        try {
            JsonElement parsed = AvpJson.parse(body);
            if (parsed.isJsonObject()) {
                JsonElement c = parsed.getAsJsonObject().get("code");
                if (c != null && c.isJsonPrimitive() && c.getAsJsonPrimitive().isString()) {
                    return Optional.of(c.getAsString()).filter(VaultFailures.CODES::contains);
                }
            }
        } catch (AltsException notJson) {
            // A bare error (SPEC 10.4 allows a 400 with no error object): the status alone.
        }
        return Optional.empty();
    }

    @Override
    public String toString() {
        return "HttpWire[" + origin + "]";
    }
}

package lol.trq.alts.internal.auth;

import com.google.gson.JsonObject;
import java.util.Map;
import java.util.Objects;
import lol.trq.alts.internal.net.HttpTransport;
import lol.trq.alts.net.NetworkScope;

/**
 * The profile hop of the sign-in chain: validates a Minecraft access token and resolves the identity
 * behind it, over the runtime's transport.
 *
 * @author trq
 * @since 0.1.0
 */
public final class AccountNetworkUtil {

    private final HttpTransport http;

    /**
     * Creates the profile hop over a transport.
     *
     * @param http the runtime's transport
     * @since 1.0.0
     */
    public AccountNetworkUtil(HttpTransport http) {
        this.http = Objects.requireNonNull(http, "http");
    }

    /**
     * The outcome of a profile lookup, carrying the status so a caller can tell a refused token from an
     * account with no profile from a service having a bad minute.
     *
     * @param status the HTTP status the profile endpoint answered with, or {@code 0} when it never
     *     answered
     * @param username the resolved username, or {@code null} when the lookup did not resolve one
     * @param uuid the resolved UUID, or {@code null} when the lookup did not resolve one
     * @param retryAfter how long the service asked the caller to wait, or {@code null} when it did not;
     *     added in 0.9.0
     * @author trq
     * @since 0.8.0
     */
    public record ProfileLookup(int status, String username, String uuid, java.time.Duration retryAfter) {

        /**
         * Returns whether the service is asking the caller to slow down.
         *
         * @return true if the status is 429
         * @since 0.9.0
         */
        public boolean rateLimited() {
            return status == 429;
        }

        /**
         * Returns whether the lookup resolved an identity.
         *
         * @return true if a username and UUID came back
         * @since 0.8.0
         */
        public boolean found() {
            return username != null && uuid != null;
        }

        /**
         * Returns whether the token was refused.
         *
         * @return true if the service answered 401 or 403
         * @since 0.8.0
         */
        public boolean refused() {
            return status == 401 || status == 403;
        }

        /**
         * Returns whether the credentials authenticated but no Minecraft profile exists for them.
         *
         * @return true if the service answered 404
         * @since 0.8.0
         */
        public boolean missingProfile() {
            return status == 404;
        }
    }

    /**
     * Validates a Minecraft access token and resolves the identity behind it, reporting the status
     * either way.
     *
     * <p>The status is the point. A 401 means the token is spent and renewal is worth trying; a 404 means
     * the credentials are fine and the account simply has no Minecraft profile, which no amount of
     * re-authenticating will change; a 5xx means try again later. Reported as one {@code null}, those
     * three produce the same unhelpful message for problems with nothing in common.
     *
     * @param token the Minecraft/Bearer access token to validate
     * @param profileUrl the Minecraft services profile endpoint
     * @param scope what is being fetched, and on whose behalf
     * @return the lookup outcome
     * @throws Exception if a network error occurs during the request
     * @since 0.8.0
     */
    public ProfileLookup fetchProfile(String token, String profileUrl, NetworkScope scope) throws Exception {
        HttpTransport.HttpResponse response =
                http.getForStatus(profileUrl, Map.of("Authorization", "Bearer " + token), scope);

        JsonObject body = response.body();
        String name = body == null ? null : text(body, "name");
        String id = body == null ? null : text(body, "id");
        if (response.successful() && name != null && id != null) {
            return new ProfileLookup(response.status(), name, id, response.retryAfter());
        }
        // A success naming nobody, a JSON null among them, is not found(): callers report it as PROTOCOL.
        return new ProfileLookup(response.status(), null, null, response.retryAfter());
    }

    /**
     * Reads a field that must be a JSON string.
     *
     * @param body the response body
     * @param key the field
     * @return the value, or {@code null} when the field is absent, a JSON null, or not a primitive
     */
    private static String text(JsonObject body, String key) {
        return body.has(key) && body.get(key).isJsonPrimitive() ? body.get(key).getAsString() : null;
    }
}

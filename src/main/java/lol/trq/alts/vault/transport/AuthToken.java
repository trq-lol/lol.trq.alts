package lol.trq.alts.vault.transport;

import com.google.gson.annotations.SerializedName;

/**
 * A bearer access token returned after a successful keypair authentication, presented on subsequent
 * vault calls. The token's internal format (JWT, opaque, etc.) is the server's concern; the client
 * treats it as opaque.
 *
 * @param token the bearer token value
 * @param expiresAt the epoch-millis expiry, after which a re-authentication is needed
 * @author trq
 * @since 0.2.0
 */
public record AuthToken(
        @SerializedName("token") String token,
        @SerializedName("expiresAt") long expiresAt) {

    /**
     * Renders this token without its value, so a bearer credential never reaches a log line or an
     * exception message.
     *
     * @return a description carrying the expiry and only whether a token is present
     */
    @Override
    public String toString() {
        return "AuthToken[token=" + (token == null ? "null" : "<redacted>") + ", expiresAt=" + expiresAt + "]";
    }
}

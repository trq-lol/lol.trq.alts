package lol.trq.alts.internal.vault;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import lol.trq.alts.internal.avp.AvpBytes;

/**
 * Bearer tokens by the host that minted them (AVP SPEC 3.3). A token is host-local: it is cached under the
 * host key the client matched the host by and the origin it was minted at, together with the key it was
 * minted for, and is only ever handed to a connection to that same host key at that same origin. Neither half
 * is enough alone: another host at the same address has another key, and discovery is unauthenticated, so an
 * impostor at another address can serve the real host's key.
 *
 * <p>Thread safe. A token is a credential: nothing here prints one.
 *
 * @author trq
 * @since 1.0.0
 */
public final class TokenCache {

    /** A token is renewed this long before it expires. */
    static final long SLACK_MILLIS = 30_000;

    private record Key(String hostKey, String origin, String subject) {}

    private record Token(String value, long expiresAt) {
        @Override
        public String toString() {
            return "Token[expiresAt=" + expiresAt + "]";
        }
    }

    private final Map<Key, Token> tokens = new ConcurrentHashMap<>();

    /** An empty cache. */
    public TokenCache() {}

    private static Key key(byte[] hostKey, String origin, byte[] subject) {
        return new Key(AvpBytes.base64(hostKey), origin, AvpBytes.base64(subject));
    }

    /**
     * The cached token a host minted for a key, if it is still good for a while.
     *
     * @param hostKey the key the host was matched by
     * @param origin the normalized origin the host is reached at, {@code scheme://host:port}
     * @param subject the Ed25519 key the token was minted for
     * @param nowMillis the current time
     * @return the token, or empty
     */
    Optional<String> get(byte[] hostKey, String origin, byte[] subject, long nowMillis) {
        Token t = tokens.get(key(hostKey, origin, subject));
        if (t == null || t.expiresAt() - SLACK_MILLIS <= nowMillis) {
            return Optional.empty();
        }
        return Optional.of(t.value());
    }

    /**
     * Caches a token a host minted.
     *
     * @param hostKey the key the host was matched by
     * @param origin the normalized origin it was minted at
     * @param subject the Ed25519 key it was minted for
     * @param value the token
     * @param expiresAt when the host says it expires, epoch milliseconds
     */
    void put(byte[] hostKey, String origin, byte[] subject, String value, long expiresAt) {
        tokens.put(key(hostKey, origin, subject), new Token(value, expiresAt));
    }

    /**
     * Drops a host's token for a key, after the host refused it.
     *
     * @param hostKey the host key
     * @param origin the normalized origin
     * @param subject the key it was minted for
     */
    void drop(byte[] hostKey, String origin, byte[] subject) {
        tokens.remove(key(hostKey, origin, subject));
    }

    /** Drops every token. */
    public void clear() {
        tokens.clear();
    }

    /**
     * Counts only; tokens are credentials.
     *
     * @return a description
     */
    @Override
    public String toString() {
        return "TokenCache[" + tokens.size() + " tokens]";
    }
}

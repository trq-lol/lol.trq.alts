package lol.trq.alts.vault;

import java.time.Instant;
import java.util.Objects;
import lol.trq.alts.AltsException;
import lol.trq.alts.internal.avp.AvpBytes;
import lol.trq.alts.internal.avp.Tokens;

/**
 * The token a joiner gives the owner (AVP SPEC 11.3): the joiner's two public keys, its home host (key and
 * locator), and the home host's signed acceptance to carry the repository for that member. The joiner gets
 * one from {@link SharedVault#prepareJoin}; the owner passes it to {@link SharedVault#invite(InviteToken)},
 * which verifies the acceptance and wraps the data key to exactly this token's key, never to one a host
 * served.
 *
 * <p>It holds no secret: its {@link #text()} is meant to be pasted to the owner. An owner who wants to be sure
 * the token came from the person they invite compares {@link #fingerprint()} with the one that person's
 * device shows ({@link VaultIdentity#fingerprint()}).
 *
 * @author trq
 * @since 1.0.0
 */
public final class InviteToken {

    private final Tokens.InviteToken token;

    InviteToken(Tokens.InviteToken token) {
        this.token = Objects.requireNonNull(token, "token");
    }

    /**
     * Reads an invite token from pasted text. Whitespace anywhere in the text is ignored.
     *
     * @param text the pasted text
     * @return the token
     * @throws AltsException of kind {@code INVALID_INPUT} if the text is not a version 2 invite token; whether
     *     its acceptance verifies is decided by {@link SharedVault#invite(InviteToken)}
     * @since 1.0.0
     */
    public static InviteToken parse(String text) {
        return new InviteToken(TokenText.parse(text, "invite token", Tokens::inviteFromJson));
    }

    /**
     * The token text to give the owner.
     *
     * @return the text
     * @since 1.0.0
     */
    public String text() {
        return TokenText.format(Tokens.toJson(token));
    }

    /**
     * The joiner's member id: its Ed25519 public key, base64.
     *
     * @return the member id
     * @since 1.0.0
     */
    public String memberId() {
        return AvpBytes.base64(token.ed25519PublicKey());
    }

    /**
     * The joiner's key fingerprint (SPEC 3.2), {@code xxxx-xxxx-xxxx-xxxx}, to compare out of band.
     *
     * @return the fingerprint
     * @since 1.0.0
     */
    public String fingerprint() {
        return Tokens.memberFingerprint(token.ed25519PublicKey(), token.x25519PublicKey());
    }

    /**
     * The key of the joiner's home host, base64.
     *
     * @return the host key
     * @since 1.0.0
     */
    public String homeHostKey() {
        return AvpBytes.base64(token.homeHostKey());
    }

    /**
     * Where the joiner's home host is reached.
     *
     * @return the host locator
     * @since 1.0.0
     */
    public String homeHostLocator() {
        return token.homeHostLocator();
    }

    /**
     * When the home host's acceptance expires; the owner must invite before then.
     *
     * @return the expiry
     * @since 1.0.0
     */
    public Instant expiresAt() {
        return Instant.ofEpochMilli(token.acceptance().expiresAt());
    }

    Tokens.InviteToken token() {
        return token;
    }

    /**
     * Whether {@code o} is a token with the same text.
     *
     * @param o the other object
     * @return whether they are equal
     * @since 1.0.0
     */
    @Override
    public boolean equals(Object o) {
        return o instanceof InviteToken other && text().equals(other.text());
    }

    /**
     * Hashes what {@link #equals(Object)} compares.
     *
     * @return the hash
     * @since 1.0.0
     */
    @Override
    public int hashCode() {
        return text().hashCode();
    }

    /**
     * The joiner's fingerprint and home host.
     *
     * @return a description
     * @since 1.0.0
     */
    @Override
    public String toString() {
        return "InviteToken[" + fingerprint() + ", home " + token.homeHostLocator() + "]";
    }
}

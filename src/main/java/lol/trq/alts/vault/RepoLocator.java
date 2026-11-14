package lol.trq.alts.vault;

import java.util.Objects;
import lol.trq.alts.AltsException;
import lol.trq.alts.internal.avp.AvpBytes;
import lol.trq.alts.internal.avp.Tokens;

/**
 * The token the owner gives a joiner (AVP SPEC 11.2): the repository id, the owner's home host (its key and
 * its locator) and the fingerprint of the owner key. The joiner reaches the owner's home host with it, by
 * key ({@link VaultHosts#connect(RepoLocator)}), and checks, once it has pulled the chain, that the genesis
 * owner key matches the fingerprint ({@link SharedVault#join}).
 *
 * <p>It holds no secret: its {@link #text()} is meant to be pasted to someone.
 *
 * @author trq
 * @since 1.0.0
 */
public final class RepoLocator {

    private final Tokens.RepoLocator token;

    RepoLocator(Tokens.RepoLocator token) {
        this.token = Objects.requireNonNull(token, "token");
    }

    /**
     * Reads a repo locator from pasted text. Whitespace anywhere in the text (around it, or a line break a
     * chat client inserted) is ignored.
     *
     * @param text the pasted text
     * @return the locator
     * @throws AltsException of kind {@code INVALID_INPUT} if the text is not a version 2 repo locator
     * @since 1.0.0
     */
    public static RepoLocator parse(String text) {
        return new RepoLocator(TokenText.parse(text, "repo locator", Tokens::locatorFromJson));
    }

    /**
     * The token text to give the joiner: base64url without padding (SPEC 11.1).
     *
     * @return the text
     * @since 1.0.0
     */
    public String text() {
        return TokenText.format(Tokens.toJson(token));
    }

    /**
     * The repository id, 22 base64url characters; a repository's identity, which never names a host.
     *
     * @return the id
     * @since 1.0.0
     */
    public String repoId() {
        return token.repoId();
    }

    /**
     * The key of the owner's home host, base64.
     *
     * @return the host key
     * @since 1.0.0
     */
    public String hostKey() {
        return AvpBytes.base64(token.hostKey());
    }

    /**
     * Where the owner's home host is reached, {@code host} or {@code host:port}: a hint, never the host's
     * identity, which is its key.
     *
     * @return the host locator
     * @since 1.0.0
     */
    public String hostLocator() {
        return token.hostLocator();
    }

    /**
     * The owner fingerprint, 16 hex digits of {@code SHA-256(ownerKey)}, to compare with the one the owner
     * sees ({@link OwnerIdentity#fingerprint()}).
     *
     * @return the fingerprint
     * @since 1.0.0
     */
    public String ownerFingerprint() {
        return token.ownerFingerprint();
    }

    /**
     * The {@code avp://<hostLocator>/<repoId>} address of the repository at the owner's home host.
     *
     * @return the address
     * @since 1.0.0
     */
    public String avpUri() {
        return new Tokens.AvpUri(token.hostLocator(), token.repoId()).toString();
    }

    Tokens.RepoLocator token() {
        return token;
    }

    /**
     * Whether {@code o} is a locator with the same text.
     *
     * @param o the other object
     * @return whether they are equal
     */
    @Override
    public boolean equals(Object o) {
        return o instanceof RepoLocator other && text().equals(other.text());
    }

    @Override
    public int hashCode() {
        return text().hashCode();
    }

    /**
     * The address and the owner fingerprint.
     *
     * @return a description
     */
    @Override
    public String toString() {
        return "RepoLocator[" + avpUri() + ", owner " + token.ownerFingerprint() + "]";
    }
}

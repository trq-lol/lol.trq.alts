package lol.trq.alts.vault.transport;

import lol.trq.alts.crypto.WrappedKey;
import lol.trq.alts.vault.MemberPublicKey;
import lol.trq.alts.vault.VaultException;

/**
 * The anti-MITM seam: verifies that a member's public keys, as served by a (potentially hostile)
 * server, are genuinely bound to that identity before another member wraps a data key to them. A host
 * may back this with an out-of-band signed binding (for example one signed by an external auth service
 * the member trusts).
 *
 * <p>{@link lol.trq.alts.vault.SharedVault} takes a verifier at construction and runs it before every
 * wrap to another member's keys: the data key is wrapped only to keys the verifier has already returned.
 * Its two-argument constructor has no default, so {@link #trustTransport()}, which skips the check, has
 * to be passed on purpose. The one exception is the deprecated one-argument constructor, kept so
 * existing callers compile: it installs {@link #trustTransport()} without being asked, which is the
 * reason it is deprecated.
 *
 * @author trq
 * @since 0.2.0
 */
public interface KeyBindingVerifier {

    /**
     * Verifies a member's public-key binding, returning the verified keys or throwing.
     *
     * @param repoId the repository context
     * @param entry the member entry served by the transport
     * @return the verified public keys to wrap to
     * @throws VaultException if the binding cannot be trusted
     */
    MemberPublicKey verify(String repoId, MemberEntry entry) throws VaultException;

    /**
     * Verifies a member's claimed public keys before anything has been wrapped to them. This is the
     * form {@link lol.trq.alts.vault.SharedVault} calls: the keys and their binding signature are all a
     * verifier needs, and asking first means no data key is ever wrapped to a key that was not vouched
     * for.
     *
     * <p>The default serves a verifier written against {@link #verify(String, MemberEntry)}: it hands
     * that method an entry carrying the claimed keys, the signature, and a placeholder in place of the
     * wrapped data key. The placeholder wraps nothing and names no real scheme; a verifier has no
     * reason to read it. Override this method to skip the placeholder altogether.
     *
     * @param repoId the repository context
     * @param claimed the public keys the member is claimed to hold
     * @param keyBindingSig the issuer's signature over those keys, Base64, or null when none was served
     * @return the verified public keys to wrap to
     * @throws VaultException if the binding cannot be trusted
     * @since 0.12.0
     */
    default MemberPublicKey verify(String repoId, MemberPublicKey claimed, String keyBindingSig) throws VaultException {
        WrappedKey nothingWrappedYet = new WrappedKey("unwrapped", "", "", "");
        return verify(
                repoId,
                new MemberEntry(
                        claimed.ed25519PublicKey(), claimed.x25519PublicKey(), nothingWrappedYet, 0L, keyBindingSig));
    }

    /**
     * Returns a verifier that trusts the transport as-is (no out-of-band check).
     *
     * <p>Choose this only when the keys did not come from an untrusted server: for example they were
     * exchanged out of band and compared by the people involved, or the host operates the server itself.
     * With it, a server that substitutes a member's X25519 key receives the repository data key.
     *
     * @return a pass-through verifier
     */
    static KeyBindingVerifier trustTransport() {
        return (repoId, entry) -> new MemberPublicKey(entry.ed25519PublicKey(), entry.x25519PublicKey());
    }
}

package lol.trq.alts.vault.transport;

import lol.trq.alts.vault.MemberPublicKey;
import lol.trq.alts.vault.VaultException;

/**
 * The anti-MITM seam: verifies that a member's public keys, as served by a (potentially hostile)
 * server, are genuinely bound to that identity before another member wraps a data key to them. A host
 * may back this with an out-of-band signed binding (for example one signed by an external auth service
 * the member trusts).
 *
 * <p>{@link lol.trq.alts.vault.SharedVault} takes a verifier at construction and runs it before every
 * wrap to another member's keys. There is no implicit default: {@link #trustTransport()} skips the check
 * and has to be passed on purpose.
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

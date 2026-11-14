package lol.trq.alts.vault;

import java.util.Objects;
import lol.trq.alts.internal.avp.AvpBytes;
import lol.trq.alts.internal.avp.Manifest.MemberEntry;
import lol.trq.alts.internal.avp.Tokens;

/**
 * One member of a repository as the latest verified manifest state lists it (AVP SPEC 4.2): a view of the
 * roster, not an identity. Pass it to {@link SharedVault#remove(VaultMember)} to remove that member.
 *
 * @author trq
 * @since 1.0.0
 */
public final class VaultMember {

    private final byte[] ed25519;
    private final String fingerprint;
    private final String homeHostKey;
    private final boolean owner;

    private VaultMember(byte[] ed25519, String fingerprint, String homeHostKey, boolean owner) {
        this.ed25519 = ed25519.clone();
        this.fingerprint = fingerprint;
        this.homeHostKey = homeHostKey;
        this.owner = owner;
    }

    static VaultMember of(MemberEntry entry, byte[] ownerKey) {
        return new VaultMember(
                entry.ed25519PublicKey(),
                Tokens.memberFingerprint(entry.ed25519PublicKey(), entry.x25519PublicKey()),
                AvpBytes.base64(entry.homeHostKey()),
                AvpBytes.same(entry.ed25519PublicKey(), ownerKey));
    }

    /**
     * The member id: the member's Ed25519 public key, base64, as {@code lastUsedBy} and {@code observedBy}
     * name it.
     *
     * @return the member id
     * @since 1.0.0
     */
    public String memberId() {
        return AvpBytes.base64(ed25519);
    }

    /**
     * The key fingerprint (SPEC 3.2), {@code xxxx-xxxx-xxxx-xxxx}, to compare out of band.
     *
     * @return the fingerprint
     * @since 1.0.0
     */
    public String fingerprint() {
        return fingerprint;
    }

    /**
     * The key of the host this member syncs through, base64.
     *
     * @return the home host key
     * @since 1.0.0
     */
    public String homeHostKey() {
        return homeHostKey;
    }

    /**
     * Whether this member is the owner's device.
     *
     * @return whether its key is the owner key
     * @since 1.0.0
     */
    public boolean owner() {
        return owner;
    }

    byte[] key() {
        return ed25519.clone();
    }

    /**
     * Whether {@code o} is the same member as listed in the same way.
     *
     * @param o the other object
     * @return whether they are equal
     */
    @Override
    public boolean equals(Object o) {
        return o instanceof VaultMember m
                && AvpBytes.same(ed25519, m.ed25519)
                && fingerprint.equals(m.fingerprint)
                && homeHostKey.equals(m.homeHostKey)
                && owner == m.owner;
    }

    @Override
    public int hashCode() {
        return Objects.hash(memberId(), fingerprint, homeHostKey, owner);
    }

    /**
     * The fingerprint and the owner flag.
     *
     * @return a description
     */
    @Override
    public String toString() {
        return "VaultMember[" + fingerprint + (owner ? ", owner" : "") + "]";
    }
}

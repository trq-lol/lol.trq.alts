package lol.trq.alts.internal.vault;

import java.util.Arrays;
import lol.trq.alts.internal.avp.AvpBytes;
import lol.trq.alts.internal.avp.AvpCrypto;
import lol.trq.alts.internal.avp.Ed25519Strict;
import lol.trq.alts.internal.avp.OwnerKeys;
import lol.trq.alts.internal.avp.Tokens;

/**
 * One member device's key pairs (AVP SPEC 3.2): an Ed25519 key, the member id that signs commits, leave
 * requests and challenges, and an X25519 key the data keys are wrapped to. The owner is the member whose
 * keys derive from the phrase ({@link #ofOwner(OwnerKeys)}).
 *
 * <p>The private halves never leave the device: {@link #toString()} names the member id only, and the
 * accessors that hand out a private key return a copy, which the caller zeroes.
 *
 * @author trq
 * @since 1.0.0
 */
public final class MemberKeys {

    private final byte[] seed;
    private final byte[] ed25519Public;
    private final byte[] x25519Private;
    private final byte[] x25519Public;

    private MemberKeys(byte[] seed, byte[] x25519Private) {
        if (seed.length != 32 || x25519Private.length != 32) {
            throw VaultFailures.invalid("a member key is 32 bytes");
        }
        this.seed = seed.clone();
        this.x25519Private = x25519Private.clone();
        this.ed25519Public = Ed25519Strict.publicKey(seed);
        this.x25519Public = AvpCrypto.x25519Public(x25519Private);
    }

    /**
     * A member from its two private keys.
     *
     * @param ed25519Seed the 32-byte Ed25519 seed; copied
     * @param x25519Private the 32-byte X25519 scalar; copied
     * @return the member keys
     */
    public static MemberKeys of(byte[] ed25519Seed, byte[] x25519Private) {
        return new MemberKeys(ed25519Seed, x25519Private);
    }

    /**
     * A fresh member from the CSPRNG.
     *
     * @return the member keys
     */
    public static MemberKeys generate() {
        byte[] seed = AvpCrypto.randomBytes(32);
        byte[] x = AvpCrypto.randomBytes(32);
        try {
            return new MemberKeys(seed, x);
        } finally {
            Arrays.fill(seed, (byte) 0);
            Arrays.fill(x, (byte) 0);
        }
    }

    /**
     * The owner as a member (SPEC 3.1: the owner is one member entry).
     *
     * @param owner the owner keys
     * @return the member keys
     */
    public static MemberKeys ofOwner(OwnerKeys owner) {
        byte[] seed = owner.ed25519Seed();
        byte[] x = owner.x25519Private();
        try {
            return new MemberKeys(seed, x);
        } finally {
            Arrays.fill(seed, (byte) 0);
            Arrays.fill(x, (byte) 0);
        }
    }

    /**
     * The Ed25519 public key, the member id.
     *
     * @return a copy
     */
    public byte[] ed25519Public() {
        return ed25519Public.clone();
    }

    /**
     * The X25519 public key the data keys are wrapped to.
     *
     * @return a copy
     */
    public byte[] x25519Public() {
        return x25519Public.clone();
    }

    /**
     * The Ed25519 seed. A secret.
     *
     * @return a copy, which the caller zeroes
     */
    public byte[] ed25519Seed() {
        return seed.clone();
    }

    /**
     * The X25519 private key. A secret.
     *
     * @return a copy, which the caller zeroes
     */
    public byte[] x25519Private() {
        return x25519Private.clone();
    }

    /**
     * The member id written into stamps: the base64 Ed25519 public key.
     *
     * @return the id
     */
    public String id() {
        return AvpBytes.base64(ed25519Public);
    }

    /**
     * The key fingerprint to show and compare (SPEC 3.2).
     *
     * @return {@code xxxx-xxxx-xxxx-xxxx}
     */
    public String fingerprint() {
        return Tokens.memberFingerprint(ed25519Public, x25519Public);
    }

    /** Whether a key is this member's Ed25519 key. */
    boolean is(byte[] key) {
        return AvpBytes.same(ed25519Public, key);
    }

    /** The seed itself, for signing inside this package; never handed out. */
    byte[] seedRef() {
        return seed;
    }

    /** The X25519 scalar itself, for unwrapping inside this package; never handed out. */
    byte[] x25519Ref() {
        return x25519Private;
    }

    /**
     * Names the member id only; never a private key.
     *
     * @return a description
     */
    @Override
    public String toString() {
        return "MemberKeys[" + id() + "]";
    }
}

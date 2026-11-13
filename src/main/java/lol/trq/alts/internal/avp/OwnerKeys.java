package lol.trq.alts.internal.avp;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * The owner keys derived from a BIP39 seed (AVP SPEC 3.1):
 *
 * <pre>
 * ed25519Seed   = HKDF-SHA256(ikm = seed, salt = empty, info = "avp/owner/ed25519/v1", L = 32)
 * x25519Private = HKDF-SHA256(ikm = seed, salt = empty, info = "avp/owner/x25519/v1",  L = 32)
 * </pre>
 *
 * <p>The Ed25519 public key is the repository's {@code ownerKey}. The private halves are secret: {@link
 * #toString()} shows only the owner key, the accessors hand out copies, and {@link #destroy()} zeroes the
 * held copies. Not thread safe against {@link #destroy()}.
 *
 * <p>Ported from the Alt Vault Protocol reference implementation (MIT).
 *
 * @author trq
 * @since 1.0.0
 */
public final class OwnerKeys {

    /** The HKDF info label of the owner Ed25519 seed. */
    public static final String ED25519_INFO = "avp/owner/ed25519/v1";

    /** The HKDF info label of the owner X25519 private key. */
    public static final String X25519_INFO = "avp/owner/x25519/v1";

    private final byte[] ed25519Seed;
    private final byte[] ownerKey;
    private final byte[] x25519Private;
    private final byte[] x25519Public;

    /** Copies the private keys; the caller zeroes its own arrays. */
    private OwnerKeys(byte[] ed25519Seed, byte[] x25519Private) {
        this.ed25519Seed = ed25519Seed.clone();
        this.x25519Private = x25519Private.clone();
        this.ownerKey = Ed25519Strict.publicKey(ed25519Seed);
        this.x25519Public = AvpCrypto.x25519Public(x25519Private);
    }

    /**
     * Derives the owner keys from a 64-byte BIP39 seed.
     *
     * @param seed the seed; not retained
     * @return the keys
     * @throws lol.trq.alts.AltsException of kind {@code INVALID_INPUT} if the seed is not 64 bytes
     */
    public static OwnerKeys fromSeed(byte[] seed) {
        if (seed.length != 64) {
            throw AvpFailures.invalidInput("a BIP39 seed is 64 bytes");
        }
        byte[] ed = new byte[0];
        byte[] x = new byte[0];
        try {
            ed = AvpCrypto.hkdf(seed, new byte[0], ED25519_INFO.getBytes(StandardCharsets.UTF_8), 32);
            x = AvpCrypto.hkdf(seed, new byte[0], X25519_INFO.getBytes(StandardCharsets.UTF_8), 32);
            return new OwnerKeys(ed, x);
        } finally {
            Arrays.fill(ed, (byte) 0);
            Arrays.fill(x, (byte) 0);
        }
    }

    /**
     * Derives the owner keys from the mnemonic entropy: its mnemonic, the empty-passphrase seed, then
     * {@link #fromSeed(byte[])}.
     *
     * @param entropy the 32 bytes of entropy; not retained
     * @return the keys
     */
    public static OwnerKeys fromEntropy(byte[] entropy) {
        byte[] seed = Bip39.mnemonicToSeed(Bip39.entropyToMnemonic(entropy), "");
        try {
            return fromSeed(seed);
        } finally {
            Arrays.fill(seed, (byte) 0);
        }
    }

    /**
     * Derives the owner keys from a typed 24-word phrase, after checking its words and checksum.
     *
     * @param mnemonic the phrase
     * @return the keys
     * @throws lol.trq.alts.AltsException of kind {@code INVALID_INPUT} if the phrase does not decode
     */
    public static OwnerKeys fromMnemonic(String mnemonic) {
        byte[] entropy = Bip39.mnemonicToEntropy(mnemonic);
        try {
            return fromEntropy(entropy);
        } finally {
            Arrays.fill(entropy, (byte) 0);
        }
    }

    /**
     * The owner's Ed25519 signing seed.
     *
     * @return a copy, which the caller zeroes
     */
    public byte[] ed25519Seed() {
        return ed25519Seed.clone();
    }

    /**
     * The repository's {@code ownerKey}, the owner's Ed25519 public key.
     *
     * @return a copy
     */
    public byte[] ownerKey() {
        return ownerKey.clone();
    }

    /**
     * The owner's X25519 private key.
     *
     * @return a copy, which the caller zeroes
     */
    public byte[] x25519Private() {
        return x25519Private.clone();
    }

    /**
     * The owner's X25519 public key.
     *
     * @return a copy
     */
    public byte[] x25519Public() {
        return x25519Public.clone();
    }

    /** Zeroes the private keys this object holds. */
    public void destroy() {
        Arrays.fill(ed25519Seed, (byte) 0);
        Arrays.fill(x25519Private, (byte) 0);
    }

    /**
     * Names the owner key only; the private keys are never printed.
     *
     * @return a description
     */
    @Override
    public String toString() {
        return "OwnerKeys[ownerKey=" + AvpBytes.base64(ownerKey) + "]";
    }
}

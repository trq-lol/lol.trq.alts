package lol.trq.alts.vault;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.SecretKey;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure;
import lol.trq.alts.crypto.Ed25519;
import lol.trq.alts.crypto.PayloadCipher;
import lol.trq.alts.crypto.Pbkdf2;
import lol.trq.alts.crypto.X25519;
import lol.trq.alts.internal.avp.Tokens;
import lol.trq.alts.internal.vault.MemberKeys;

/**
 * A member's cryptographic identity: an Ed25519 key pair (the member key, which signs the member's AVP 0.5
 * commits and leave requests and authenticates it to hosts) plus an X25519 key pair (used only to unwrap
 * repository data keys wrapped to this member). Both private keys are held in memory only while unlocked.
 * Every failure is an {@link AltsException}: {@code INVALID_INPUT} for a stored record that is malformed,
 * {@code CRYPTO} for a wrong passphrase or recovery code, a tampered record, or a key operation that fails.
 *
 * <p>The two private keys are concatenated into 64 bytes of "private material" and sealed under a
 * passphrase-derived master key for storage as a {@link WrappedIdentity}. There is no account: the
 * Ed25519 public key <em>is</em> the identity. Optionally a second sealing under an offline recovery
 * code can be attached so the identity survives a forgotten passphrase, without any server-side escrow.
 *
 * @author trq
 * @since 0.2.0
 */
public final class VaultIdentity {

    private static final byte[] PASSPHRASE_AAD = "lol.trq.alts/identity-material/v1".getBytes(StandardCharsets.UTF_8);
    private static final byte[] RECOVERY_AAD = "lol.trq.alts/identity-recovery/v1".getBytes(StandardCharsets.UTF_8);
    private static final byte[] CONSISTENCY_PROBE =
            "lol.trq.alts/identity-consistency/v1".getBytes(StandardCharsets.UTF_8);
    private static final int MATERIAL_BYTES = Ed25519.KEY_BYTES + X25519.KEY_BYTES;

    /**
     * The shortest challenge {@link #signChallenge(byte[])} signs.
     *
     * @since 1.0.0
     */
    public static final int MIN_CHALLENGE_BYTES = 16;

    /**
     * The longest challenge {@link #signChallenge(byte[])} signs.
     *
     * @since 1.0.0
     */
    public static final int MAX_CHALLENGE_BYTES = 1024;

    /** The ASCII bytes every AVP 0.5 canonical-encoding tag begins with. */
    private static final byte[] AVP_TAG_PREFIX = "avp/".getBytes(StandardCharsets.US_ASCII);

    private final PublicKey edPublic;
    private final PrivateKey edPrivate;
    private final PublicKey xPublic;
    private final PrivateKey xPrivate;
    private final WrappedIdentity stored;

    private VaultIdentity(
            PublicKey edPublic, PrivateKey edPrivate, PublicKey xPublic, PrivateKey xPrivate, WrappedIdentity stored) {
        this.edPublic = edPublic;
        this.edPrivate = edPrivate;
        this.xPublic = xPublic;
        this.xPrivate = xPrivate;
        this.stored = stored;
    }

    /**
     * Creates a brand-new identity from fresh key pairs, sealed under {@code passphrase}.
     *
     * @param passphrase the passphrase protecting the private material
     * @return the unlocked identity
     * @throws AltsException of kind {@link AltsFailure.Kind#INVALID_INPUT} if {@code passphrase} is null, and of
     *     kind {@link AltsFailure.Kind#CRYPTO} if key generation or sealing fails
     */
    public static VaultIdentity create(char[] passphrase) {
        var ed = Ed25519.newKeyPair();
        var x = X25519.newKeyPair();
        byte[] salt = Pbkdf2.newSalt();
        SecretKey mk = Pbkdf2.deriveKey(passphrase, salt, Pbkdf2.VAULT_ITERATIONS);
        byte[] material = material(ed.getPrivate(), x.getPrivate());
        String wrapped;
        try {
            wrapped = seal(mk, PASSPHRASE_AAD, material);
        } finally {
            Arrays.fill(material, (byte) 0);
        }
        Base64.Encoder b64 = Base64.getEncoder();
        WrappedIdentity stored = new WrappedIdentity(
                b64.encodeToString(Ed25519.encodePublicKey(ed.getPublic())),
                b64.encodeToString(X25519.encodePublicKey(x.getPublic())),
                b64.encodeToString(salt),
                Pbkdf2.VAULT_ITERATIONS,
                wrapped,
                null,
                null);
        return new VaultIdentity(ed.getPublic(), ed.getPrivate(), x.getPublic(), x.getPrivate(), stored);
    }

    /**
     * Unlocks a stored identity with its passphrase.
     *
     * <p>The stored record is treated as untrusted: its iteration count must lie within
     * {@link Pbkdf2#MIN_ITERATIONS} and {@link Pbkdf2#MAX_ITERATIONS}, and the public keys it names must
     * be the ones that belong to the unsealed private keys. A record whose public keys were swapped
     * after sealing, so that peers would wrap repository keys to someone else, is rejected.
     *
     * @param stored the stored identity
     * @param passphrase the passphrase used at creation
     * @return the unlocked identity
     * @throws AltsException of kind {@link AltsFailure.Kind#CRYPTO} if the passphrase is wrong, the sealing was
     *     tampered with, or the record's public keys do not match the private material, and of kind {@link
     *     AltsFailure.Kind#INVALID_INPUT} if the record is malformed or its iteration count out of range, or
     *     {@code passphrase} is null
     */
    public static VaultIdentity unlock(WrappedIdentity stored, char[] passphrase) {
        SecretKey mk = Pbkdf2.deriveKey(passphrase, decode(stored.kdfSalt(), "kdf salt"), stored.kdfIterations());
        byte[] material = open(mk, PASSPHRASE_AAD, stored.wrappedPrivateMaterial());
        return fromMaterial(material, stored);
    }

    /**
     * Restores a stored identity from its offline recovery code, bypassing the passphrase.
     *
     * @param stored the stored identity (must carry a recovery sealing)
     * @param recoveryCode the recovery code shown at recovery setup
     * @return the unlocked identity
     * @throws AltsException of kind {@link AltsFailure.Kind#CRYPTO} if the code is wrong, the sealing was
     *     tampered with, or the record's public keys do not match the private material, and of kind {@link
     *     AltsFailure.Kind#INVALID_INPUT} if the record carries no recovery sealing or is malformed
     */
    public static VaultIdentity unlockWithRecovery(WrappedIdentity stored, String recoveryCode) {
        if (!stored.hasRecovery()) {
            throw invalid("the stored identity has no recovery sealing");
        }
        SecretKey rk = RecoveryCode.deriveKey(recoveryCode, decode(stored.recoverySalt(), "recovery salt"));
        byte[] material = open(rk, RECOVERY_AAD, stored.recoveryWrappedPrivateMaterial());
        return fromMaterial(material, stored);
    }

    /**
     * Returns a copy of this identity's stored form with an offline recovery sealing added (or
     * replaced) under {@code recoveryCode}. Persist the returned record; the live identity is unchanged.
     *
     * @param recoveryCode the recovery code (see {@link RecoveryCode#newCode()})
     * @return the stored form including the recovery sealing
     * @throws AltsException of kind {@link AltsFailure.Kind#CRYPTO} if sealing fails
     */
    public WrappedIdentity withRecovery(String recoveryCode) {
        byte[] salt = Pbkdf2.newSalt();
        SecretKey rk = RecoveryCode.deriveKey(recoveryCode, salt);
        byte[] material = material(edPrivate, xPrivate);
        String recoveryWrapped;
        try {
            recoveryWrapped = seal(rk, RECOVERY_AAD, material);
        } finally {
            Arrays.fill(material, (byte) 0);
        }
        return new WrappedIdentity(
                stored.ed25519PublicKey(),
                stored.x25519PublicKey(),
                stored.kdfSalt(),
                stored.kdfIterations(),
                stored.wrappedPrivateMaterial(),
                Base64.getEncoder().encodeToString(salt),
                recoveryWrapped);
    }

    /**
     * Returns the stored, passphrase-protected form of this identity for persistence or upload.
     *
     * @return the wrapped identity
     */
    public WrappedIdentity export() {
        return stored;
    }

    /**
     * Returns the Ed25519 identity public key — this member's stable identity.
     *
     * @return the identity public key
     */
    public PublicKey identityPublicKey() {
        return edPublic;
    }

    /**
     * Returns the raw 32-byte Ed25519 identity public key, Base64-encoded — the member id used on the
     * wire and to key membership server-side.
     *
     * @return the Base64 identity public key
     * @throws AltsException of kind {@link AltsFailure.Kind#CRYPTO} if the key cannot be encoded
     */
    public String identityId() {
        return Base64.getEncoder().encodeToString(Ed25519.encodePublicKey(edPublic));
    }

    /**
     * Returns the key fingerprint of this member (AVP SPEC 3.2), {@code xxxx-xxxx-xxxx-xxxx}: what an owner
     * compares with {@link InviteToken#fingerprint()} and the roster shows as {@link
     * VaultMember#fingerprint()}.
     *
     * @return the fingerprint
     * @throws AltsException of kind {@link lol.trq.alts.AltsFailure.Kind#CRYPTO} if a key cannot be encoded
     * @since 1.0.0
     */
    public String fingerprint() {
        return Tokens.memberFingerprint(Ed25519.encodePublicKey(edPublic), X25519.encodePublicKey(xPublic));
    }

    /**
     * This identity as AVP 0.5 member keys: the same Ed25519 key signs and the same X25519 key unwraps.
     *
     * @return the member keys
     * @throws AltsException of kind {@link lol.trq.alts.AltsFailure.Kind#CRYPTO} if a key cannot be encoded
     */
    MemberKeys memberKeys() {
        byte[] seed = null;
        byte[] scalar = null;
        try {
            seed = Ed25519.encodePrivateKey(edPrivate);
            scalar = X25519.encodePrivateKey(xPrivate);
            return MemberKeys.of(seed, scalar);
        } finally {
            if (seed != null) {
                Arrays.fill(seed, (byte) 0);
            }
            if (scalar != null) {
                Arrays.fill(scalar, (byte) 0);
            }
        }
    }

    /**
     * Returns the X25519 public key, to which other members wrap repository data keys for this member.
     *
     * @return the key-agreement public key
     */
    public PublicKey keyAgreementPublicKey() {
        return xPublic;
    }

    /**
     * Returns the X25519 private key, used to unwrap repository data keys wrapped to this member.
     *
     * @return the key-agreement private key
     */
    public PrivateKey keyAgreementPrivateKey() {
        return xPrivate;
    }

    /**
     * Signs a challenge nonce from a 0.4 vault server with the Ed25519 identity key, as 0.4 authentication
     * asks: over the raw nonce bytes. It exists so a host can still authenticate to its 0.4 server to
     * export a repository.
     *
     * <p>The same key is a 0.5 member key, and a 0.5 member signs only the canonical-encoding structures
     * of AVP SPEC 4.1, never raw bytes a server chose. So that a server cannot pass one of those off as a
     * nonce, this refuses, without signing, any input that begins with the ASCII bytes {@code avp/} (every
     * 0.5 canonical-encoding string begins with such a tag) or that is shorter than {@value
     * #MIN_CHALLENGE_BYTES} or longer than {@value #MAX_CHALLENGE_BYTES} bytes.
     *
     * @param nonce the challenge bytes
     * @return the signature
     * @throws AltsException of kind {@link AltsFailure.Kind#INVALID_INPUT} if the input is refused; nothing is
     *     signed. Of kind {@link AltsFailure.Kind#CRYPTO} if signing fails
     */
    public byte[] signChallenge(byte[] nonce) {
        if (nonce == null
                || nonce.length < MIN_CHALLENGE_BYTES
                || nonce.length > MAX_CHALLENGE_BYTES
                || startsWith(nonce, AVP_TAG_PREFIX)) {
            throw new AltsException(
                    AltsFailure.Kind.INVALID_INPUT,
                    "Vault identity: a challenge must be 16 to 1024 bytes and must not be a protocol structure");
        }
        return Ed25519.sign(edPrivate, nonce);
    }

    private static boolean startsWith(byte[] data, byte[] prefix) {
        return data.length >= prefix.length && Arrays.equals(data, 0, prefix.length, prefix, 0, prefix.length);
    }

    private static VaultIdentity fromMaterial(byte[] material, WrappedIdentity stored) {
        byte[] edSeed = null;
        byte[] xScalar = null;
        try {
            if (material.length != MATERIAL_BYTES) {
                throw invalid("the stored identity's private material is not " + MATERIAL_BYTES + " bytes");
            }
            edSeed = Arrays.copyOfRange(material, 0, Ed25519.KEY_BYTES);
            xScalar = Arrays.copyOfRange(material, Ed25519.KEY_BYTES, MATERIAL_BYTES);
            PublicKey edPublic = Ed25519.decodePublicKey(key(stored.ed25519PublicKey(), "Ed25519 public key"));
            PrivateKey edPrivate = Ed25519.decodePrivateKey(edSeed);
            PublicKey xPublic = X25519.decodePublicKey(key(stored.x25519PublicKey(), "X25519 public key"));
            PrivateKey xPrivate = X25519.decodePrivateKey(xScalar);
            requireConsistent(edPublic, edPrivate, xPublic, xPrivate);
            return new VaultIdentity(edPublic, edPrivate, xPublic, xPrivate, stored);
        } finally {
            Arrays.fill(material, (byte) 0);
            if (edSeed != null) {
                Arrays.fill(edSeed, (byte) 0);
            }
            if (xScalar != null) {
                Arrays.fill(xScalar, (byte) 0);
            }
        }
    }

    /**
     * The stored public keys sit outside the sealing, so anyone able to edit the record could replace
     * them. Check each against the private key it claims to pair with before anything trusts it.
     */
    private static void requireConsistent(
            PublicKey edPublic, PrivateKey edPrivate, PublicKey xPublic, PrivateKey xPrivate) {
        if (!Ed25519.verify(edPublic, CONSISTENCY_PROBE, Ed25519.sign(edPrivate, CONSISTENCY_PROBE))) {
            throw mismatch("Ed25519");
        }
        byte[] derived = X25519.encodePublicKey(X25519.derivePublicKey(xPrivate));
        if (!MessageDigest.isEqual(derived, X25519.encodePublicKey(xPublic))) {
            throw mismatch("X25519");
        }
    }

    private static byte[] material(PrivateKey edPrivate, PrivateKey xPrivate) {
        byte[] edSeed = Ed25519.encodePrivateKey(edPrivate);
        byte[] xScalar = null;
        try {
            xScalar = X25519.encodePrivateKey(xPrivate);
            return concat(edSeed, xScalar);
        } finally {
            Arrays.fill(edSeed, (byte) 0);
            if (xScalar != null) {
                Arrays.fill(xScalar, (byte) 0);
            }
        }
    }

    private static byte[] decode(String base64, String what) {
        if (base64 == null) {
            throw invalid("the stored identity's " + what + " is missing");
        }
        try {
            return Base64.getDecoder().decode(base64);
        } catch (IllegalArgumentException e) {
            throw invalid("the stored identity's " + what + " is not Base64");
        }
    }

    /** A stored public key: Base64 of exactly 32 bytes, or the record is malformed. */
    private static byte[] key(String base64, String what) {
        byte[] raw = decode(base64, what);
        if (raw.length != Ed25519.KEY_BYTES) {
            throw invalid("the stored identity's " + what + " is not " + Ed25519.KEY_BYTES + " bytes");
        }
        return raw;
    }

    private static AltsException invalid(String what) {
        return new AltsException(AltsFailure.Kind.INVALID_INPUT, "Vault identity: " + what);
    }

    /**
     * A record whose public key does not pair with its private material was tampered with after sealing: a
     * failed check of the keys, not of the record's shape.
     */
    private static AltsException mismatch(String which) {
        return new AltsException(
                AltsFailure.Kind.CRYPTO,
                "Vault identity: the stored " + which + " public key does not match the private key");
    }

    private static String seal(SecretKey key, byte[] aad, byte[] plaintext) {
        byte[] iv = PayloadCipher.newIv();
        byte[] ct = PayloadCipher.encrypt(key, iv, aad, plaintext);
        return Base64.getEncoder().encodeToString(concat(iv, ct));
    }

    private static byte[] open(SecretKey key, byte[] aad, String sealedB64) {
        byte[] sealed = decode(sealedB64, "sealed private material");
        if (sealed.length <= PayloadCipher.IV_BYTES) {
            throw invalid("the sealed private material is too short");
        }
        byte[] iv = Arrays.copyOfRange(sealed, 0, PayloadCipher.IV_BYTES);
        byte[] ct = Arrays.copyOfRange(sealed, PayloadCipher.IV_BYTES, sealed.length);
        return PayloadCipher.decrypt(key, iv, aad, ct);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}

package lol.trq.alts.internal.avp;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HexFormat;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * The primitives of AVP over the JDK providers, on raw byte encodings (AVP SPEC 2, 4.4): SHA-256,
 * HKDF-SHA256, AES-256-GCM, X25519, and the one wrap scheme {@code X25519-HKDF-SHA256-AESGCM-v1} with its
 * label.
 *
 * <p>A failure on input is an {@link lol.trq.alts.AltsException} of kind {@code CRYPTO} (or {@code
 * PROTOCOL} for an unknown scheme id); a missing mandatory JDK algorithm is an environment fault and an
 * {@link IllegalStateException}. Intermediate secrets (shared secrets, key-encryption keys) are zeroed
 * once used.
 *
 * <p>Ported from the Alt Vault Protocol reference implementation (MIT).
 *
 * @author trq
 * @since 1.0.0
 */
public final class AvpCrypto {

    /** The only wrap scheme id of AVP 0.5 (SPEC 4.4). */
    public static final String SCHEME_ID = "X25519-HKDF-SHA256-AESGCM-v1";

    /**
     * The label a wrap is bound to, as both the HKDF {@code info} and the GCM associated data (SPEC 4.4),
     * so a wrap made under one label never opens under the other.
     */
    public enum WrapLabel {
        /** The data key of a key epoch, wrapped to a member (SPEC 4.4). */
        DATA_KEY("avp/rdk-wrap/v1"),
        /** The owner's mnemonic entropy, wrapped to a new owner device (SPEC 11.6). */
        OWNER_LINK("avp/owner-link/v1");

        private final String label;

        WrapLabel(String label) {
            this.label = label;
        }

        /**
         * The label text.
         *
         * @return the label, for example {@code avp/rdk-wrap/v1}
         */
        public String label() {
            return label;
        }

        byte[] bytes() {
            return label.getBytes(StandardCharsets.UTF_8);
        }
    }

    private static final int TAG_BYTES = 16;
    private static final byte[] X25519_SPKI_PREFIX = HexFormat.of().parseHex("302a300506032b656e032100");
    private static final byte[] X25519_PKCS8_PREFIX = HexFormat.of().parseHex("302e020100300506032b656e04220420");
    private static final byte[] X25519_BASE = basePoint();
    private static final SecureRandom RANDOM = new SecureRandom();

    private AvpCrypto() {}

    /**
     * SHA-256.
     *
     * @param data the input
     * @return the 32-byte digest
     */
    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is missing from this JDK", e);
        }
    }

    private static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 is missing from this JDK", e);
        }
    }

    /**
     * HKDF-SHA256 (RFC 5869). An empty salt is 32 zero bytes in the extract step.
     *
     * @param ikm the input key material
     * @param salt the salt, possibly empty
     * @param info the context label
     * @param length the output length, 1 to 255 * 32
     * @return the output key material
     * @throws lol.trq.alts.AltsException of kind {@code CRYPTO} if the length is out of range
     */
    public static byte[] hkdf(byte[] ikm, byte[] salt, byte[] info, int length) {
        if (length < 1 || length > 255 * 32) {
            throw AvpFailures.crypto("HKDF output length out of range", null);
        }
        byte[] prk = hmacSha256(salt.length == 0 ? new byte[32] : salt, ikm);
        byte[] out = new byte[length];
        byte[] previous = new byte[0];
        int filled = 0;
        for (int counter = 1; filled < length; counter++) {
            byte[] block = new byte[previous.length + info.length + 1];
            System.arraycopy(previous, 0, block, 0, previous.length);
            System.arraycopy(info, 0, block, previous.length, info.length);
            block[block.length - 1] = (byte) counter;
            Arrays.fill(previous, (byte) 0);
            previous = hmacSha256(prk, block);
            int take = Math.min(previous.length, length - filled);
            System.arraycopy(previous, 0, out, filled, take);
            filled += take;
        }
        Arrays.fill(previous, (byte) 0);
        Arrays.fill(prk, (byte) 0);
        return out;
    }

    /**
     * AES-256-GCM encryption with the 16-byte tag appended.
     *
     * @param key the 32-byte key
     * @param iv the 12-byte IV, never reused under one key
     * @param plaintext the plaintext
     * @param aad the associated data
     * @return {@code ciphertext || tag}
     * @throws lol.trq.alts.AltsException of kind {@code CRYPTO} if a length is wrong or the cipher fails
     */
    public static byte[] aesGcmSeal(byte[] key, byte[] iv, byte[] plaintext, byte[] aad) {
        return gcm(Cipher.ENCRYPT_MODE, key, iv, plaintext, aad);
    }

    /**
     * AES-256-GCM decryption of {@code ciphertext || tag}.
     *
     * @param key the 32-byte key
     * @param iv the 12-byte IV
     * @param ciphertext the ciphertext with its tag
     * @param aad the associated data
     * @return the plaintext
     * @throws lol.trq.alts.AltsException of kind {@code CRYPTO} if it does not authenticate: a wrong key
     *     or AAD, or a tampered or truncated ciphertext
     */
    public static byte[] aesGcmOpen(byte[] key, byte[] iv, byte[] ciphertext, byte[] aad) {
        if (ciphertext.length < TAG_BYTES) {
            throw AvpFailures.crypto("the ciphertext is shorter than its tag", null);
        }
        return gcm(Cipher.DECRYPT_MODE, key, iv, ciphertext, aad);
    }

    private static byte[] gcm(int mode, byte[] key, byte[] iv, byte[] input, byte[] aad) {
        if (key.length != 32 || iv.length != 12) {
            throw AvpFailures.crypto("AES-256-GCM needs a 32-byte key and a 12-byte IV", null);
        }
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BYTES * 8, iv));
            cipher.updateAAD(aad);
            return cipher.doFinal(input);
        } catch (GeneralSecurityException | RuntimeException e) {
            throw AvpFailures.crypto(
                    mode == Cipher.DECRYPT_MODE ? "the ciphertext does not authenticate" : "encryption failed", e);
        }
    }

    /**
     * X25519 (RFC 7748): the raw, unhashed shared secret. The scalar is clamped as the RFC specifies.
     *
     * @param scalar the 32-byte private scalar
     * @param u the peer's 32-byte u-coordinate
     * @return the 32-byte shared secret
     * @throws lol.trq.alts.AltsException of kind {@code CRYPTO} if an input has the wrong length or the
     *     agreement fails, a small-order peer key included
     */
    public static byte[] x25519(byte[] scalar, byte[] u) {
        if (scalar.length != 32 || u.length != 32) {
            throw AvpFailures.crypto("X25519 needs 32-byte inputs", null);
        }
        byte[] pkcs8 = AvpBytes.concat(X25519_PKCS8_PREFIX, scalar);
        try {
            KeyFactory factory = KeyFactory.getInstance("XDH");
            PrivateKey own = factory.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
            PublicKey peer = factory.generatePublic(new X509EncodedKeySpec(AvpBytes.concat(X25519_SPKI_PREFIX, u)));
            KeyAgreement agreement = KeyAgreement.getInstance("XDH");
            agreement.init(own);
            agreement.doPhase(peer, true);
            return agreement.generateSecret();
        } catch (GeneralSecurityException | RuntimeException e) {
            throw AvpFailures.crypto("the X25519 agreement failed", e);
        } finally {
            Arrays.fill(pkcs8, (byte) 0);
        }
    }

    /**
     * The raw X25519 public key of a scalar: {@code X25519(scalar, 9)}.
     *
     * @param scalar the 32-byte private scalar
     * @return the 32-byte public key
     */
    public static byte[] x25519Public(byte[] scalar) {
        return x25519(scalar, X25519_BASE);
    }

    /**
     * Wraps a secret to a recipient with a fresh random ephemeral key and IV (SPEC 4.4).
     *
     * @param recipientPublic the recipient's 32-byte X25519 public key
     * @param secret the secret
     * @param label the label the wrap is bound to
     * @return the wrap
     */
    public static WrappedKey wrap(byte[] recipientPublic, byte[] secret, WrapLabel label) {
        byte[] ephemeral = randomBytes(32);
        try {
            return wrapWith(recipientPublic, secret, label, ephemeral, randomBytes(12));
        } finally {
            Arrays.fill(ephemeral, (byte) 0);
        }
    }

    /**
     * {@link #wrap} with a caller-chosen ephemeral key and IV, to reproduce the vectors. A real wrap uses
     * {@link #wrap}.
     *
     * @param recipientPublic the recipient's 32-byte X25519 public key
     * @param secret the secret
     * @param label the label the wrap is bound to
     * @param ephemeralPrivate the 32-byte ephemeral scalar
     * @param iv the 12-byte IV
     * @return the wrap
     */
    static WrappedKey wrapWith(
            byte[] recipientPublic, byte[] secret, WrapLabel label, byte[] ephemeralPrivate, byte[] iv) {
        byte[] info = label.bytes();
        byte[] ephemeralPublic = x25519Public(ephemeralPrivate);
        byte[] shared = x25519(ephemeralPrivate, recipientPublic);
        byte[] kek = hkdf(shared, ephemeralPublic, info, 32);
        try {
            return new WrappedKey(SCHEME_ID, ephemeralPublic, iv, aesGcmSeal(kek, iv, secret, info));
        } finally {
            Arrays.fill(shared, (byte) 0);
            Arrays.fill(kek, (byte) 0);
        }
    }

    /**
     * Unwraps with the recipient's private key under a label (SPEC 4.4).
     *
     * @param recipientPrivate the recipient's 32-byte X25519 scalar
     * @param wrapped the wrap
     * @param label the label it must have been made under
     * @return the secret
     * @throws lol.trq.alts.AltsException of kind {@code PROTOCOL} for another scheme id, and of kind
     *     {@code CRYPTO} if it does not open: a wrong key, the other label, or tampered bytes
     */
    public static byte[] unwrap(byte[] recipientPrivate, WrappedKey wrapped, WrapLabel label) {
        if (!SCHEME_ID.equals(wrapped.schemeId())) {
            throw AvpFailures.protocol("the wrap scheme is not supported");
        }
        byte[] info = label.bytes();
        byte[] shared = x25519(recipientPrivate, wrapped.ephemeralPublicKey());
        byte[] kek = hkdf(shared, wrapped.ephemeralPublicKey(), info, 32);
        try {
            return aesGcmOpen(kek, wrapped.iv(), wrapped.ciphertext(), info);
        } finally {
            Arrays.fill(shared, (byte) 0);
            Arrays.fill(kek, (byte) 0);
        }
    }

    /**
     * Bytes from the JDK's secure random source.
     *
     * @param n how many
     * @return {@code n} random bytes
     */
    public static byte[] randomBytes(int n) {
        byte[] out = new byte[n];
        RANDOM.nextBytes(out);
        return out;
    }

    private static byte[] basePoint() {
        byte[] u = new byte[32];
        u[0] = 9;
        return u;
    }
}

package lol.trq.alts.internal.crypto;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure;

/**
 * Ed25519 signing, verification, and raw 32-byte key encoding (RFC 8032) via the JDK's built-in
 * {@code Ed25519} provider. The Ed25519 public key is a vault member's stable identity: it is what the
 * server keys membership on and what other members verify signatures against. Distinct from the
 * member's {@link X25519} key, which is only used to wrap the repository data key.
 *
 * @author trq
 * @since 0.2.0
 */
public final class Ed25519 {

    /** Raw public/private key length, in bytes. */
    public static final int KEY_BYTES = 32;

    private Ed25519() {}

    /**
     * Generates a fresh Ed25519 key pair.
     *
     * @return a new key pair
     * @throws AltsException of kind {@code CRYPTO} if key generation fails
     */
    public static KeyPair newKeyPair() {
        if (Curves.raw()) {
            byte[] seed = BcCurves.edNewSeed();
            return new KeyPair(
                    RawKeys.publicKey(RawKeys.ED25519, BcCurves.edPublic(seed)),
                    RawKeys.privateKey(RawKeys.ED25519, seed));
        }
        try {
            return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        } catch (Exception e) {
            throw failure("Ed25519 keygen failed", e);
        }
    }

    /**
     * Signs a message.
     *
     * @param privateKey the signing key
     * @param message the message bytes
     * @return the 64-byte signature
     * @throws AltsException of kind {@code CRYPTO} if signing fails
     */
    public static byte[] sign(PrivateKey privateKey, byte[] message) {
        if (privateKey instanceof RawKeys.Private) {
            return BcCurves.edSign(((RawKeys.Private) privateKey).raw(), message);
        }
        try {
            Signature sig = Signature.getInstance("Ed25519");
            sig.initSign(privateKey);
            sig.update(message);
            return sig.sign();
        } catch (Exception e) {
            throw failure("Ed25519 sign failed", e);
        }
    }

    /**
     * Verifies a signature.
     *
     * @param publicKey the verification key
     * @param message the message bytes
     * @param signature the signature to verify
     * @return true if the signature is valid for the message and key
     */
    public static boolean verify(PublicKey publicKey, byte[] message, byte[] signature) {
        if (publicKey instanceof RawKeys.Public) {
            return BcCurves.edVerify(((RawKeys.Public) publicKey).raw(), message, signature);
        }
        try {
            Signature sig = Signature.getInstance("Ed25519");
            sig.initVerify(publicKey);
            sig.update(message);
            return sig.verify(signature);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Encodes a public key to its raw 32-byte RFC 8032 form (little-endian y with the x sign bit in the
     * top bit of the last byte).
     *
     * @param publicKey the Ed25519 public key
     * @return the raw 32-byte encoding
     * @throws AltsException of kind {@code CRYPTO} if the key is not an Ed25519 key
     */
    public static byte[] encodePublicKey(PublicKey publicKey) {
        if (publicKey instanceof RawKeys.Public) {
            return ((RawKeys.Public) publicKey).raw();
        }
        if (!(publicKey instanceof EdECPublicKey ed)) {
            throw failure("not an Ed25519 public key", null);
        }
        EdECPoint point = ed.getPoint();
        byte[] raw = bigIntToLe(point.getY(), KEY_BYTES);
        if (point.isXOdd()) {
            raw[KEY_BYTES - 1] |= (byte) 0x80;
        }
        return raw;
    }

    /**
     * Decodes a raw 32-byte RFC 8032 public key.
     *
     * @param raw the raw 32-byte encoding
     * @return the Ed25519 public key
     * @throws AltsException of kind {@code CRYPTO} if decoding fails
     */
    public static PublicKey decodePublicKey(byte[] raw) {
        requireLen(raw, "public key");
        if (Curves.raw()) {
            return RawKeys.publicKey(RawKeys.ED25519, raw);
        }
        try {
            byte[] copy = raw.clone();
            boolean xOdd = (copy[KEY_BYTES - 1] & 0x80) != 0;
            copy[KEY_BYTES - 1] &= (byte) 0x7F;
            BigInteger y = leToBigInt(copy);
            KeyFactory kf = KeyFactory.getInstance("Ed25519");
            return kf.generatePublic(new EdECPublicKeySpec(NamedParameterSpec.ED25519, new EdECPoint(xOdd, y)));
        } catch (Exception e) {
            throw failure("Ed25519 public key decode failed", e);
        }
    }

    /**
     * Encodes a private key to its raw 32-byte seed.
     *
     * @param privateKey the Ed25519 private key
     * @return the raw 32-byte seed
     * @throws AltsException of kind {@code CRYPTO} if the seed is unavailable
     */
    public static byte[] encodePrivateKey(PrivateKey privateKey) {
        if (privateKey instanceof RawKeys.Private) {
            return ((RawKeys.Private) privateKey).raw();
        }
        if (!(privateKey instanceof EdECPrivateKey ed)) {
            throw failure("not an Ed25519 private key", null);
        }
        return ed.getBytes().orElseThrow(() -> failure("Ed25519 seed not extractable", null));
    }

    /**
     * Decodes a raw 32-byte seed into a private key.
     *
     * @param raw the raw 32-byte seed
     * @return the Ed25519 private key
     * @throws AltsException of kind {@code CRYPTO} if decoding fails
     */
    public static PrivateKey decodePrivateKey(byte[] raw) {
        requireLen(raw, "private key");
        if (Curves.raw()) {
            return RawKeys.privateKey(RawKeys.ED25519, raw);
        }
        try {
            KeyFactory kf = KeyFactory.getInstance("Ed25519");
            return kf.generatePrivate(new EdECPrivateKeySpec(NamedParameterSpec.ED25519, raw.clone()));
        } catch (Exception e) {
            throw failure("Ed25519 private key decode failed", e);
        }
    }

    private static void requireLen(byte[] raw, String what) {
        if (raw == null || raw.length != KEY_BYTES) {
            throw failure("Ed25519 " + what + " must be " + KEY_BYTES + " bytes", null);
        }
    }

    private static byte[] bigIntToLe(BigInteger value, int len) {
        byte[] be = value.toByteArray();
        byte[] le = new byte[len];
        for (int i = 0; i < be.length && i < len; i++) {
            le[i] = be[be.length - 1 - i];
        }
        return le;
    }

    private static BigInteger leToBigInt(byte[] le) {
        byte[] be = new byte[le.length];
        for (int i = 0; i < le.length; i++) {
            be[i] = le[le.length - 1 - i];
        }
        return new BigInteger(1, Arrays.copyOf(be, be.length));
    }

    private static AltsException failure(String what, Throwable cause) {
        return new AltsException(AltsFailure.of(AltsFailure.Kind.CRYPTO, "Vault crypto: " + what), cause);
    }
}

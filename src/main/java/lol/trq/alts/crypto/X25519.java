package lol.trq.alts.crypto;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;
import javax.crypto.KeyAgreement;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure;

/**
 * X25519 (Curve25519 ECDH) key generation, agreement, and raw 32-byte key encoding via the JDK's
 * built-in {@code XDH} provider. Raw little-endian 32-byte encodings (RFC 7748) are used on the wire
 * so member public keys are compact and provider-portable.
 *
 * @author trq
 * @since 0.2.0
 */
public final class X25519 {

    /** Raw key length, in bytes. */
    public static final int KEY_BYTES = 32;

    private X25519() {}

    /**
     * Generates a fresh X25519 key pair.
     *
     * @return a new key pair
     * @throws AltsException of kind {@code CRYPTO} if key generation fails
     */
    public static KeyPair newKeyPair() {
        try {
            return KeyPairGenerator.getInstance("X25519").generateKeyPair();
        } catch (Exception e) {
            throw failure("X25519 keygen failed", e);
        }
    }

    /**
     * Performs ECDH, producing the raw 32-byte shared secret.
     *
     * @param ownPrivate this party's private key
     * @param peerPublic the peer's public key
     * @return the 32-byte shared secret
     * @throws AltsException of kind {@code CRYPTO} if agreement fails
     */
    public static byte[] agree(PrivateKey ownPrivate, PublicKey peerPublic) {
        try {
            KeyAgreement ka = KeyAgreement.getInstance("XDH");
            ka.init(ownPrivate);
            ka.doPhase(peerPublic, true);
            return ka.generateSecret();
        } catch (Exception e) {
            throw failure("X25519 agreement failed", e);
        }
    }

    /**
     * Encodes a public key to its raw 32-byte little-endian u-coordinate.
     *
     * @param publicKey the X25519 public key
     * @return the raw 32-byte encoding
     * @throws AltsException of kind {@code CRYPTO} if the key is not an X25519 key
     */
    public static byte[] encodePublicKey(PublicKey publicKey) {
        if (!(publicKey instanceof XECPublicKey xec)) {
            throw failure("not an X25519 public key", null);
        }
        return bigIntToLe(xec.getU(), KEY_BYTES);
    }

    /**
     * Decodes a raw 32-byte little-endian u-coordinate into a public key.
     *
     * @param raw the raw 32-byte encoding
     * @return the X25519 public key
     * @throws AltsException of kind {@code CRYPTO} if decoding fails
     */
    public static PublicKey decodePublicKey(byte[] raw) {
        requireLen(raw, "public key");
        try {
            BigInteger u = leToBigInt(raw);
            KeyFactory kf = KeyFactory.getInstance("XDH");
            return kf.generatePublic(new XECPublicKeySpec(NamedParameterSpec.X25519, u));
        } catch (Exception e) {
            throw failure("X25519 public key decode failed", e);
        }
    }

    /**
     * Encodes a private key to its raw 32-byte scalar.
     *
     * @param privateKey the X25519 private key
     * @return the raw 32-byte scalar
     * @throws AltsException of kind {@code CRYPTO} if the scalar is unavailable
     */
    public static byte[] encodePrivateKey(PrivateKey privateKey) {
        if (!(privateKey instanceof XECPrivateKey xec)) {
            throw failure("not an X25519 private key", null);
        }
        return xec.getScalar().orElseThrow(() -> failure("X25519 scalar not extractable", null));
    }

    /**
     * Decodes a raw 32-byte scalar into a private key.
     *
     * @param raw the raw 32-byte scalar
     * @return the X25519 private key
     * @throws AltsException of kind {@code CRYPTO} if decoding fails
     */
    public static PrivateKey decodePrivateKey(byte[] raw) {
        requireLen(raw, "private key");
        try {
            KeyFactory kf = KeyFactory.getInstance("XDH");
            return kf.generatePrivate(new XECPrivateKeySpec(NamedParameterSpec.X25519, raw.clone()));
        } catch (Exception e) {
            throw failure("X25519 private key decode failed", e);
        }
    }

    /**
     * Derives the public key that belongs to a private key, by multiplying the Curve25519 base point by
     * the private scalar. Lets a caller check that a public key it was handed really pairs with the
     * private key it holds.
     *
     * @param privateKey the X25519 private key
     * @return the matching X25519 public key
     * @throws AltsException of kind {@code CRYPTO} if the derivation fails
     * @since 0.12.0
     */
    public static PublicKey derivePublicKey(PrivateKey privateKey) {
        byte[] basePoint = new byte[KEY_BYTES];
        basePoint[0] = 9;
        return decodePublicKey(agree(privateKey, decodePublicKey(basePoint)));
    }

    private static void requireLen(byte[] raw, String what) {
        if (raw == null || raw.length != KEY_BYTES) {
            throw failure("X25519 " + what + " must be " + KEY_BYTES + " bytes", null);
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
        return new BigInteger(1, be);
    }

    private static AltsException failure(String what, Throwable cause) {
        return new AltsException(AltsFailure.of(AltsFailure.Kind.CRYPTO, "Vault crypto: " + what), cause);
    }
}

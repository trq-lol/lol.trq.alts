package lol.trq.alts.internal.avp;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.EdECPrivateKey;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * Ed25519 over raw keys, with the strict verification of AVP SPEC 2.
 *
 * <p>Every AVP signature is verified strictly, so that every implementation accepts exactly the same
 * signatures. Before any other check the verifier rejects a public key {@code A} or signature half
 * {@code R} that is the encoding of a small-order point or a non-canonical encoding ({@code y >= p}),
 * and a scalar {@code S >= L}. A signature that passes then has to satisfy the cofactorless equation:
 * the encoding of {@code [S]B - [k]A} equals {@code R} byte for byte.
 *
 * <p>The JDK's {@code Ed25519} verification is cofactorless and compares by encoding, but it makes none
 * of the point checks, so on its own it accepts a forgery under a small-order key that has no private
 * key (the strict cases of the conformance vectors {@code negative.json}). This class makes the checks
 * first and only then asks the JDK.
 *
 * <p>Ported from the Alt Vault Protocol reference implementation (MIT).
 *
 * @author trq
 * @since 1.0.0
 */
public final class Ed25519Strict {

    private static final byte[] SPKI_PREFIX = HexFormat.of().parseHex("302a300506032b6570032100");
    private static final byte[] PKCS8_PREFIX = HexFormat.of().parseHex("302e020100300506032b657004220420");

    /** The field prime {@code p = 2^255 - 19}. */
    private static final BigInteger P = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));

    /** The prime order {@code L} of the base point. */
    private static final BigInteger L =
            BigInteger.ONE.shiftLeft(252).add(new BigInteger("27742317777372353535851937790883648493"));

    /**
     * The seven small-order encodings of SPEC 2, compared with the sign bit cleared: {@code y} = 0 (order
     * 4), 1 (the identity), the two order-8 values, {@code p - 1} (order 2), and the non-canonical
     * {@code p} and {@code p + 1}.
     */
    private static final byte[][] SMALL_ORDER = {
        HexFormat.of().parseHex("0000000000000000000000000000000000000000000000000000000000000000"),
        HexFormat.of().parseHex("0100000000000000000000000000000000000000000000000000000000000000"),
        HexFormat.of().parseHex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
        HexFormat.of().parseHex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
        HexFormat.of().parseHex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        HexFormat.of().parseHex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        HexFormat.of().parseHex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
    };

    private Ed25519Strict() {}

    /**
     * Verifies a signature strictly (SPEC 2).
     *
     * @param publicKey the raw 32-byte public key
     * @param message the signed message, a CE string of one of the SPEC 4.1 constructions
     * @param signature the raw 64-byte signature
     * @return true only if the strict checks pass and the signature verifies; never throws
     */
    public static boolean verify(byte[] publicKey, byte[] message, byte[] signature) {
        if (publicKey == null || message == null || signature == null || !strictInputsOk(publicKey, signature)) {
            return false;
        }
        try {
            PublicKey key = KeyFactory.getInstance("Ed25519")
                    .generatePublic(new X509EncodedKeySpec(AvpBytes.concat(SPKI_PREFIX, publicKey)));
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(key);
            verifier.update(message);
            return verifier.verify(signature);
        } catch (GeneralSecurityException | RuntimeException notValid) {
            // A key that is not a point, or a malformed signature, does not verify.
            return false;
        }
    }

    /**
     * The strict checks of SPEC 2 on their own: lengths 32 and 64, neither {@code A} nor {@code R} of
     * small order or non-canonical, and {@code S < L}.
     *
     * @param publicKey the raw public key
     * @param signature the raw signature
     * @return whether every check passes
     */
    static boolean strictInputsOk(byte[] publicKey, byte[] signature) {
        if (publicKey.length != 32 || signature.length != 64) {
            return false;
        }
        byte[] r = Arrays.copyOfRange(signature, 0, 32);
        if (isSmallOrder(publicKey) || !isCanonical(publicKey) || isSmallOrder(r) || !isCanonical(r)) {
            return false;
        }
        return littleEndian(Arrays.copyOfRange(signature, 32, 64)).compareTo(L) < 0;
    }

    private static boolean isSmallOrder(byte[] point) {
        for (byte[] blocked : SMALL_ORDER) {
            int diff = (point[31] & 0x7f) ^ blocked[31];
            for (int k = 0; k < 31; k++) {
                diff |= point[k] ^ blocked[k];
            }
            if (diff == 0) {
                return true;
            }
        }
        return false;
    }

    private static boolean isCanonical(byte[] point) {
        byte[] y = point.clone();
        y[31] &= 0x7f;
        return littleEndian(y).compareTo(P) < 0;
    }

    private static BigInteger littleEndian(byte[] b) {
        byte[] be = new byte[b.length];
        for (int k = 0; k < b.length; k++) {
            be[k] = b[b.length - 1 - k];
        }
        return new BigInteger(1, be);
    }

    /**
     * Signs a message (RFC 8032, deterministic).
     *
     * @param seed the signer's 32-byte RFC 8032 seed
     * @param message the message, a CE string of one of the SPEC 4.1 constructions
     * @return the raw 64-byte signature
     * @throws lol.trq.alts.AltsException of kind {@code CRYPTO} if the seed has the wrong length or the
     *     provider fails
     */
    public static byte[] sign(byte[] seed, byte[] message) {
        if (seed.length != 32) {
            throw AvpFailures.crypto("an Ed25519 seed is 32 bytes", null);
        }
        byte[] pkcs8 = AvpBytes.concat(PKCS8_PREFIX, seed);
        try {
            PrivateKey key = KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(key);
            signer.update(message);
            return signer.sign();
        } catch (GeneralSecurityException | RuntimeException e) {
            throw AvpFailures.crypto("Ed25519 signing failed", e);
        } finally {
            Arrays.fill(pkcs8, (byte) 0);
        }
    }

    /**
     * The raw public key of a seed. The JCA has no seed-to-public call, so this runs the key pair
     * generator with a random source that yields exactly the seed, then checks the private key it made is
     * the seed.
     *
     * @param seed the 32-byte seed
     * @return the raw 32-byte public key
     * @throws lol.trq.alts.AltsException of kind {@code CRYPTO} if the seed has the wrong length or the
     *     provider does not draw the key from the seed
     */
    public static byte[] publicKey(byte[] seed) {
        if (seed.length != 32) {
            throw AvpFailures.crypto("an Ed25519 seed is 32 bytes", null);
        }
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
            generator.initialize(NamedParameterSpec.ED25519, new SeedRandom(seed));
            KeyPair pair = generator.generateKeyPair();
            byte[] made = ((EdECPrivateKey) pair.getPrivate()).getBytes().orElse(new byte[0]);
            boolean fromSeed = MessageDigest.isEqual(made, seed);
            Arrays.fill(made, (byte) 0);
            if (!fromSeed) {
                throw AvpFailures.crypto("the Ed25519 provider did not use the seed", null);
            }
            byte[] spki = pair.getPublic().getEncoded();
            return Arrays.copyOfRange(spki, spki.length - 32, spki.length);
        } catch (GeneralSecurityException | IllegalStateException | ClassCastException e) {
            throw AvpFailures.crypto("Ed25519 key derivation failed", e);
        }
    }

    /** A random source that yields one fixed 32-byte seed, once. */
    private static final class SeedRandom extends SecureRandom {
        private static final long serialVersionUID = 1L;
        private final byte[] seed;
        private boolean used;

        SeedRandom(byte[] seed) {
            this.seed = seed.clone();
        }

        @Override
        public synchronized void nextBytes(byte[] bytes) {
            if (used || bytes.length != seed.length) {
                throw new IllegalStateException("the seed source serves one 32-byte draw");
            }
            used = true;
            System.arraycopy(seed, 0, bytes, 0, seed.length);
            Arrays.fill(seed, (byte) 0);
        }
    }
}

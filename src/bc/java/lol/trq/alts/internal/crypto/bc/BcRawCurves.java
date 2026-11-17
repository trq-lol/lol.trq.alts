package lol.trq.alts.internal.crypto.bc;

import java.security.SecureRandom;
import lol.trq.alts.internal.crypto.RawCurves;
import org.bouncycastle.math.ec.rfc7748.X25519;
import org.bouncycastle.math.ec.rfc8032.Ed25519;

/** {@link RawCurves} over the Bouncy Castle low-level RFC 8032 and RFC 7748 implementations. */
public final class BcRawCurves implements RawCurves {

    private static final SecureRandom RANDOM = new SecureRandom();

    public BcRawCurves() {}

    @Override
    public byte[] edNewSeed() {
        byte[] seed = new byte[32];
        Ed25519.generatePrivateKey(RANDOM, seed);
        return seed;
    }

    @Override
    public byte[] edPublic(byte[] seed) {
        byte[] pk = new byte[32];
        Ed25519.generatePublicKey(seed, 0, pk, 0);
        return pk;
    }

    @Override
    public byte[] edSign(byte[] seed, byte[] message) {
        byte[] sig = new byte[64];
        Ed25519.sign(seed, 0, message, 0, message.length, sig, 0);
        return sig;
    }

    @Override
    public boolean edVerify(byte[] publicKey, byte[] message, byte[] signature) {
        try {
            return Ed25519.verify(signature, 0, publicKey, 0, message, 0, message.length);
        } catch (RuntimeException notValid) {
            return false;
        }
    }

    @Override
    public byte[] xNewScalar() {
        byte[] k = new byte[32];
        X25519.generatePrivateKey(RANDOM, k);
        return k;
    }

    @Override
    public byte[] xPublic(byte[] scalar) {
        byte[] pk = new byte[32];
        X25519.generatePublicKey(scalar, 0, pk, 0);
        return pk;
    }

    @Override
    public byte[] xAgree(byte[] scalar, byte[] peerPublic) {
        byte[] out = new byte[32];
        return X25519.calculateAgreement(scalar, 0, peerPublic, 0, out, 0) ? out : null;
    }
}

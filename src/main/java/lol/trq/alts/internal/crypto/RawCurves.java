package lol.trq.alts.internal.crypto;

/**
 * Ed25519 and X25519 over raw bytes, for runtimes without the JCA curves. The implementation lives outside the
 * main sources (the Java 8 build adds it, over Bouncy Castle), so the main sources need no extra library;
 * {@link BcCurves} loads it by name.
 */
public interface RawCurves {

    byte[] edNewSeed();

    byte[] edPublic(byte[] seed);

    byte[] edSign(byte[] seed, byte[] message);

    boolean edVerify(byte[] publicKey, byte[] message, byte[] signature);

    byte[] xNewScalar();

    byte[] xPublic(byte[] scalar);

    /** The shared secret, or null when it is all zeros (a small-order peer point). */
    byte[] xAgree(byte[] scalar, byte[] peerPublic);
}

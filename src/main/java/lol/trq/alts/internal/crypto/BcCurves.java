package lol.trq.alts.internal.crypto;

/**
 * The raw-byte Ed25519 and X25519 path, used only when {@link Curves#raw()}. It delegates to the
 * {@link RawCurves} implementation the Java 8 build bundles ({@code lol.trq.alts.internal.crypto.bc.BcRawCurves},
 * over Bouncy Castle), loaded by name the first time it is needed, so a build without it never touches it.
 */
public final class BcCurves {

    private static final String IMPLEMENTATION = "lol.trq.alts.internal.crypto.bc.BcRawCurves";

    private BcCurves() {}

    /** Whether the raw-byte path is in use on this runtime. */
    public static boolean active() {
        return Curves.raw();
    }

    static byte[] edNewSeed() {
        return Holder.CURVES.edNewSeed();
    }

    /** The raw public key of a 32-byte Ed25519 seed. */
    public static byte[] edPublic(byte[] seed) {
        return Holder.CURVES.edPublic(seed);
    }

    /** A deterministic RFC 8032 signature by a 32-byte seed. */
    public static byte[] edSign(byte[] seed, byte[] message) {
        return Holder.CURVES.edSign(seed, message);
    }

    /** Verifies a 64-byte signature by a raw 32-byte public key; any malformed input is simply false. */
    public static boolean edVerify(byte[] publicKey, byte[] message, byte[] signature) {
        if (publicKey.length != 32 || signature.length != 64) {
            return false;
        }
        return Holder.CURVES.edVerify(publicKey, message, signature);
    }

    static byte[] xNewScalar() {
        return Holder.CURVES.xNewScalar();
    }

    static byte[] xPublic(byte[] scalar) {
        return Holder.CURVES.xPublic(scalar);
    }

    /** The X25519 shared secret, or null when it is all zeros (a small-order peer point). */
    public static byte[] xAgree(byte[] scalar, byte[] peerPublic) {
        return Holder.CURVES.xAgree(scalar, peerPublic);
    }

    private static final class Holder {
        static final RawCurves CURVES = load();

        private static RawCurves load() {
            try {
                return (RawCurves)
                        Class.forName(IMPLEMENTATION).getDeclaredConstructor().newInstance();
            } catch (ReflectiveOperationException | LinkageError absent) {
                throw new IllegalStateException(
                        "this runtime has no JCA Ed25519/X25519 and this build bundles no fallback: use the jdk8 build",
                        absent);
            }
        }
    }
}

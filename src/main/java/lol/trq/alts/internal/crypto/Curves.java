package lol.trq.alts.internal.crypto;

/**
 * Which implementation of Ed25519 and X25519 this runtime uses.
 *
 * <p>The JDK provides both curves from Java 15 (Ed25519) and 11 (X25519), and that is the default. On an older
 * runtime, where the JCA has neither, the library falls back to the Bouncy Castle low-level implementations,
 * which the Java 8 build bundles. The system property {@code lol.trq.alts.curves=bc} forces the fallback on
 * any runtime, so the whole suite can exercise it.
 */
final class Curves {

    private static final boolean RAW = forced() || !jcaHasCurves();

    private Curves() {}

    /** Whether keys are raw-byte keys handled by Bouncy Castle rather than JCA keys. */
    static boolean raw() {
        return RAW;
    }

    private static boolean forced() {
        return "bc".equals(System.getProperty("lol.trq.alts.curves"));
    }

    private static boolean jcaHasCurves() {
        try {
            Class.forName("java.security.spec.EdECPoint");
            Class.forName("java.security.spec.XECPublicKeySpec");
            return true;
        } catch (ClassNotFoundException absent) {
            return false;
        }
    }
}

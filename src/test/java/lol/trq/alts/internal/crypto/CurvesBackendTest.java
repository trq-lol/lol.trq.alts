package lol.trq.alts.internal.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.security.KeyPair;
import org.junit.jupiter.api.Test;

class CurvesBackendTest {

    private static final boolean FORCED_BC = "bc".equals(System.getProperty("lol.trq.alts.curves"));

    @Test
    void theForcedPropertySelectsTheRawPath() {
        assertEquals(FORCED_BC || !jcaHasCurves(), BcCurves.active());
        if (FORCED_BC) {
            assertTrue(Ed25519.newKeyPair().getPublic() instanceof RawKeys.Public, "keys are raw keys");
        }
    }

    @Test
    void rawKeysEncodeAsStandardSpkiAndPkcs8() {
        KeyPair ed = Ed25519.newKeyPair();
        byte[] raw = Ed25519.encodePublicKey(ed.getPublic());
        byte[] spki = ed.getPublic().getEncoded();
        assertEquals(44, spki.length);
        assertArrayEquals(raw, java.util.Arrays.copyOfRange(spki, 12, 44));

        KeyPair x = X25519.newKeyPair();
        byte[] xraw = X25519.encodePublicKey(x.getPublic());
        byte[] xspki = x.getPublic().getEncoded();
        assertEquals(44, xspki.length);
        assertArrayEquals(xraw, java.util.Arrays.copyOfRange(xspki, 12, 44));
    }

    @Test
    void bothPathsAgreeOnAKnownSeed() {
        // The Bouncy Castle fallback is a separate source set: present on the class path and in the jdk8 jar,
        // absent from the module-path run, which tests the main jar alone.
        assumeTrue(fallbackPresent(), "the Bouncy Castle fallback is not on this path");
        byte[] seed = new byte[32];
        for (int i = 0; i < 32; i++) {
            seed[i] = (byte) i;
        }
        byte[] message = "avp".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] pkBc = BcCurves.edPublic(seed);
        byte[] sigBc = BcCurves.edSign(seed, message);
        byte[] pk = Ed25519.encodePublicKey(Ed25519.decodePublicKey(pkBc));
        assertArrayEquals(pkBc, pk);
        assertTrue(Ed25519.verify(Ed25519.decodePublicKey(pk), message, sigBc));
        assertArrayEquals(sigBc, Ed25519.sign(Ed25519.decodePrivateKey(seed), message), "RFC 8032 is deterministic");
    }

    private static boolean fallbackPresent() {
        try {
            Class.forName("lol.trq.alts.internal.crypto.bc.BcRawCurves");
            return true;
        } catch (ClassNotFoundException absent) {
            return false;
        }
    }

    private static boolean jcaHasCurves() {
        try {
            Class.forName("java.security.spec.EdECPoint");
            return true;
        } catch (ClassNotFoundException absent) {
            return false;
        }
    }
}

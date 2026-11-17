package lol.trq.alts.internal.avp;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

/**
 * SPEC 2 requires the cofactorless equation {@code [S]B = R + [k]A}. A cofactored verifier ({@code [8][S]B =
 * [8]R + [8k]A}) also accepts a signature made over a mixed-order key {@code A' = A + T} (T of order 8) whenever
 * {@code k} is not a multiple of 8; the strict pre-checks do not catch it, because {@code A'} is neither small-order
 * nor non-canonical. Every verification path (the JCA one, and the raw-byte one the Java 8 build uses) must reject
 * it.
 */
class MixedOrderVerifyTest {

    private static final BigInteger P = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
    private static final BigInteger L =
            BigInteger.ONE.shiftLeft(252).add(new BigInteger("27742317777372353535851937790883648493"));
    private static final BigInteger D = BigInteger.valueOf(-121665)
            .multiply(BigInteger.valueOf(121666).modInverse(P))
            .mod(P);
    private static final BigInteger SQRT_M1 =
            BigInteger.valueOf(2).modPow(P.subtract(BigInteger.ONE).shiftRight(2), P);
    private static final BigInteger[] BASE =
            decode(hex("5866666666666666666666666666666666666666666666666666666666666666"));
    /** An order-8 point (one of the SPEC 2 small-order encodings). */
    private static final BigInteger[] T8 =
            decode(hex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"));

    @Test
    void theTorsionPointHasOrderEight() {
        assertTrue(isIdentity(mul(BigInteger.valueOf(8), T8)));
        assertFalse(isIdentity(mul(BigInteger.valueOf(4), T8)));
    }

    @Test
    void aSignatureOnlyACofactoredVerifierAcceptsIsRejected() throws Exception {
        BigInteger a = new BigInteger("1234567890123456789012345678901234567890").mod(L);
        BigInteger r = new BigInteger("9876543210987654321098765432109876543210").mod(L);
        BigInteger[] mixedKey = add(mul(a, BASE), T8);
        byte[] aEnc = encode(mixedKey);
        byte[] rEnc = encode(mul(r, BASE));
        for (int i = 0; ; i++) {
            byte[] message = ("mixed-order " + i).getBytes(StandardCharsets.UTF_8);
            BigInteger k = littleEndian(sha512(rEnc, aEnc, message)).mod(L);
            if (k.mod(BigInteger.valueOf(8)).signum() == 0) {
                continue; // the torsion term vanishes; both equations agree
            }
            BigInteger s = r.add(k.multiply(a)).mod(L);
            byte[] signature = Arrays.copyOf(rEnc, 64);
            System.arraycopy(toLittleEndian(s), 0, signature, 32, 32);

            // Cofactored acceptance, computed here: [8][S]B == [8]R + [8k]A'.
            BigInteger eight = BigInteger.valueOf(8);
            assertTrue(equal(
                    mul(eight, mul(s, BASE)), add(mul(eight, mul(r, BASE)), mul(eight.multiply(k), mixedKey))));
            assertTrue(Ed25519Strict.strictInputsOk(aEnc, signature), "the pre-checks pass a mixed-order key");

            assertFalse(Ed25519Strict.verify(aEnc, message, signature), "the cofactorless equation must reject it");
            return;
        }
    }

    // --- Edwards25519 over BigInteger, affine; test-only ---

    private static BigInteger[] add(BigInteger[] p, BigInteger[] q) {
        BigInteger x1 = p[0], y1 = p[1], x2 = q[0], y2 = q[1];
        BigInteger dxy = D.multiply(x1).multiply(x2).multiply(y1).multiply(y2).mod(P);
        BigInteger x3 = x1.multiply(y2)
                .add(x2.multiply(y1))
                .multiply(BigInteger.ONE.add(dxy).modInverse(P))
                .mod(P);
        BigInteger y3 = y1.multiply(y2)
                .add(x1.multiply(x2))
                .multiply(BigInteger.ONE.subtract(dxy).mod(P).modInverse(P))
                .mod(P);
        return new BigInteger[] {x3, y3};
    }

    private static BigInteger[] mul(BigInteger n, BigInteger[] p) {
        BigInteger[] result = {BigInteger.ZERO, BigInteger.ONE};
        BigInteger[] addend = p;
        for (int i = 0; i < n.bitLength(); i++) {
            if (n.testBit(i)) {
                result = add(result, addend);
            }
            addend = add(addend, addend);
        }
        return result;
    }

    private static boolean isIdentity(BigInteger[] p) {
        return p[0].signum() == 0 && p[1].equals(BigInteger.ONE);
    }

    private static boolean equal(BigInteger[] p, BigInteger[] q) {
        return p[0].equals(q[0]) && p[1].equals(q[1]);
    }

    private static BigInteger[] decode(byte[] enc) {
        byte[] yBytes = enc.clone();
        boolean xOdd = (yBytes[31] & 0x80) != 0;
        yBytes[31] &= 0x7f;
        BigInteger y = littleEndian(yBytes);
        BigInteger y2 = y.multiply(y).mod(P);
        BigInteger u = y2.subtract(BigInteger.ONE).mod(P);
        BigInteger v = D.multiply(y2).add(BigInteger.ONE).mod(P);
        BigInteger x2 = u.multiply(v.modInverse(P)).mod(P);
        BigInteger x = x2.modPow(P.add(BigInteger.valueOf(3)).shiftRight(3), P);
        if (!x.multiply(x).mod(P).equals(x2)) {
            x = x.multiply(SQRT_M1).mod(P);
        }
        if (x.testBit(0) != xOdd) {
            x = P.subtract(x).mod(P);
        }
        return new BigInteger[] {x, y};
    }

    private static byte[] encode(BigInteger[] p) {
        byte[] out = toLittleEndian(p[1]);
        if (p[0].testBit(0)) {
            out[31] |= (byte) 0x80;
        }
        return out;
    }

    private static byte[] sha512(byte[]... parts) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        for (byte[] part : parts) {
            digest.update(part);
        }
        return digest.digest();
    }

    private static BigInteger littleEndian(byte[] le) {
        byte[] be = new byte[le.length];
        for (int i = 0; i < le.length; i++) {
            be[i] = le[le.length - 1 - i];
        }
        return new BigInteger(1, be);
    }

    private static byte[] toLittleEndian(BigInteger v) {
        byte[] be = v.toByteArray();
        byte[] le = new byte[32];
        for (int i = 0; i < be.length && i < 32; i++) {
            le[i] = be[be.length - 1 - i];
        }
        return le;
    }

    private static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }
}

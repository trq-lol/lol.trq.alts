package lol.trq.alts.internal.avp;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * The SPEC 2 cofactorless Ed25519 equation, computed directly: decode {@code A}, compute {@code [S]B - [k]A}, and
 * compare its encoding with {@code R} byte for byte.
 *
 * <p>Used on the raw-byte path (runtimes without the JCA curves). Bouncy Castle's verifier uses the cofactored
 * equation, which also accepts signatures over mixed-order keys that SPEC 2 rejects; the JCA verifier is
 * cofactorless already. Plain {@link BigInteger} arithmetic in extended coordinates; correctness over speed.
 */
public final class Ed25519Cofactorless {

    private static final BigInteger P = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
    private static final BigInteger L =
            BigInteger.ONE.shiftLeft(252).add(new BigInteger("27742317777372353535851937790883648493"));
    private static final BigInteger D = BigInteger.valueOf(-121665)
            .multiply(BigInteger.valueOf(121666).modInverse(P))
            .mod(P);
    private static final BigInteger D2 = D.shiftLeft(1).mod(P);
    private static final BigInteger SQRT_M1 =
            BigInteger.valueOf(2).modPow(P.subtract(BigInteger.ONE).shiftRight(2), P);
    private static final BigInteger[] BASE =
            decode(hex("5866666666666666666666666666666666666666666666666666666666666666"));

    private Ed25519Cofactorless() {}

    /**
     * Whether {@code [S]B - [k]A} encodes to {@code R}, with {@code k = SHA-512(R || A || M) mod L}. The SPEC 2
     * strict input checks are the caller's; this is only the equation.
     */
    public static boolean verify(byte[] publicKey, byte[] message, byte[] signature) {
        if (publicKey.length != 32 || signature.length != 64) {
            return false;
        }
        BigInteger[] a = decode(publicKey);
        if (a == null) {
            return false;
        }
        byte[] r = Arrays.copyOfRange(signature, 0, 32);
        BigInteger s = littleEndian(Arrays.copyOfRange(signature, 32, 64));
        if (s.compareTo(L) >= 0) {
            // Malleable: S and S + L satisfy the same equation. RFC 8032 and the JCA verifier reject it.
            return false;
        }
        BigInteger k = littleEndian(sha512(r, publicKey, message)).mod(L);
        BigInteger[] check = add(mul(s, BASE), mul(k, negate(a)));
        return MessageDigest.isEqual(encode(check), r);
    }

    // Extended coordinates (X, Y, Z, T), x = X/Z, y = Y/Z, xy = T/Z; formulas from RFC 8032 section 5.1.4.

    private static BigInteger[] add(BigInteger[] p, BigInteger[] q) {
        BigInteger a = p[1].subtract(p[0]).multiply(q[1].subtract(q[0])).mod(P);
        BigInteger b = p[1].add(p[0]).multiply(q[1].add(q[0])).mod(P);
        BigInteger c = p[3].multiply(D2).multiply(q[3]).mod(P);
        BigInteger d = p[2].shiftLeft(1).multiply(q[2]).mod(P);
        BigInteger e = b.subtract(a);
        BigInteger f = d.subtract(c);
        BigInteger g = d.add(c);
        BigInteger h = b.add(a);
        return new BigInteger[] {
            e.multiply(f).mod(P),
            g.multiply(h).mod(P),
            f.multiply(g).mod(P),
            e.multiply(h).mod(P)
        };
    }

    private static BigInteger[] mul(BigInteger n, BigInteger[] p) {
        BigInteger[] result = {BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE, BigInteger.ZERO};
        BigInteger[] addend = p;
        for (int i = 0; i < n.bitLength(); i++) {
            if (n.testBit(i)) {
                result = add(result, addend);
            }
            addend = add(addend, addend);
        }
        return result;
    }

    private static BigInteger[] negate(BigInteger[] p) {
        return new BigInteger[] {
            P.subtract(p[0]).mod(P), p[1], p[2], P.subtract(p[3]).mod(P)
        };
    }

    /** RFC 8032 decoding; null if the bytes are not a point. */
    private static BigInteger[] decode(byte[] enc) {
        if (enc.length != 32) {
            return null;
        }
        byte[] yBytes = enc.clone();
        boolean xOdd = (yBytes[31] & 0x80) != 0;
        yBytes[31] &= 0x7f;
        BigInteger y = littleEndian(yBytes);
        if (y.compareTo(P) >= 0) {
            return null;
        }
        BigInteger y2 = y.multiply(y).mod(P);
        BigInteger u = y2.subtract(BigInteger.ONE).mod(P);
        BigInteger v = D.multiply(y2).add(BigInteger.ONE).mod(P);
        BigInteger x2 = u.multiply(v.modInverse(P)).mod(P);
        BigInteger x = x2.modPow(P.add(BigInteger.valueOf(3)).shiftRight(3), P);
        if (!x.multiply(x).mod(P).equals(x2)) {
            x = x.multiply(SQRT_M1).mod(P);
            if (!x.multiply(x).mod(P).equals(x2)) {
                return null;
            }
        }
        if (x.signum() == 0 && xOdd) {
            return null;
        }
        if (x.testBit(0) != xOdd) {
            x = P.subtract(x);
        }
        return new BigInteger[] {x, y, BigInteger.ONE, x.multiply(y).mod(P)};
    }

    private static byte[] encode(BigInteger[] p) {
        BigInteger zInv = p[2].modInverse(P);
        BigInteger x = p[0].multiply(zInv).mod(P);
        BigInteger y = p[1].multiply(zInv).mod(P);
        byte[] out = toLittleEndian(y);
        if (x.testBit(0)) {
            out[31] |= (byte) 0x80;
        }
        return out;
    }

    private static byte[] sha512(byte[] r, byte[] a, byte[] m) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-512");
            digest.update(r);
            digest.update(a);
            digest.update(m);
            return digest.digest();
        } catch (NoSuchAlgorithmException absent) {
            throw new IllegalStateException("SHA-512 is required of every Java platform", absent);
        }
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

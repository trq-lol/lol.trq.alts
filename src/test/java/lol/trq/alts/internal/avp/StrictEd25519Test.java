package lol.trq.alts.internal.avp;

import static lol.trq.alts.internal.avp.Vectors.hex;
import static lol.trq.alts.internal.avp.Vectors.str;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonObject;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Strict Ed25519 verification (SPEC 2) against the {@code ed25519-verify} cases of {@code negative.json}:
 * the three mutations of the RFC 8032 signature and the six strict rejects a plain cofactorless verifier
 * accepts (small-order or non-canonical {@code A} and {@code R}, and {@code S >= L}).
 */
class StrictEd25519Test {

    private static final BigInteger L =
            BigInteger.ONE.shiftLeft(252).add(new BigInteger("27742317777372353535851937790883648493"));

    private static List<JsonObject> verifyCases() {
        return Vectors.cases(Vectors.load("negative.json"), "cases", 34).stream()
                .filter(c -> str(c, "op").equals("ed25519-verify"))
                .toList();
    }

    @Test
    void everyEd25519RejectIsRejected() {
        List<JsonObject> cases = verifyCases();
        assertEquals(9, cases.size(), "three mutations and six strict rejects");
        for (JsonObject c : cases) {
            assertFalse(
                    Ed25519Strict.verify(hex(c, "publicKeyHex"), hex(c, "messageHex"), hex(c, "signatureHex")),
                    str(c, "name"));
        }
    }

    @Test
    void eachStrictRejectFailsAPreCheckOfSpecTwo() {
        List<String> strict = List.of(
                "ed25519/identity-key-forgery",
                "ed25519/order-8-key-forgery",
                "ed25519/identity-r",
                "ed25519/s-plus-l",
                "ed25519/non-canonical-key",
                "ed25519/order-8-sign-bit-key-forgery");
        for (JsonObject c : verifyCases()) {
            String name = str(c, "name");
            boolean preChecked = !Ed25519Strict.strictInputsOk(hex(c, "publicKeyHex"), hex(c, "signatureHex"));
            assertEquals(strict.contains(name), preChecked, name);
        }
    }

    /** SPEC 2: {@code S} must be below {@code L}; {@code S == L} itself is refused. */
    @Test
    void anSEqualToLIsRefused() {
        byte[] key = Vectors.hex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        byte[] sig = Vectors.hex("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
                + "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
        assertTrue(Ed25519Strict.strictInputsOk(key, sig));
        System.arraycopy(reverse(toFixed(L)), 0, sig, 32, 32);
        assertFalse(Ed25519Strict.strictInputsOk(key, sig));
        System.arraycopy(reverse(toFixed(L.subtract(BigInteger.ONE))), 0, sig, 32, 32);
        assertTrue(Ed25519Strict.strictInputsOk(key, sig), "L - 1 passes the pre-check");
    }

    /** A null argument is a caller's bug, not a signature that fails. */
    @Test
    void aNullArgumentIsRefusedAsNull() {
        byte[] b = new byte[32];
        assertThrows(NullPointerException.class, () -> Ed25519Strict.verify(null, b, new byte[64]));
        assertThrows(NullPointerException.class, () -> Ed25519Strict.verify(b, null, new byte[64]));
        assertThrows(NullPointerException.class, () -> Ed25519Strict.verify(b, b, null));
        assertThrows(NullPointerException.class, () -> Challenge.verify(null, b, b, new byte[64]));
        assertThrows(NullPointerException.class, () -> Challenge.verify(b, b, null, new byte[64]));
    }

    /** {@code s-plus-l} is a valid signature with {@code L} added to {@code S}: reduced, it verifies. */
    @Test
    void sPlusLReducedIsTheValidSignature() {
        JsonObject c = verifyCases().stream()
                .filter(x -> str(x, "name").equals("ed25519/s-plus-l"))
                .findFirst()
                .orElseThrow();
        byte[] sig = hex(c, "signatureHex");
        byte[] s = Arrays.copyOfRange(sig, 32, 64);
        BigInteger value = new BigInteger(1, reverse(s));
        assertTrue(value.compareTo(L) >= 0);
        byte[] reduced = reverse(toFixed(value.subtract(L)));
        byte[] fixed = Arrays.copyOf(sig, 64);
        System.arraycopy(reduced, 0, fixed, 32, 32);
        assertTrue(Ed25519Strict.verify(hex(c, "publicKeyHex"), hex(c, "messageHex"), fixed));
    }

    /**
     * The pre-checks pinned to the SPEC 2 text, independent of the vectors: each of the seven listed
     * small-order encodings (and each with the sign bit set) is refused as {@code A} and as {@code R}, and
     * so is a non-canonical {@code y} that is not on the list ({@code p + 2} up to {@code 2^255 - 1}).
     */
    @Test
    void everySpecListedEncodingAndEveryNonCanonicalYIsRefusedAsAOrR() {
        BigInteger p = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
        List<byte[]> listed = List.of(
                new byte[32],
                le(BigInteger.ONE),
                Vectors.hex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
                Vectors.hex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
                le(p.subtract(BigInteger.ONE)),
                le(p),
                le(p.add(BigInteger.ONE)));
        List<byte[]> nonCanonical = List.of(
                le(p.add(BigInteger.TWO)),
                le(p.add(BigInteger.valueOf(18))),
                le(BigInteger.ONE.shiftLeft(255).subtract(BigInteger.ONE)));
        byte[] honestKey = Vectors.hex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        byte[] honestSig = Vectors.hex("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
                + "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
        assertTrue(Ed25519Strict.strictInputsOk(honestKey, honestSig));
        for (List<byte[]> group : List.of(listed, nonCanonical)) {
            for (byte[] encoding : group) {
                for (boolean signBit : new boolean[] {false, true}) {
                    byte[] point = encoding.clone();
                    if (signBit) {
                        point[31] |= (byte) 0x80;
                    }
                    String what = Vectors.hex(point);
                    assertFalse(Ed25519Strict.strictInputsOk(point, honestSig), what + " as A");
                    byte[] sig = honestSig.clone();
                    System.arraycopy(point, 0, sig, 0, 32);
                    assertFalse(Ed25519Strict.strictInputsOk(honestKey, sig), what + " as R");
                }
            }
        }
    }

    private static byte[] le(BigInteger v) {
        return reverse(toFixed(v));
    }

    private static byte[] reverse(byte[] b) {
        byte[] out = new byte[b.length];
        for (int k = 0; k < b.length; k++) {
            out[k] = b[b.length - 1 - k];
        }
        return out;
    }

    private static byte[] toFixed(BigInteger v) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[32];
        int n = Math.min(raw.length, 32);
        System.arraycopy(raw, raw.length - n, out, 32 - n, n);
        return out;
    }
}

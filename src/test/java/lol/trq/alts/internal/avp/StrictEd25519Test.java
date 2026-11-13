package lol.trq.alts.internal.avp;

import static lol.trq.alts.internal.avp.Vectors.hex;
import static lol.trq.alts.internal.avp.Vectors.str;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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

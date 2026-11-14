package lol.trq.alts.internal.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure;
import org.junit.jupiter.api.Test;

/** PBKDF2 derivation: accepted range, argument failures as checked exceptions, and determinism. */
class Pbkdf2Test {

    private static final byte[] SALT = "0123456789abcdef".getBytes(StandardCharsets.UTF_8);

    @Test
    void derivationIsDeterministicAndLeavesTheCallersPassphraseIntact() throws Exception {
        char[] passphrase = "correct horse".toCharArray();

        byte[] first = Pbkdf2.deriveKey(passphrase, SALT, Pbkdf2.MIN_ITERATIONS).getEncoded();
        byte[] second =
                Pbkdf2.deriveKey(passphrase, SALT, Pbkdf2.MIN_ITERATIONS).getEncoded();

        assertEquals(Pbkdf2.KEY_BITS / 8, first.length);
        assertArrayEquals(first, second);
        // Only the specification's internal copy is cleared; the caller's array is the caller's to wipe.
        assertArrayEquals("correct horse".toCharArray(), passphrase);
    }

    @Test
    void theIterationCountNewIdentitiesUseIsAccepted() {
        assertTrue(Pbkdf2.VAULT_ITERATIONS >= Pbkdf2.MIN_ITERATIONS);
        assertTrue(Pbkdf2.VAULT_ITERATIONS <= Pbkdf2.MAX_ITERATIONS);
    }

    @Test
    void rejectsIterationCountsOutsideTheAcceptedRange() {
        char[] passphrase = "pw".toCharArray();

        for (int iterations : new int[] {
            Integer.MIN_VALUE, -1, 0, 1, Pbkdf2.MIN_ITERATIONS - 1, Pbkdf2.MAX_ITERATIONS + 1, Integer.MAX_VALUE
        }) {
            assertEquals(
                    AltsFailure.Kind.INVALID_INPUT,
                    assertThrows(AltsException.class, () -> Pbkdf2.deriveKey(passphrase, SALT, iterations))
                            .kind());
        }
    }

    @Test
    void rejectsAMissingSaltOrPassphrase() {
        assertEquals(
                AltsFailure.Kind.INVALID_INPUT,
                assertThrows(AltsException.class, () -> Pbkdf2.deriveKey("pw".toCharArray(), new byte[0], 600_000))
                        .kind());
        assertEquals(
                AltsFailure.Kind.INVALID_INPUT,
                assertThrows(AltsException.class, () -> Pbkdf2.deriveKey("pw".toCharArray(), null, 600_000))
                        .kind());
        assertEquals(
                AltsFailure.Kind.INVALID_INPUT,
                assertThrows(AltsException.class, () -> Pbkdf2.deriveKey(null, SALT, 600_000))
                        .kind());
    }
}

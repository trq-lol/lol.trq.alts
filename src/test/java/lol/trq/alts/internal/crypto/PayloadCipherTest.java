package lol.trq.alts.internal.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure;
import org.junit.jupiter.api.Test;

/** AES-GCM AEAD round-trip and AAD-binding behaviour. */
class PayloadCipherTest {

    /** Some associated data that differs whenever one of its parts does. */
    private static byte[] aad(String context, long a, long b) {
        return (context + "/" + a + "/" + b).getBytes(StandardCharsets.UTF_8);
    }

    private static SecretKey aesKey() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        return kg.generateKey();
    }

    @Test
    void roundTripsUnderSameKeyAndAad() throws Exception {
        SecretKey key = aesKey();
        byte[] iv = PayloadCipher.newIv();
        byte[] aad = aad("repo-1", 3L, 0L);
        byte[] plaintext = "the alts payload".getBytes(StandardCharsets.UTF_8);

        byte[] ct = PayloadCipher.encrypt(key, iv, aad, plaintext);
        byte[] pt = PayloadCipher.decrypt(key, iv, aad, ct);

        assertArrayEquals(plaintext, pt);
    }

    @Test
    void rejectsMismatchedAad() throws Exception {
        SecretKey key = aesKey();
        byte[] iv = PayloadCipher.newIv();
        byte[] plaintext = "x".getBytes(StandardCharsets.UTF_8);

        byte[] ct = PayloadCipher.encrypt(key, iv, aad("repo-1", 3L, 0L), plaintext);

        // Different version → different AAD → tag fails.
        assertEquals(
                AltsFailure.Kind.CRYPTO,
                assertThrows(AltsException.class, () -> PayloadCipher.decrypt(key, iv, aad("repo-1", 4L, 0L), ct))
                        .kind());
        // Different epoch → tag fails.
        assertEquals(
                AltsFailure.Kind.CRYPTO,
                assertThrows(AltsException.class, () -> PayloadCipher.decrypt(key, iv, aad("repo-1", 3L, 1L), ct))
                        .kind());
        // Different repo → tag fails.
        assertEquals(
                AltsFailure.Kind.CRYPTO,
                assertThrows(AltsException.class, () -> PayloadCipher.decrypt(key, iv, aad("repo-2", 3L, 0L), ct))
                        .kind());
    }

    @Test
    void rejectsTamperedCiphertext() throws Exception {
        SecretKey key = aesKey();
        byte[] iv = PayloadCipher.newIv();
        byte[] aad = aad("r", 1L, 0L);
        byte[] ct = PayloadCipher.encrypt(key, iv, aad, "data".getBytes(StandardCharsets.UTF_8));

        ct[0] ^= 0x01;
        assertEquals(
                AltsFailure.Kind.CRYPTO,
                assertThrows(AltsException.class, () -> PayloadCipher.decrypt(key, iv, aad, ct))
                        .kind());
    }

    @Test
    void freshIvProducesDistinctCiphertext() throws Exception {
        SecretKey key = aesKey();
        byte[] aad = aad("r", 1L, 0L);
        byte[] pt = "same".getBytes(StandardCharsets.UTF_8);

        byte[] a = PayloadCipher.encrypt(key, PayloadCipher.newIv(), aad, pt);
        byte[] b = PayloadCipher.encrypt(key, PayloadCipher.newIv(), aad, pt);

        assertFalse(Arrays.equals(a, b));
    }
}

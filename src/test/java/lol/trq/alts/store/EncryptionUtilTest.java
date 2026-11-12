package lol.trq.alts.store;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class EncryptionUtilTest {

    @Test
    void roundTripsUnderSameKey() throws Exception {
        String key = "test-hardware-key";
        String plaintext = "{\"accounts\":[{\"username\":\"Steve\"}]}";

        String encrypted = EncryptionUtil.encrypt(plaintext, key);
        assertNotEquals(plaintext, encrypted);
        assertEquals(plaintext, EncryptionUtil.decrypt(encrypted, key));
    }

    @Test
    void failsUnderWrongKey() throws Exception {
        String encrypted = EncryptionUtil.encrypt("secret", "right-key");
        assertThrows(Exception.class, () -> EncryptionUtil.decrypt(encrypted, "wrong-key"));
    }

    @Test
    void freshSaltProducesDistinctCiphertext() throws Exception {
        String key = "k";
        assertNotEquals(EncryptionUtil.encrypt("same", key), EncryptionUtil.encrypt("same", key));
    }

    /** A bundle produced by the 0.11.1 release; the format must keep opening byte for byte. */
    @Test
    void opensABundleWrittenByAnEarlierRelease() throws Exception {
        String bundle =
                "JmJzGEXuHvOirV4tfESsqKLwsQuZKKRMRWwUAXsFkyojEBHWHQC570XTaNjLqWdzRAu1sBCoIMoVbscydx1lXGZ+OUZl/goq"
                        + "22Y96bJ0TPh5YthP9KC69Jx2Wq1P2DWzAUk3lsrPmr/o2dRjKm0pRuwNUe22gQG6ez53em/n9oyS9XByoOZQJ357vcQuLpky"
                        + "DZggNnzAi0PquQhL2c5FvGwrmBwYZGCqGsfE9pwVSCLZ8FZMhlLDghgYV+E8QTq5ma6aXGk+nr0jwVnv";

        assertEquals(
                "{\"accounts\":[{\"uuid\":\"00000000-0000-4000-8000-0000000000f1\",\"username\":\"Fixture\","
                        + "\"accessToken\":\"fixture-access\",\"type\":\"MICROSOFT\",\"lastUsed\":1,\"expiresAt\":0}]}",
                EncryptionUtil.decrypt(bundle, "fixture-password"));
    }

    @Test
    void aReusedKeySealsEachMessageUnderItsOwnNonce() throws Exception {
        EncryptionUtil.DerivedKey key = EncryptionUtil.derive("k");

        String first = EncryptionUtil.encrypt("same", key);
        String second = EncryptionUtil.encrypt("same", key);

        assertNotEquals(first, second, "one key, two messages, two nonces");
        assertEquals("same", EncryptionUtil.decrypt(first, "k"));
        assertEquals("same", EncryptionUtil.decrypt(second, "k"));
    }

    @Test
    void aTruncatedBundleIsRejectedAsUndecryptable() {
        assertThrows(java.security.GeneralSecurityException.class, () -> EncryptionUtil.decrypt("AAAA", "k"));
    }
}

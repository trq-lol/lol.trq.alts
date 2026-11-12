package lol.trq.alts.crypto;

import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * PBKDF2-HMAC-SHA256 key derivation. Used to stretch a low-entropy passphrase into the 256-bit master
 * key that wraps a vault identity's private key. The high iteration count makes an offline guessing
 * attack against a stolen wrapped blob expensive.
 *
 * @author trq
 * @since 0.2.0
 */
public final class Pbkdf2 {

    /** Iteration count for passphrase-derived vault keys. High by design — these guard a private key. */
    public static final int VAULT_ITERATIONS = 600_000;

    /** Derived key length, in bits. */
    public static final int KEY_BITS = 256;

    /** Salt length, in bytes. */
    public static final int SALT_BYTES = 16;

    private static final SecureRandom RANDOM = new SecureRandom();

    private Pbkdf2() {}

    /**
     * Derives a 256-bit AES key from a passphrase and salt. The passphrase copy held by the key
     * specification and the intermediate key bytes are cleared before returning; the caller still owns
     * (and should clear) {@code passphrase} itself.
     *
     * @param passphrase the passphrase characters
     * @param salt the per-derivation salt
     * @param iterations the PBKDF2 iteration count (use {@link #VAULT_ITERATIONS})
     * @return an AES secret key
     * @throws CryptoException if key derivation fails
     */
    public static SecretKey deriveKey(char[] passphrase, byte[] salt, int iterations) throws CryptoException {
        PBEKeySpec spec = new PBEKeySpec(passphrase, salt, iterations, KEY_BITS);
        byte[] derived = null;
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            derived = factory.generateSecret(spec).getEncoded();
            return new SecretKeySpec(derived, "AES");
        } catch (java.security.NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new CryptoException("PBKDF2 derivation failed", e);
        } finally {
            spec.clearPassword();
            if (derived != null) {
                Arrays.fill(derived, (byte) 0);
            }
        }
    }

    /**
     * Generates a fresh random salt of {@link #SALT_BYTES} bytes.
     *
     * @return a new random salt
     */
    public static byte[] newSalt() {
        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        return salt;
    }
}

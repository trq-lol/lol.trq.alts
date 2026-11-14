package lol.trq.alts.internal.crypto;

import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure;

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

    /**
     * The lowest iteration count {@link #deriveKey} accepts. A stored record names its own count, so the
     * floor keeps a tampered or corrupt record from asking for a derivation too cheap to mean anything.
     *
     * @since 0.12.0
     */
    public static final int MIN_ITERATIONS = 10_000;

    /**
     * The highest iteration count {@link #deriveKey} accepts. A stored or served record names its own
     * count, so the ceiling keeps a hostile one from pinning a core for hours.
     *
     * @since 0.12.0
     */
    public static final int MAX_ITERATIONS = 10_000_000;

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
     * @param salt the per-derivation salt (non-empty)
     * @param iterations the PBKDF2 iteration count, within {@link #MIN_ITERATIONS} and
     *     {@link #MAX_ITERATIONS} (use {@link #VAULT_ITERATIONS})
     * @return an AES secret key
     * @throws AltsException of kind {@code INVALID_INPUT} if the passphrase is missing, the salt empty or the
     *     iteration count out of range, and of kind {@code CRYPTO} if the derivation fails
     */
    public static SecretKey deriveKey(char[] passphrase, byte[] salt, int iterations) {
        if (passphrase == null) {
            throw invalid("PBKDF2 passphrase is missing");
        }
        if (salt == null || salt.length == 0) {
            throw invalid("PBKDF2 salt is empty");
        }
        if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
            throw invalid("PBKDF2 iteration count out of range [" + MIN_ITERATIONS + ", " + MAX_ITERATIONS + "]");
        }
        PBEKeySpec spec = new PBEKeySpec(passphrase, salt, iterations, KEY_BITS);
        byte[] derived = null;
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            derived = factory.generateSecret(spec).getEncoded();
            return new SecretKeySpec(derived, "AES");
        } catch (java.security.NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw failure("PBKDF2 derivation failed", e);
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

    private static AltsException invalid(String what) {
        return new AltsException(AltsFailure.Kind.INVALID_INPUT, "Vault crypto: " + what);
    }

    private static AltsException failure(String what, Throwable cause) {
        return new AltsException(AltsFailure.of(AltsFailure.Kind.CRYPTO, "Vault crypto: " + what), cause);
    }
}

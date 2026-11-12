package lol.trq.alts.store;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES-GCM encryption and decryption for secure local data persistence. Uses PBKDF2 for key derivation
 * and GCM for authenticated encryption, so stored account data is both private and tamper-evident.
 *
 * <p>The bundle is {@code Base64([salt:16][nonce:12][ciphertext+tag])}. The salt selects the key and
 * the nonce is drawn fresh for every message, so one derived key can seal many messages: the stores
 * derive once per process and reuse that key, which keeps the 65,536 PBKDF2 iterations off every save
 * without changing a byte of the format.
 *
 * @author trq
 * @since 0.1.0
 */
public final class EncryptionUtil {

    /** The length of the PBKDF2 salt, in bytes. */
    private static final int SALT_LENGTH = 16;

    /** The length of the initialization vector for AES-GCM, in bytes. */
    private static final int GCM_IV_LENGTH = 12;

    /** The size of the authentication tag, in bits. */
    private static final int GCM_TAG_LENGTH = 128;

    /** One generator for salts and nonces; {@link SecureRandom} is safe to share between threads. */
    private static final SecureRandom RANDOM = new SecureRandom();

    private EncryptionUtil() {}

    /**
     * Generates an environment-specific string used as a password for key derivation. It is built
     * from the OS user name, OS name, home directory and the binding, none of which is secret, so a
     * file sealed under it resists casual copying and not an attacker who knows those values.
     *
     * @param appBinding a host-supplied constant mixed into the key so files are bound to one
     *     application; changing it for an existing store renders prior files undecryptable
     * @return the machine-derived key string
     */
    public static String getHardwareKey(String appBinding) {
        return System.getProperty("user.name")
                + System.getProperty("os.name")
                + System.getProperty("user.home")
                + appBinding;
    }

    /**
     * Encrypts a plaintext string using AES-GCM with a randomly generated salt and IV. The result is a
     * Base64-encoded bundle containing {@code [salt][iv][ciphertext]}.
     *
     * @param plaintext the string to encrypt
     * @param password the password or hardware key used for derivation
     * @return a Base64-encoded string containing the encrypted data and metadata
     * @throws Exception if encryption or key derivation fails
     */
    public static String encrypt(String plaintext, String password) throws Exception {
        return encrypt(plaintext, derive(password));
    }

    /**
     * Derives a key from {@code password} under a fresh random salt, for sealing any number of messages
     * with {@link #encrypt(String, DerivedKey)}.
     *
     * @param password the password or hardware key used for derivation
     * @return the derived key together with the salt that selects it
     * @throws GeneralSecurityException if key derivation fails
     */
    static DerivedKey derive(String password) throws GeneralSecurityException {
        byte[] salt = new byte[SALT_LENGTH];
        RANDOM.nextBytes(salt);
        return new DerivedKey(salt, deriveKey(password, salt));
    }

    /**
     * Encrypts a plaintext string under an already-derived key, in the same bundle format as
     * {@link #encrypt(String, String)}. The nonce is drawn fresh on every call, which is what makes
     * reusing the key sound: GCM only fails when a key and nonce pair repeats, and a random 96-bit
     * nonce stays far inside its collision bound for any number of saves one process will ever make.
     *
     * @param plaintext the string to encrypt
     * @param key the derived key and its salt
     * @return a Base64-encoded string containing the encrypted data and metadata
     * @throws GeneralSecurityException if encryption fails
     */
    static String encrypt(String plaintext, DerivedKey key) throws GeneralSecurityException {
        byte[] salt = key.salt();
        byte[] iv = new byte[GCM_IV_LENGTH];
        RANDOM.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key.key(), new GCMParameterSpec(GCM_TAG_LENGTH, iv));

        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        // Bundle metadata (salt + IV) with the ciphertext for portability
        byte[] combined = new byte[salt.length + iv.length + ciphertext.length];
        System.arraycopy(salt, 0, combined, 0, salt.length);
        System.arraycopy(iv, 0, combined, salt.length, iv.length);
        System.arraycopy(ciphertext, 0, combined, salt.length + iv.length, ciphertext.length);

        return Base64.getEncoder().encodeToString(combined);
    }

    /**
     * Decrypts a Base64-encoded bundle previously produced by {@link #encrypt(String, String)}.
     * Extracts the salt and IV from the bundle to recreate the decryption key.
     *
     * @param encrypted the Base64-encoded bundle
     * @param password the password or hardware key used for derivation
     * @return the original decrypted plaintext string
     * @throws Exception if decryption fails, indicating an incorrect key or tampered data
     */
    public static String decrypt(String encrypted, String password) throws Exception {
        byte[] combined = Base64.getDecoder().decode(encrypted);
        if (combined.length < SALT_LENGTH + GCM_IV_LENGTH + GCM_TAG_LENGTH / 8) {
            throw new GeneralSecurityException("bundle is too short to be an encrypted store");
        }

        byte[] salt = new byte[SALT_LENGTH];
        byte[] iv = new byte[GCM_IV_LENGTH];
        byte[] ciphertext = new byte[combined.length - salt.length - iv.length];

        // Extract metadata and ciphertext from the bundle
        System.arraycopy(combined, 0, salt, 0, salt.length);
        System.arraycopy(combined, salt.length, iv, 0, iv.length);
        System.arraycopy(combined, salt.length + iv.length, ciphertext, 0, ciphertext.length);

        SecretKey key = deriveKey(password, salt);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH, iv));

        return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
    }

    /**
     * Derives a 256-bit AES key from a password and salt using PBKDF2WithHmacSHA256.
     *
     * @param password the input password string
     * @param salt the unique salt for this operation
     * @return a secret key suitable for AES encryption
     * @throws GeneralSecurityException if key factory generation fails
     */
    private static SecretKey deriveKey(String password, byte[] salt) throws GeneralSecurityException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        // 65,536 iterations balances security and performance for a machine-keyed local file
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }

    /**
     * A key derived once and reused, with the salt a reader needs to derive it again.
     *
     * @param salt the PBKDF2 salt written at the head of every bundle sealed with this key
     * @param key the derived AES key
     */
    record DerivedKey(byte[] salt, SecretKey key) {}
}

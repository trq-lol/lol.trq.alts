package lol.trq.alts.internal.crypto;

import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure;

/**
 * AES-256-GCM over a raw {@link SecretKey} with caller-supplied additional authenticated data (AAD), tag
 * appended. It seals a vault identity's private material under the passphrase or recovery key, with an AAD
 * naming which sealing it is, so one cannot be passed off as the other. Internal: not part of the API.
 *
 * @author trq
 * @since 0.2.0
 */
public final class PayloadCipher {

    /** GCM initialization-vector length, in bytes. */
    public static final int IV_BYTES = 12;

    /** GCM authentication-tag length, in bits. */
    public static final int TAG_BITS = 128;

    private static final SecureRandom RANDOM = new SecureRandom();

    private PayloadCipher() {}

    /**
     * Encrypts {@code plaintext} under {@code key} and {@code iv}, authenticating {@code aad}.
     *
     * @param key the AES key
     * @param iv a fresh {@link #IV_BYTES}-byte IV (never reuse one with the same key)
     * @param aad the additional authenticated data, or null/empty for none
     * @param plaintext the bytes to encrypt
     * @return the ciphertext with the GCM tag appended
     * @throws AltsException of kind {@code CRYPTO} if encryption fails
     */
    public static byte[] encrypt(SecretKey key, byte[] iv, byte[] aad, byte[] plaintext) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(plaintext);
        } catch (Exception e) {
            throw failure("AES-GCM encrypt failed", e);
        }
    }

    /**
     * Decrypts {@code ciphertext} under {@code key} and {@code iv}, verifying {@code aad}.
     *
     * @param key the AES key
     * @param iv the {@link #IV_BYTES}-byte IV used at encryption time
     * @param aad the additional authenticated data that must match the encrypt-time value
     * @param ciphertext the ciphertext with the appended GCM tag
     * @return the recovered plaintext
     * @throws AltsException of kind {@code CRYPTO} if the tag is invalid (wrong key, tampered data, or mismatched AAD)
     */
    public static byte[] decrypt(SecretKey key, byte[] iv, byte[] aad, byte[] ciphertext) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw failure("AES-GCM decrypt failed (wrong key, tampered data, or AAD mismatch)", e);
        }
    }

    /**
     * Generates a fresh random {@link #IV_BYTES}-byte IV.
     *
     * @return a new random IV
     */
    public static byte[] newIv() {
        byte[] iv = new byte[IV_BYTES];
        RANDOM.nextBytes(iv);
        return iv;
    }

    private static AltsException failure(String what, Throwable cause) {
        return new AltsException(AltsFailure.of(AltsFailure.Kind.CRYPTO, "Vault crypto: " + what), cause);
    }
}

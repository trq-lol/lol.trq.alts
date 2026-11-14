package lol.trq.alts.internal.avp;

/**
 * A secret wrapped to one recipient with the wrap scheme {@code X25519-HKDF-SHA256-AESGCM-v1} (AVP SPEC
 * 4.4): a data key in a member entry, or the owner entropy in a device link grant. Nothing in it is
 * secret; the constructor copies the arrays and the accessors return the record's own, which callers must
 * not modify.
 *
 * <p>Ported from the Alt Vault Protocol reference implementation (MIT).
 *
 * @param schemeId the wrap scheme id
 * @param ephemeralPublicKey the 32-byte ephemeral X25519 public key
 * @param iv the 12-byte AES-GCM IV
 * @param ciphertext the wrapped secret with the 16-byte tag appended
 * @author trq
 * @since 1.0.0
 */
public record WrappedKey(String schemeId, byte[] ephemeralPublicKey, byte[] iv, byte[] ciphertext) {

    /** Copies the arrays. */
    public WrappedKey {
        ephemeralPublicKey = ephemeralPublicKey.clone();
        iv = iv.clone();
        ciphertext = ciphertext.clone();
    }

    /**
     * Describes the wrap by its lengths only.
     *
     * @return a short description
     */
    @Override
    public String toString() {
        return "WrappedKey[" + schemeId + ", " + ciphertext.length + " bytes]";
    }
}

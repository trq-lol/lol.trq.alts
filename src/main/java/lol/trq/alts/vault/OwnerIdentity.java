package lol.trq.alts.vault;

import java.text.Normalizer;
import java.util.Arrays;
import java.util.Locale;
import java.util.Objects;
import lol.trq.alts.AltsException;
import lol.trq.alts.internal.avp.AvpBytes;
import lol.trq.alts.internal.avp.AvpCrypto;
import lol.trq.alts.internal.avp.Bip39;
import lol.trq.alts.internal.avp.OwnerKeys;
import lol.trq.alts.internal.avp.Tokens;
import lol.trq.alts.internal.vault.MemberKeys;

/**
 * The owner of a repository (AVP SPEC 3.1): the keys derived from a 24-word BIP39 phrase. The owner key is
 * fixed for the repository's life; only it signs the manifest states that change the members, the
 * refresh-token policy or the hosts. The owner's own device is also a member, whose keys derive from the
 * same phrase.
 *
 * <p>This is a secret: whoever holds the phrase or the entropy owns the repository. A host persists it as its
 * {@link #entropy()} (for example in {@link lol.trq.alts.store.HostSecrets}) and restores it with {@link
 * #fromEntropy(byte[])}, or shows the {@link #phrase()} once and keeps nothing, and restores it with {@link
 * #fromPhrase(String)}. A second owner device gets it without typing the phrase through a {@link
 * LinkSession}. No method of the library sends the phrase, the entropy, the seed or a private key to a host,
 * and {@link #toString()} shows none of them.
 *
 * @author trq
 * @since 1.0.0
 */
public final class OwnerIdentity {

    /** The length of the mnemonic entropy: 32 bytes, 24 words. */
    public static final int ENTROPY_BYTES = 32;

    private final byte[] entropy;
    private final OwnerKeys keys;

    private OwnerIdentity(byte[] entropy) {
        if (entropy.length != ENTROPY_BYTES) {
            throw VaultFutures.invalid("owner entropy is 32 bytes");
        }
        this.entropy = entropy.clone();
        this.keys = OwnerKeys.fromEntropy(this.entropy);
    }

    /**
     * A new owner from fresh entropy. Show its {@link #phrase()} to the owner to write down, or keep its
     * {@link #entropy()}, before creating a repository with it.
     *
     * @return the identity
     * @since 1.0.0
     */
    public static OwnerIdentity generate() {
        byte[] fresh = AvpCrypto.randomBytes(ENTROPY_BYTES);
        try {
            return new OwnerIdentity(fresh);
        } finally {
            Arrays.fill(fresh, (byte) 0);
        }
    }

    /**
     * The owner from a typed or pasted phrase. Case and the whitespace between and around the words do not
     * matter; the words and the checksum are checked (SPEC 3.1).
     *
     * @param phrase the 24 words
     * @return the identity
     * @throws AltsException of kind {@code INVALID_INPUT} if the phrase is not 24 words of the BIP39 English
     *     list with a matching checksum
     * @since 1.0.0
     */
    public static OwnerIdentity fromPhrase(String phrase) {
        Objects.requireNonNull(phrase, "phrase");
        String words = Normalizer.normalize(phrase, Normalizer.Form.NFKD)
                .strip()
                .toLowerCase(Locale.ROOT)
                .replaceAll("\\s+", " ");
        byte[] decoded = Bip39.mnemonicToEntropy(words);
        try {
            return new OwnerIdentity(decoded);
        } finally {
            Arrays.fill(decoded, (byte) 0);
        }
    }

    /**
     * The owner from the entropy a host persisted.
     *
     * @param entropy the 32 bytes {@link #entropy()} returned; copied
     * @return the identity
     * @throws AltsException of kind {@code INVALID_INPUT} if it is not 32 bytes
     * @since 1.0.0
     */
    public static OwnerIdentity fromEntropy(byte[] entropy) {
        Objects.requireNonNull(entropy, "entropy");
        return new OwnerIdentity(entropy);
    }

    /**
     * The 24-word phrase. A secret: show it to the owner, never log it.
     *
     * @return the words, separated by single spaces
     * @since 1.0.0
     */
    public String phrase() {
        return Bip39.entropyToMnemonic(entropy);
    }

    /**
     * The mnemonic entropy, the form a host persists. A secret.
     *
     * @return a copy of the 32 bytes, which the caller zeroes when done
     * @since 1.0.0
     */
    public byte[] entropy() {
        return entropy.clone();
    }

    /**
     * The owner key as a member id: the owner's Ed25519 public key, base64.
     *
     * @return the member id
     * @since 1.0.0
     */
    public String memberId() {
        return AvpBytes.base64(keys.ownerKey());
    }

    /**
     * The owner fingerprint (SPEC 11.2), 16 hex digits, which a joiner's {@link RepoLocator} carries.
     *
     * @return the fingerprint
     * @since 1.0.0
     */
    public String fingerprint() {
        return Tokens.ownerFingerprint(keys.ownerKey());
    }

    OwnerKeys ownerKeys() {
        return keys;
    }

    /** The owner's device as a member: the owner keys. */
    MemberKeys memberKeys() {
        return MemberKeys.ofOwner(keys);
    }

    /**
     * The fingerprint only; never the phrase, the entropy or a key.
     *
     * @return a description
     */
    @Override
    public String toString() {
        return "OwnerIdentity[" + fingerprint() + "]";
    }
}

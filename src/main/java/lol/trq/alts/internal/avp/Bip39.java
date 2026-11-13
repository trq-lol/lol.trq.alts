package lol.trq.alts.internal.avp;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.text.Normalizer;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.security.auth.DestroyFailedException;

/**
 * The BIP39 encoding of the owner identity (AVP SPEC 3.1): 32 bytes of entropy to a 24-word English
 * mnemonic and back, and the PBKDF2 seed.
 *
 * <p>The English wordlist is a resource of this package, a byte copy of the upstream list pinned by the
 * conformance vectors; it is checked against its SHA-256 before first use, so a changed list can never
 * change an owner identity silently.
 *
 * <p>The phrase is a {@link String} because a person types it; the entropy and seed arrays this class
 * returns belong to the caller, who zeroes them once done. Intermediate arrays are zeroed here.
 *
 * <p>Ported from the Alt Vault Protocol reference implementation (MIT).
 *
 * @author trq
 * @since 1.0.0
 */
public final class Bip39 {

    /** SHA-256 of the upstream BIP39 English wordlist. */
    private static final String WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda";

    private static final String WORDLIST = "bip39-english.txt";

    /** An AVP mnemonic is always 24 words over 32 bytes of entropy. */
    public static final int WORDS = 24;

    private static volatile Words words;

    private Bip39() {}

    private record Words(List<String> list, Map<String, Integer> index) {}

    private static Words words() {
        Words w = words;
        if (w == null) {
            synchronized (Bip39.class) {
                w = words;
                if (w == null) {
                    w = load();
                    words = w;
                }
            }
        }
        return w;
    }

    private static Words load() {
        byte[] raw;
        try (InputStream in = Bip39.class.getResourceAsStream(WORDLIST)) {
            if (in == null) {
                throw new IllegalStateException("the BIP39 wordlist resource is missing");
            }
            raw = in.readAllBytes();
        } catch (IOException e) {
            throw new UncheckedIOException("the BIP39 wordlist resource cannot be read", e);
        }
        if (!AvpBytes.hex(AvpCrypto.sha256(raw)).equals(WORDLIST_SHA256)) {
            throw new IllegalStateException("the BIP39 wordlist does not match its pinned SHA-256");
        }
        String text = new String(raw, StandardCharsets.UTF_8);
        List<String> list = List.of(text.substring(0, text.length() - 1).split("\n", -1));
        if (list.size() != 2048) {
            throw new IllegalStateException("the BIP39 wordlist does not hold 2048 words");
        }
        Map<String, Integer> index = new HashMap<>();
        for (int k = 0; k < list.size(); k++) {
            index.put(list.get(k), k);
        }
        return new Words(list, Map.copyOf(index));
    }

    /**
     * Encodes 32 bytes of entropy as 24 words: the first 8 bits of {@code SHA-256(entropy)} are appended
     * as a checksum, the 264 bits are split into 24 groups of 11, most significant first, and each indexes
     * the wordlist. Words are joined by one space.
     *
     * @param entropy the 32 bytes of entropy
     * @return the mnemonic
     * @throws lol.trq.alts.AltsException of kind {@code INVALID_INPUT} if the entropy is not 32 bytes
     */
    public static String entropyToMnemonic(byte[] entropy) {
        if (entropy.length != 32) {
            throw AvpFailures.invalidInput("owner entropy is 32 bytes");
        }
        byte[] bits = Arrays.copyOf(entropy, 33);
        bits[32] = AvpCrypto.sha256(entropy)[0];
        List<String> list = words().list();
        StringBuilder out = new StringBuilder();
        for (int w = 0; w < WORDS; w++) {
            int idx = 0;
            for (int b = 0; b < 11; b++) {
                int bit = w * 11 + b;
                idx = (idx << 1) | ((bits[bit / 8] >> (7 - bit % 8)) & 1);
            }
            if (w > 0) {
                out.append(' ');
            }
            out.append(list.get(idx));
        }
        Arrays.fill(bits, (byte) 0);
        return out.toString();
    }

    /**
     * Decodes a 24-word mnemonic to its entropy. The phrase is NFKD-normalized and split on single
     * spaces, so a doubled space is an empty, unknown word.
     *
     * @param mnemonic the phrase
     * @return the 32 bytes of entropy
     * @throws lol.trq.alts.AltsException of kind {@code INVALID_INPUT} if the phrase is not exactly 24
     *     words, holds a word not in the list, or fails the checksum
     */
    public static byte[] mnemonicToEntropy(String mnemonic) {
        String[] parts = Normalizer.normalize(mnemonic, Normalizer.Form.NFKD).split(" ", -1);
        if (parts.length != WORDS) {
            throw AvpFailures.invalidInput("a recovery phrase is exactly 24 words");
        }
        Map<String, Integer> index = words().index();
        byte[] bits = new byte[33];
        for (int w = 0; w < WORDS; w++) {
            Integer idx = index.get(parts[w]);
            if (idx == null) {
                Arrays.fill(bits, (byte) 0);
                throw AvpFailures.invalidInput("the recovery phrase holds a word that is not in the list");
            }
            for (int b = 0; b < 11; b++) {
                if (((idx >> (10 - b)) & 1) == 1) {
                    int bit = w * 11 + b;
                    bits[bit / 8] |= (byte) (0x80 >> (bit % 8));
                }
            }
        }
        byte[] entropy = Arrays.copyOf(bits, 32);
        boolean checksumOk = AvpCrypto.sha256(entropy)[0] == bits[32];
        Arrays.fill(bits, (byte) 0);
        if (!checksumOk) {
            Arrays.fill(entropy, (byte) 0);
            throw AvpFailures.invalidInput("the recovery phrase checksum does not match");
        }
        return entropy;
    }

    /**
     * The BIP39 seed: {@code PBKDF2-HMAC-SHA512(NFKD(mnemonic), UTF8("mnemonic") || NFKD(passphrase), 2048,
     * 64)}. AVP uses the empty passphrase; the parameter exists for the published reference vectors.
     *
     * @param mnemonic the phrase
     * @param passphrase the BIP39 passphrase, empty for AVP
     * @return the 64-byte seed
     * @throws lol.trq.alts.AltsException of kind {@code INVALID_INPUT} for an empty phrase, and of kind
     *     {@code CRYPTO} if PBKDF2 fails
     */
    public static byte[] mnemonicToSeed(String mnemonic, String passphrase) {
        char[] password = Normalizer.normalize(mnemonic, Normalizer.Form.NFKD).toCharArray();
        if (password.length == 0) {
            throw AvpFailures.invalidInput("an empty recovery phrase has no seed");
        }
        byte[] salt =
                ("mnemonic" + Normalizer.normalize(passphrase, Normalizer.Form.NFKD)).getBytes(StandardCharsets.UTF_8);
        PBEKeySpec spec = new PBEKeySpec(password, salt, 2048, 512);
        try {
            // The JDK's PBKDF2 encodes the char[] password as UTF-8, which an NFKD English phrase is.
            SecretKey key = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512").generateSecret(spec);
            try {
                return key.getEncoded();
            } finally {
                try {
                    key.destroy();
                } catch (DestroyFailedException notSupported) {
                    // A provider whose key cannot be destroyed: its copy goes with the garbage collector.
                }
            }
        } catch (GeneralSecurityException | RuntimeException e) {
            throw AvpFailures.crypto("PBKDF2 failed", e);
        } finally {
            spec.clearPassword();
            Arrays.fill(password, '\0');
        }
    }
}

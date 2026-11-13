package lol.trq.alts.internal.avp;

import static lol.trq.alts.internal.avp.Vectors.hex;
import static lol.trq.alts.internal.avp.Vectors.str;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.google.gson.JsonObject;
import java.util.Arrays;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure.Kind;
import org.junit.jupiter.api.Test;

/**
 * {@code bip39-owner.json} (SPEC 3.1): entropy to mnemonic to seed to the owner keys, and the three
 * Trezor reference anchors that pin entropy, mnemonic and seed against an external implementation.
 */
class Bip39OwnerVectorsTest {

    @Test
    void theWordlistIsTheOneTheVectorsPin() {
        JsonObject wordlist = Vectors.load("bip39-owner.json").getAsJsonObject("wordlist");
        assertEquals(AvpVectorFilesTest.SHA256.get(str(wordlist, "file")), str(wordlist, "sha256"));
        // The main resource is checked against this hash before use; a mnemonic of the last word proves
        // the whole list was read.
        assertEquals(2048, wordlist.get("words").getAsInt());
    }

    @Test
    void everyOwnerCaseReproduces() {
        for (JsonObject c : Vectors.cases(Vectors.load("bip39-owner.json"), "cases", 3)) {
            String name = str(c, "name");
            byte[] entropy = hex(c, "entropyHex");
            assertEquals(str(c, "mnemonic"), Bip39.entropyToMnemonic(entropy), name);
            assertArrayEquals(entropy, Bip39.mnemonicToEntropy(str(c, "mnemonic")), name);
            byte[] seed = Bip39.mnemonicToSeed(str(c, "mnemonic"), str(c, "passphrase"));
            assertEquals(str(c, "seedHex"), Vectors.hex(seed), name);

            OwnerKeys keys = OwnerKeys.fromSeed(seed);
            assertEquals(str(c, "ed25519SeedHex"), Vectors.hex(keys.ed25519Seed()), name);
            assertEquals(str(c, "ed25519PublicKeyHex"), Vectors.hex(keys.ownerKey()), name);
            assertEquals(str(c, "x25519PrivateHex"), Vectors.hex(keys.x25519Private()), name);
            assertEquals(str(c, "x25519PublicKeyHex"), Vectors.hex(keys.x25519Public()), name);

            assertArrayEquals(keys.ownerKey(), OwnerKeys.fromEntropy(entropy).ownerKey(), name);
            assertArrayEquals(
                    keys.ownerKey(), OwnerKeys.fromMnemonic(str(c, "mnemonic")).ownerKey(), name);
        }
    }

    @Test
    void theTrezorAnchorsReproduce() {
        JsonObject anchors = Vectors.load("bip39-owner.json").getAsJsonObject("anchors");
        for (JsonObject c : Vectors.cases(anchors, "cases", 3)) {
            byte[] entropy = hex(c, "entropyHex");
            assertEquals(str(c, "mnemonic"), Bip39.entropyToMnemonic(entropy));
            assertArrayEquals(entropy, Bip39.mnemonicToEntropy(str(c, "mnemonic")));
            assertEquals(
                    str(c, "seedHex"),
                    Vectors.hex(Bip39.mnemonicToSeed(str(c, "mnemonic"), str(anchors, "passphrase"))));
        }
    }

    @Test
    void aPhraseThatIsNotTwentyFourKnownWordsWithItsChecksumIsRefused() {
        String good =
                str(Vectors.cases(Vectors.load("bip39-owner.json"), "cases", 3).get(0), "mnemonic");
        String[] words = good.split(" ");

        String[] swapped = words.clone();
        String last = swapped[23];
        swapped[23] = swapped[22];
        swapped[22] = last;
        String twentyThree = String.join(" ", Arrays.copyOf(words, 23));
        String unknown = good.replaceFirst("^\\S+", "notaword");
        String doubleSpace = good.replaceFirst(" ", "  ");

        for (String bad : new String[] {String.join(" ", swapped), twentyThree, unknown, doubleSpace, ""}) {
            AltsException e = assertThrows(AltsException.class, () -> Bip39.mnemonicToEntropy(bad));
            assertEquals(Kind.INVALID_INPUT, e.kind());
            assertFalse(e.getMessage().contains("abandon"), "the message never quotes the phrase");
        }
    }

    @Test
    void theOwnerKeysNeverPrintAPrivateKeyAndCanBeZeroed() {
        JsonObject c =
                Vectors.cases(Vectors.load("bip39-owner.json"), "cases", 3).get(0);
        OwnerKeys keys = OwnerKeys.fromEntropy(hex(c, "entropyHex"));
        String printed = keys.toString();
        assertFalse(printed.contains(str(c, "ed25519SeedHex")));
        assertFalse(printed.contains(AvpBytes.base64(hex(c, "ed25519SeedHex"))));
        assertFalse(printed.contains(AvpBytes.base64(hex(c, "x25519PrivateHex"))));

        keys.destroy();
        assertArrayEquals(new byte[32], keys.ed25519Seed());
        assertArrayEquals(new byte[32], keys.x25519Private());
    }
}

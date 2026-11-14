package lol.trq.alts.internal.vault.legacy;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.internal.avp.AvpCrypto;
import org.junit.jupiter.api.Test;

/**
 * Gates the 0.4 importer's constructions against the vendored AVP 0.4 vectors ({@code
 * src/test/resources/avp-vectors/0.4}), byte for byte: the AAD, the payload AEAD and the data-key unwrap, and
 * every {@code payload-decrypt} and {@code key-unwrap} case of the negative bank. Each test counts its cases,
 * so a vector file that lost one fails rather than passing on fewer.
 */
class LegacyVectorsTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final byte[] WRAP_INFO = "avp/rdk-wrap/v1".getBytes(StandardCharsets.UTF_8);

    private static List<JsonObject> cases(String file) throws Exception {
        try (InputStream in = LegacyVectorsTest.class.getResourceAsStream("/avp-vectors/0.4/" + file)) {
            Objects.requireNonNull(in, "missing vendored vector resource: " + file);
            JsonArray cases = JsonParser.parseReader(new InputStreamReader(in, StandardCharsets.UTF_8))
                    .getAsJsonObject()
                    .getAsJsonArray("cases");
            List<JsonObject> out = new ArrayList<>();
            cases.forEach(c -> out.add(c.getAsJsonObject()));
            return out;
        }
    }

    private static byte[] b64(String s) {
        return Base64.getDecoder().decode(s);
    }

    private static String str(JsonObject c, String key) {
        return c.get(key).getAsString();
    }

    @Test
    void aad() throws Exception {
        List<JsonObject> cases = cases("aad.json");
        assertEquals(2, cases.size());
        for (JsonObject c : cases) {
            byte[] aad = LegacyRepository.aad(
                    str(c, "repoId"),
                    c.get("payloadVersion").getAsLong(),
                    c.get("keyEpoch").getAsLong());
            assertEquals(str(c, "expectedAadHex"), HEX.formatHex(aad));
        }
    }

    @Test
    void payloadAead() throws Exception {
        List<JsonObject> cases = cases("payload-aead.json");
        assertEquals(1, cases.size());
        for (JsonObject c : cases) {
            String name = str(c, "name");
            byte[] key = b64(str(c, "keyB64"));
            byte[] iv = b64(str(c, "ivB64"));
            String repoId = str(c, "repoId");
            long version = c.get("payloadVersion").getAsLong();
            long epoch = c.get("keyEpoch").getAsLong();
            byte[] aad = LegacyRepository.aad(repoId, version, epoch);
            assertEquals(str(c, "aadHex"), HEX.formatHex(aad), name + " aad");
            byte[] plaintext = str(c, "plaintextUtf8").getBytes(StandardCharsets.UTF_8);
            byte[] ciphertext = b64(str(c, "ciphertextB64"));

            // (a) sealing under the 0.4 AAD reproduces the vector; (b) the importer's open recovers it.
            assertArrayEquals(ciphertext, AvpCrypto.aesGcmSeal(key, iv, plaintext, aad), name + " seal");
            assertArrayEquals(
                    plaintext,
                    LegacyRepository.openPayload(key, iv, ciphertext, repoId, version, epoch),
                    name + " open");
            // (c) the epoch changed in the AAD fails authentication.
            long tamperEpoch = c.get("tamperEpoch").getAsLong();
            AltsException e = assertThrows(
                    AltsException.class,
                    () -> LegacyRepository.openPayload(key, iv, ciphertext, repoId, version, tamperEpoch),
                    name + " tampered epoch");
            assertEquals(Kind.CRYPTO, e.kind());
        }
    }

    @Test
    void keyWrap() throws Exception {
        List<JsonObject> cases = cases("key-wrap.json");
        assertEquals(1, cases.size());
        for (JsonObject c : cases) {
            String name = str(c, "name");
            byte[] recipient = b64(str(c, "recipientPrivateKeyB64"));
            JsonObject wrapped = c.getAsJsonObject("wrappedKey");
            byte[] ephemeral = b64(str(wrapped, "ephemeralPublicKey"));

            // The intermediates the scheme defines, then the wrap ciphertext under the pinned KEK and IV.
            byte[] shared = AvpCrypto.x25519(recipient, ephemeral);
            assertEquals(str(c, "sharedSecretHex"), HEX.formatHex(shared), name + " shared secret");
            byte[] kek = AvpCrypto.hkdf(shared, ephemeral, WRAP_INFO, 32);
            assertEquals(str(c, "kekHex"), HEX.formatHex(kek), name + " kek");
            byte[] dataKey = b64(str(c, "dataKeyB64"));
            assertEquals(
                    str(wrapped, "ciphertext"),
                    Base64.getEncoder()
                            .encodeToString(AvpCrypto.aesGcmSeal(kek, b64(str(wrapped, "iv")), dataKey, WRAP_INFO)),
                    name + " wrap ciphertext");

            // The importer unwraps the wire WrappedKey to the data key.
            assertArrayEquals(dataKey, LegacyRepository.unwrapDataKey(wrapped, recipient), name + " unwrap");
        }
    }

    @Test
    void negative() throws Exception {
        int payload = 0;
        int unwrap = 0;
        int other = 0;
        for (JsonObject c : cases("negative.json")) {
            String name = str(c, "name");
            switch (str(c, "op")) {
                case "payload-decrypt" -> {
                    payload++;
                    byte[] key = b64(str(c, "keyB64"));
                    byte[] iv = b64(str(c, "ivB64"));
                    byte[] ct = b64(str(c, "ciphertextB64"));
                    AltsException e = assertThrows(
                            AltsException.class,
                            () -> LegacyRepository.openPayload(
                                    key,
                                    iv,
                                    ct,
                                    str(c, "repoId"),
                                    c.get("payloadVersion").getAsLong(),
                                    c.get("keyEpoch").getAsLong()),
                            name);
                    assertEquals(Kind.CRYPTO, e.kind(), name);
                }
                case "key-unwrap" -> {
                    unwrap++;
                    JsonObject wrapped = new JsonObject();
                    wrapped.addProperty("schemeId", LegacyRepository.SCHEME_ID);
                    wrapped.addProperty("ephemeralPublicKey", str(c, "ephemeralPublicKeyB64"));
                    wrapped.addProperty("iv", str(c, "ivB64"));
                    wrapped.addProperty("ciphertext", str(c, "ciphertextB64"));
                    byte[] recipient = b64(str(c, "recipientPrivateKeyB64"));
                    AltsException e = assertThrows(
                            AltsException.class, () -> LegacyRepository.unwrapDataKey(wrapped, recipient), name);
                    assertEquals(Kind.CRYPTO, e.kind(), name);
                }
                case "ed25519-verify" -> other++; // the identity's signer; gated with the primitives
                default -> throw new IllegalStateException("unknown negative op: " + str(c, "op"));
            }
        }
        assertEquals(8, payload, "payload-decrypt cases");
        assertEquals(5, unwrap, "key-unwrap cases");
        assertEquals(3, other, "ed25519-verify cases");
    }
}

package lol.trq.alts.internal.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HexFormat;
import java.util.Objects;
import lol.trq.alts.internal.avp.AvpCrypto;
import org.junit.jupiter.api.Test;

/**
 * Gates the primitives the vault identity and the 0.4 importer rest on against the vendored AVP 0.4 vectors
 * ({@code src/test/resources/avp-vectors/0.4}): HKDF, X25519 and Ed25519, and the negative bank's signature
 * cases. The importer's own constructions (the AAD, the payload AEAD, the unwrap and the rest of the negative
 * bank) are gated by {@code LegacyVectorsTest}.
 */
class AvpConformanceVectorsTest {

    private static final HexFormat HEX = HexFormat.of();

    private static JsonArray cases(String file) throws Exception {
        try (InputStream in = AvpConformanceVectorsTest.class.getResourceAsStream("/avp-vectors/0.4/" + file)) {
            Objects.requireNonNull(in, "missing vendored vector resource: " + file);
            JsonObject root = JsonParser.parseReader(new InputStreamReader(in, StandardCharsets.UTF_8))
                    .getAsJsonObject();
            return root.getAsJsonArray("cases");
        }
    }

    // --- RFC-anchored primitives -------------------------------------------------------------------

    @Test
    void hkdf() throws Exception {
        int n = 0;
        for (JsonObject c : objects(cases("hkdf.json"))) {
            n++;
            String name = c.get("name").getAsString();
            byte[] okm = AvpCrypto.hkdf(
                    HEX.parseHex(c.get("ikmHex").getAsString()),
                    HEX.parseHex(c.get("saltHex").getAsString()),
                    HEX.parseHex(c.get("infoHex").getAsString()),
                    c.get("length").getAsInt());
            assertEquals(c.get("okmHex").getAsString(), HEX.formatHex(okm), name + " okm");
        }
        assertTrue(n > 0, "hkdf cases");
    }

    @Test
    void x25519() throws Exception {
        for (JsonObject c : objects(cases("x25519.json"))) {
            String name = c.get("name").getAsString();
            PrivateKey scalar =
                    X25519.decodePrivateKey(HEX.parseHex(c.get("scalarHex").getAsString()));
            PublicKey peer =
                    X25519.decodePublicKey(HEX.parseHex(c.get("uCoordinateHex").getAsString()));
            byte[] output = X25519.agree(scalar, peer);
            assertEquals(c.get("outputHex").getAsString(), HEX.formatHex(output), name + " shared secret");
        }
    }

    @Test
    void ed25519() throws Exception {
        for (JsonObject c : objects(cases("ed25519.json"))) {
            String name = c.get("name").getAsString();
            PrivateKey priv =
                    Ed25519.decodePrivateKey(HEX.parseHex(c.get("seedHex").getAsString()));
            PublicKey pub =
                    Ed25519.decodePublicKey(HEX.parseHex(c.get("publicKeyHex").getAsString()));
            byte[] message = HEX.parseHex(c.get("messageHex").getAsString());
            String expectedSig = c.get("signatureHex").getAsString();

            // Ed25519 is deterministic: the signature must reproduce the published vector byte for byte.
            assertEquals(expectedSig, HEX.formatHex(Ed25519.sign(priv, message)), name + " signature");
            assertTrue(Ed25519.verify(pub, message, HEX.parseHex(expectedSig)), name + " verify");
        }
    }

    // --- Negative (MUST-reject) bank ---------------------------------------------------------------

    @Test
    void negativeSignatures() throws Exception {
        int n = 0;
        for (JsonObject c : objects(cases("negative.json"))) {
            if (!c.get("op").getAsString().equals("ed25519-verify")) {
                continue; // payload-decrypt and key-unwrap: LegacyVectorsTest
            }
            n++;
            String name = c.get("name").getAsString();
            PublicKey pub =
                    Ed25519.decodePublicKey(HEX.parseHex(c.get("publicKeyHex").getAsString()));
            byte[] message = HEX.parseHex(c.get("messageHex").getAsString());
            byte[] signature = HEX.parseHex(c.get("signatureHex").getAsString());
            assertFalse(Ed25519.verify(pub, message, signature), name);
        }
        assertEquals(3, n, "ed25519-verify cases");
    }

    private static Iterable<JsonObject> objects(JsonArray array) {
        return () -> array.asList().stream().map(JsonObject.class::cast).iterator();
    }
}

package lol.trq.alts.internal.avp;

import static lol.trq.alts.internal.avp.Vectors.b64;
import static lol.trq.alts.internal.avp.Vectors.hex;
import static lol.trq.alts.internal.avp.Vectors.obj;
import static lol.trq.alts.internal.avp.Vectors.str;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonObject;
import java.util.Arrays;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.internal.avp.AvpCrypto.WrapLabel;
import org.junit.jupiter.api.Test;

/**
 * The RFC-anchored primitives and the wrap composition of the AVP 0.5 vectors: {@code hkdf.json}, {@code
 * x25519.json}, {@code ed25519.json} and {@code key-wrap.json}, each reproduced byte for byte.
 */
class PrimitiveVectorsTest {

    /** Bob's private key of RFC 7748 section 6.1, the ephemeral key of {@code key-wrap.json}. */
    private static final byte[] RFC7748_BOB_PRIVATE =
            hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");

    @Test
    void hkdfReproducesRfc5869() {
        for (JsonObject c : Vectors.cases(Vectors.load("hkdf.json"), "cases", 2)) {
            byte[] okm = AvpCrypto.hkdf(
                    hex(c, "ikmHex"),
                    hex(c, "saltHex"),
                    hex(c, "infoHex"),
                    c.get("length").getAsInt());
            assertEquals(str(c, "okmHex"), Vectors.hex(okm), str(c, "name"));
        }
    }

    @Test
    void x25519ReproducesRfc7748() {
        for (JsonObject c : Vectors.cases(Vectors.load("x25519.json"), "cases", 3)) {
            byte[] out = AvpCrypto.x25519(hex(c, "scalarHex"), hex(c, "uCoordinateHex"));
            assertEquals(str(c, "outputHex"), Vectors.hex(out), str(c, "name"));
        }
    }

    @Test
    void ed25519ReproducesRfc8032() {
        for (JsonObject c : Vectors.cases(Vectors.load("ed25519.json"), "cases", 2)) {
            String name = str(c, "name");
            byte[] seed = hex(c, "seedHex");
            byte[] message = hex(c, "messageHex");
            assertEquals(str(c, "publicKeyHex"), Vectors.hex(Ed25519Strict.publicKey(seed)), name);
            assertEquals(str(c, "signatureHex"), Vectors.hex(Ed25519Strict.sign(seed, message)), name);
            assertTrue(Ed25519Strict.verify(hex(c, "publicKeyHex"), message, hex(c, "signatureHex")), name);
        }
    }

    @Test
    void keyWrapReproducesTheCompositionAndUnwraps() {
        JsonObject c = Vectors.cases(Vectors.load("key-wrap.json"), "cases", 1).get(0);
        assertEquals(WrapLabel.DATA_KEY.label(), str(c, "info"));
        JsonObject wire = obj(c, "wrappedKey");
        byte[] recipientPublic = b64(c, "recipientPublicKeyB64");
        byte[] dataKey = b64(c, "dataKeyB64");

        assertArrayEquals(recipientPublic, AvpCrypto.x25519Public(b64(c, "recipientPrivateKeyB64")));
        assertArrayEquals(b64(wire, "ephemeralPublicKey"), AvpCrypto.x25519Public(RFC7748_BOB_PRIVATE));
        assertEquals(str(c, "sharedSecretHex"), Vectors.hex(AvpCrypto.x25519(RFC7748_BOB_PRIVATE, recipientPublic)));

        WrappedKey rewrapped =
                AvpCrypto.wrapWith(recipientPublic, dataKey, WrapLabel.DATA_KEY, RFC7748_BOB_PRIVATE, b64(wire, "iv"));
        assertEquals(str(wire, "schemeId"), rewrapped.schemeId());
        assertArrayEquals(b64(wire, "ephemeralPublicKey"), rewrapped.ephemeralPublicKey());
        assertArrayEquals(b64(wire, "ciphertext"), rewrapped.ciphertext());

        WrappedKey vector = new WrappedKey(
                str(wire, "schemeId"), b64(wire, "ephemeralPublicKey"), b64(wire, "iv"), b64(wire, "ciphertext"));
        assertArrayEquals(dataKey, AvpCrypto.unwrap(b64(c, "recipientPrivateKeyB64"), vector, WrapLabel.DATA_KEY));
        AltsException other = assertThrows(
                AltsException.class,
                () -> AvpCrypto.unwrap(b64(c, "recipientPrivateKeyB64"), vector, WrapLabel.OWNER_LINK));
        assertEquals(Kind.CRYPTO, other.kind(), "the data key wrap does not open under the link label");
    }

    @Test
    void aRandomWrapRoundTripsAndIsFreshEachTime() {
        byte[] recipientPrivate = AvpCrypto.randomBytes(32);
        byte[] recipientPublic = AvpCrypto.x25519Public(recipientPrivate);
        byte[] secret = AvpCrypto.randomBytes(32);
        WrappedKey a = AvpCrypto.wrap(recipientPublic, secret, WrapLabel.OWNER_LINK);
        WrappedKey b = AvpCrypto.wrap(recipientPublic, secret, WrapLabel.OWNER_LINK);
        assertFalse(Arrays.equals(a.ephemeralPublicKey(), b.ephemeralPublicKey()));
        assertFalse(Arrays.equals(a.iv(), b.iv()));
        assertArrayEquals(secret, AvpCrypto.unwrap(recipientPrivate, a, WrapLabel.OWNER_LINK));
        assertEquals(
                Kind.CRYPTO,
                assertThrows(AltsException.class, () -> AvpCrypto.unwrap(recipientPrivate, a, WrapLabel.DATA_KEY))
                        .kind());
        WrappedKey otherScheme = new WrappedKey("other", a.ephemeralPublicKey(), a.iv(), a.ciphertext());
        assertEquals(
                Kind.PROTOCOL,
                assertThrows(
                                AltsException.class,
                                () -> AvpCrypto.unwrap(recipientPrivate, otherScheme, WrapLabel.OWNER_LINK))
                        .kind());
    }
}

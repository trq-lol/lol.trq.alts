package lol.trq.alts.internal.vault.legacy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.internal.avp.AvpCrypto;
import lol.trq.alts.internal.avp.AvpCrypto.WrapLabel;
import lol.trq.alts.internal.avp.WrappedKey;
import lol.trq.alts.model.AltAccount;
import org.junit.jupiter.api.Test;

/**
 * The payload side of the 0.4 importer, over repositories built here with a known data key, so a plaintext
 * no 0.12 member would have written can be sealed: what an authenticated payload that is not an alt list
 * becomes, and which entries are dropped.
 */
class LegacyRepositoryTest {

    private static final String MEMBER = "bWVtYmVyLWlk";
    private static final String REPO = "repo-legacy";
    private static final byte[] SCALAR = AvpCrypto.randomBytes(32);
    private static final Base64.Encoder B64 = Base64.getEncoder();

    private static String manifest(byte[] dataKey, boolean share) {
        WrappedKey w = AvpCrypto.wrap(AvpCrypto.x25519Public(SCALAR), dataKey, WrapLabel.DATA_KEY);
        JsonObject wrapped = new JsonObject();
        wrapped.addProperty("schemeId", w.schemeId());
        wrapped.addProperty("ephemeralPublicKey", B64.encodeToString(w.ephemeralPublicKey()));
        wrapped.addProperty("iv", B64.encodeToString(w.iv()));
        wrapped.addProperty("ciphertext", B64.encodeToString(w.ciphertext()));
        JsonObject entry = new JsonObject();
        entry.addProperty("ed25519PublicKey", MEMBER);
        entry.addProperty("x25519PublicKey", B64.encodeToString(AvpCrypto.x25519Public(SCALAR)));
        entry.add("wrappedDataKey", wrapped);
        entry.addProperty("keyEpoch", 0);
        JsonArray members = new JsonArray();
        members.add(entry);
        JsonObject m = new JsonObject();
        m.addProperty("repoId", REPO);
        m.addProperty("schemeId", LegacyRepository.SCHEME_ID);
        m.addProperty("keyEpoch", 0);
        m.addProperty("payloadVersion", 1);
        m.add("members", members);
        m.addProperty("shareRefreshTokens", share);
        return m.toString();
    }

    private static String envelope(byte[] dataKey, String plaintext) {
        byte[] iv = AvpCrypto.randomBytes(12);
        byte[] ct = AvpCrypto.aesGcmSeal(
                dataKey, iv, plaintext.getBytes(StandardCharsets.UTF_8), LegacyRepository.aad(REPO, 1, 0));
        JsonObject e = new JsonObject();
        e.addProperty("repoId", REPO);
        e.addProperty("payloadVersion", 1);
        e.addProperty("keyEpoch", 0);
        e.addProperty("iv", B64.encodeToString(iv));
        e.addProperty("ciphertext", B64.encodeToString(ct));
        return e.toString();
    }

    private static List<AltAccount> read(String plaintext, boolean share) {
        byte[] key = AvpCrypto.randomBytes(32);
        return LegacyRepository.read(manifest(key, share), envelope(key, plaintext), MEMBER, SCALAR);
    }

    private static void assertProtocol(String plaintext) {
        AltsException e = assertThrows(AltsException.class, () -> read(plaintext, true), plaintext);
        assertEquals(Kind.PROTOCOL, e.kind(), plaintext);
    }

    @Test
    void aPayloadWithoutAnAltListIsEmpty() {
        assertEquals(List.of(), read("{}", true));
        assertEquals(List.of(), read("{\"alts\":null,\"payloadVersion\":1}", true));
        assertEquals(List.of(), read("{\"alts\":[]}", true));
    }

    @Test
    void aNullAccountIsDropped() {
        List<AltAccount> read = read("{\"alts\":[null,{\"uuid\":\"u1\",\"username\":\"One\"},null]}", true);
        assertEquals(1, read.size());
        assertEquals("u1", read.get(0).uuid());
    }

    @Test
    void anAuthenticatedPayloadThatIsNotAnAltListIsProtocol() {
        assertProtocol("not json");
        assertProtocol("[]");
        assertProtocol("{\"alts\":{}}");
        assertProtocol("{\"alts\":[5]}");
        assertProtocol("{\"alts\":[{\"lastUsed\":\"yesterday\"}]}");
        assertProtocol("{\"alts\":[{\"bans\":[1]}]}");
    }

    @Test
    void theWithholdingPolicyClearsBothTokenFields() {
        String payload = "{\"alts\":[{\"uuid\":\"u1\",\"accessToken\":\"a\",\"refreshToken\":\"r\",\"expiresAt\":9}]}";
        AltAccount withheld = read(payload, false).get(0);
        assertEquals("a", withheld.accessToken());
        assertNull(withheld.refreshToken());
        assertEquals(0L, withheld.expiresAt());
        AltAccount shared = read(payload, true).get(0);
        assertEquals("r", shared.refreshToken());
        assertEquals(9L, shared.expiresAt());
    }

    @Test
    void aDataKeyOfAnotherLengthIsProtocol() {
        byte[] shortKey = AvpCrypto.randomBytes(16);
        String envelope = envelope(AvpCrypto.randomBytes(32), "{}");
        AltsException e = assertThrows(
                AltsException.class, () -> LegacyRepository.read(manifest(shortKey, true), envelope, MEMBER, SCALAR));
        assertEquals(Kind.PROTOCOL, e.kind());
    }
}

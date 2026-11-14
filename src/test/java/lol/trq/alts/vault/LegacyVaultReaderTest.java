package lol.trq.alts.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.reflect.TypeToken;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.internal.store.AltAccountJson;
import lol.trq.alts.model.AltAccount;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

/**
 * Pins the read-only 0.4 importer against repositories the 0.12 vault wrote ({@code
 * src/test/resources/legacy-vault-0.4}): it recovers exactly what 0.12 decrypted, holds the refresh-token
 * policy, and refuses every repository 0.12 refused, with the kind the error model names.
 */
class LegacyVaultReaderTest {

    private static VaultIdentity alice;
    private static VaultIdentity aliceByRecovery;
    private static VaultIdentity bob;
    private static VaultIdentity carol;

    @BeforeAll
    static void unlock() throws Exception {
        alice = VaultIdentity.unlock(identity("alice"), "alice-0.4-passphrase".toCharArray());
        aliceByRecovery = VaultIdentity.unlockWithRecovery(
                identity("alice"), text("alice-recovery-code.txt").strip());
        bob = VaultIdentity.unlock(identity("bob"), "bob-0.4-passphrase".toCharArray());
        carol = VaultIdentity.unlock(identity("carol"), "carol-0.4-passphrase".toCharArray());
    }

    // --- What 0.12 read -------------------------------------------------------------------------

    @Test
    void aMemberReadsExactlyWhatTheOldVaultDecrypted() throws Exception {
        List<AltAccount> read = read("sharing", bob);
        assertEquals(expected("sharing"), read);
        assertEquals(3, read.size());
        assertEquals("refresh-one", read.get(0).refreshToken(), "a sharing repository keeps refresh tokens");
        assertEquals(1_800_000_000_000L, read.get(0).expiresAt());
        assertTrue(read.get(0).banned("example.net"));
        assertFalse(read.get(0).banned("other.example"));
    }

    @Test
    void theCreatorReadsTheSameAccounts() throws Exception {
        assertEquals(expected("sharing"), read("sharing", alice));
    }

    @Test
    void aWithholdingRepositoryYieldsNoRefreshToken() throws Exception {
        List<AltAccount> read = read("withholding", bob);
        assertEquals(expected("withholding"), read);
        for (AltAccount a : read) {
            assertNull(a.refreshToken(), a.username());
            assertEquals(0L, a.expiresAt(), a.username());
        }
        assertEquals("access-one", read.get(0).accessToken(), "the access token travels");
    }

    @Test
    void refreshTokensAPeerSmuggledIntoAWithholdingRepositoryAreStripped() throws Exception {
        List<AltAccount> read = read("smuggled", bob);
        assertEquals(expected("smuggled"), read);
        for (AltAccount a : read) {
            assertNull(a.refreshToken(), a.username());
            assertEquals(0L, a.expiresAt(), a.username());
        }
        // The ciphertext really carries them: the same envelope under a sharing manifest yields them.
        String sharing = edit(text("smuggled-manifest.json"), m -> m.addProperty("shareRefreshTokens", true));
        List<AltAccount> unstripped = LegacyVaultReader.read(sharing, text("smuggled-envelope.json"), bob);
        assertEquals("refresh-one", unstripped.get(0).refreshToken());
        assertEquals("refresh-two", unstripped.get(1).refreshToken());
    }

    @Test
    void aManifestWithoutTheSharingFlagWithholds() throws Exception {
        // shareRefreshTokens was added in 0.6.0; an older manifest lacks it and withholds.
        String older = edit(text("sharing-manifest.json"), m -> m.remove("shareRefreshTokens"));
        for (AltAccount a : LegacyVaultReader.read(older, text("sharing-envelope.json"), bob)) {
            assertNull(a.refreshToken(), a.username());
        }
    }

    @Test
    void anIdentityRestoredByItsRecoveryCodeReadsARotatedRepository() throws Exception {
        assertEquals(alice.identityId(), aliceByRecovery.identityId());
        assertEquals(expected("rotated"), read("rotated", aliceByRecovery));
    }

    @Test
    void theResultIsUnmodifiable() throws Exception {
        List<AltAccount> read = read("sharing", bob);
        assertThrows(UnsupportedOperationException.class, () -> read.add(read.get(0)));
    }

    // --- Who may read ---------------------------------------------------------------------------

    @Test
    void anIdentityThatIsNotAMemberIsRefused() {
        assertKind(Kind.PROTOCOL, () -> read("sharing", carol));
    }

    @Test
    void aRemovedMemberCannotReadTheRotatedRepository() {
        assertKind(Kind.PROTOCOL, () -> read("rotated", bob));
    }

    @Test
    void anEntryThatNamesThisIdentityOverAnotherMembersWrapDoesNotUnwrap() throws Exception {
        // A host lists carol, but over the data key it wrapped to alice.
        String forged = edit(
                text("sharing-manifest.json"), m -> member(m, 0).addProperty("ed25519PublicKey", identityId(carol)));
        assertKind(Kind.CRYPTO, () -> LegacyVaultReader.read(forged, text("sharing-envelope.json"), carol));
    }

    @Test
    void theFirstEntryThatNamesTheMemberIsTheOneUsed() throws Exception {
        // A duplicate entry naming bob, placed first, over alice's wrap: 0.12 took the first, so it fails.
        String duplicated = edit(text("sharing-manifest.json"), m -> {
            JsonObject copy = member(m, 0).deepCopy();
            copy.addProperty("ed25519PublicKey", identityId(bob));
            JsonArray members = new JsonArray();
            members.add(copy);
            m.getAsJsonArray("members").forEach(members::add);
            m.add("members", members);
        });
        assertKind(Kind.CRYPTO, () -> LegacyVaultReader.read(duplicated, text("sharing-envelope.json"), bob));
    }

    @Test
    void aNullMemberEntryIsSkipped() throws Exception {
        String withNull = edit(text("sharing-manifest.json"), m -> {
            JsonArray members = new JsonArray();
            members.add(JsonNull.INSTANCE);
            m.getAsJsonArray("members").forEach(members::add);
            m.add("members", members);
        });
        assertEquals(expected("sharing"), LegacyVaultReader.read(withNull, text("sharing-envelope.json"), bob));
    }

    @Test
    void anEntryFromAnotherKeyEpochIsRefused() throws Exception {
        String stale = edit(text("sharing-manifest.json"), m -> member(m, 1).addProperty("keyEpoch", 1));
        assertKind(Kind.PROTOCOL, () -> LegacyVaultReader.read(stale, text("sharing-envelope.json"), bob));
    }

    @Test
    void anotherWrapSchemeIsRefused() throws Exception {
        String manifest = edit(text("sharing-manifest.json"), m -> m.addProperty("schemeId", "OTHER-v1"));
        assertKind(Kind.PROTOCOL, () -> LegacyVaultReader.read(manifest, text("sharing-envelope.json"), bob));
        String entry = edit(
                text("sharing-manifest.json"),
                m -> member(m, 1).getAsJsonObject("wrappedDataKey").addProperty("schemeId", "OTHER-v1"));
        assertKind(Kind.PROTOCOL, () -> LegacyVaultReader.read(entry, text("sharing-envelope.json"), bob));
    }

    @Test
    void aTamperedWrappedKeyDoesNotUnwrap() throws Exception {
        String tampered = edit(text("sharing-manifest.json"), m -> {
            JsonObject wrapped = member(m, 1).getAsJsonObject("wrappedDataKey");
            wrapped.addProperty(
                    "ciphertext", flipFirst(wrapped.get("ciphertext").getAsString()));
        });
        assertKind(Kind.CRYPTO, () -> LegacyVaultReader.read(tampered, text("sharing-envelope.json"), bob));
    }

    // --- The envelope ---------------------------------------------------------------------------

    @Test
    void aTamperedCiphertextOrIvDoesNotAuthenticate() throws Exception {
        String ct = edit(
                text("sharing-envelope.json"),
                e -> e.addProperty("ciphertext", flipFirst(e.get("ciphertext").getAsString())));
        assertKind(Kind.CRYPTO, () -> LegacyVaultReader.read(text("sharing-manifest.json"), ct, bob));
        String iv = edit(
                text("sharing-envelope.json"),
                e -> e.addProperty("iv", flipFirst(e.get("iv").getAsString())));
        assertKind(Kind.CRYPTO, () -> LegacyVaultReader.read(text("sharing-manifest.json"), iv, bob));
    }

    @Test
    void aTruncatedCiphertextDoesNotAuthenticate() throws Exception {
        String truncated = edit(text("sharing-envelope.json"), e -> {
            String ct = e.get("ciphertext").getAsString();
            e.addProperty("ciphertext", ct.substring(0, ct.length() - 8)); // still base64, 6 bytes short
        });
        assertKind(Kind.CRYPTO, () -> LegacyVaultReader.read(text("sharing-manifest.json"), truncated, bob));
        String tagOnly = edit(text("sharing-envelope.json"), e -> e.addProperty("ciphertext", "AAAA"));
        assertKind(Kind.CRYPTO, () -> LegacyVaultReader.read(text("sharing-manifest.json"), tagOnly, bob));
    }

    @Test
    void aHeaderThatIsNotTheOneSealedFailsTheAad() throws Exception {
        // A later version the manifest accepts, but not the one bound into the AAD.
        String version = edit(text("sharing-envelope.json"), e -> e.addProperty("payloadVersion", 3));
        assertKind(Kind.CRYPTO, () -> LegacyVaultReader.read(text("sharing-manifest.json"), version, bob));
        // Another repository id on both documents: every header check passes, the AAD does not.
        String manifest = edit(text("sharing-manifest.json"), m -> m.addProperty("repoId", "another-repo"));
        String envelope = edit(text("sharing-envelope.json"), e -> e.addProperty("repoId", "another-repo"));
        assertKind(Kind.CRYPTO, () -> LegacyVaultReader.read(manifest, envelope, bob));
    }

    @Test
    void anEnvelopeOfAnotherRepositoryIsRefused() throws Exception {
        assertKind(
                Kind.PROTOCOL,
                () -> LegacyVaultReader.read(text("sharing-manifest.json"), text("withholding-envelope.json"), bob));
    }

    @Test
    void anEnvelopeFromAnotherKeyEpochIsRefused() throws Exception {
        // The repository after the rotation, with the envelope from before it.
        assertKind(
                Kind.PROTOCOL,
                () -> LegacyVaultReader.read(text("rotated-manifest.json"), text("sharing-envelope.json"), alice));
    }

    @Test
    void anEnvelopeOlderThanTheManifestIsRefused() throws Exception {
        String ahead = edit(text("sharing-manifest.json"), m -> m.addProperty("payloadVersion", 3));
        assertKind(Kind.PROTOCOL, () -> LegacyVaultReader.read(ahead, text("sharing-envelope.json"), bob));
        String level = edit(text("sharing-manifest.json"), m -> m.addProperty("payloadVersion", 1));
        assertEquals(expected("sharing"), LegacyVaultReader.read(level, text("sharing-envelope.json"), bob));
    }

    // --- Text that is not a 0.4 document ---------------------------------------------------------

    @Test
    void textThatIsNotJsonIsInvalidInput() throws Exception {
        String manifest = text("sharing-manifest.json");
        String envelope = text("sharing-envelope.json");
        for (String garbage : List.of("", "not json", "{", manifest.substring(0, manifest.length() / 2), "{} {}")) {
            assertKind(Kind.INVALID_INPUT, () -> LegacyVaultReader.read(garbage, envelope, bob));
            assertKind(Kind.INVALID_INPUT, () -> LegacyVaultReader.read(manifest, garbage, bob));
        }
    }

    @Test
    void jsonThatIsNotTheOldShapeIsProtocol() throws Exception {
        String manifest = text("sharing-manifest.json");
        String envelope = text("sharing-envelope.json");
        for (String shape : List.of("[]", "{}", "42", "null")) {
            assertKind(Kind.PROTOCOL, () -> LegacyVaultReader.read(shape, envelope, bob));
            assertKind(Kind.PROTOCOL, () -> LegacyVaultReader.read(manifest, shape, bob));
        }
        List<Consumer<JsonObject>> manifestEdits = List.of(
                m -> m.remove("members"),
                m -> m.addProperty("members", "everyone"),
                m -> m.remove("repoId"),
                m -> m.addProperty("keyEpoch", "0"),
                m -> m.addProperty("shareRefreshTokens", "yes"),
                m -> member(m, 1).remove("wrappedDataKey"),
                m -> member(m, 1).getAsJsonObject("wrappedDataKey").addProperty("iv", "AAAA"),
                m -> member(m, 1).getAsJsonObject("wrappedDataKey").addProperty("ephemeralPublicKey", "!!"));
        for (Consumer<JsonObject> e : manifestEdits) {
            String edited = edit(manifest, e);
            assertKind(Kind.PROTOCOL, () -> LegacyVaultReader.read(edited, envelope, bob));
        }
        List<Consumer<JsonObject>> envelopeEdits = List.of(
                e -> e.remove("ciphertext"),
                e -> e.addProperty("iv", "AAAA"),
                e -> e.addProperty("ciphertext", "not base64!"),
                e -> e.remove("payloadVersion"));
        for (Consumer<JsonObject> e : envelopeEdits) {
            String edited = edit(envelope, e);
            assertKind(Kind.PROTOCOL, () -> LegacyVaultReader.read(manifest, edited, bob));
        }
    }

    @Test
    void aFailureQuotesNoInput() throws Exception {
        String manifest = edit(text("sharing-manifest.json"), m -> m.addProperty("repoId", "secret-repo-name"));
        AltsException e =
                assertKind(Kind.PROTOCOL, () -> LegacyVaultReader.read(manifest, text("sharing-envelope.json"), bob));
        assertFalse(e.getMessage().contains("secret-repo-name"), e.getMessage());
    }

    @Test
    void everyArgumentIsRequired() throws Exception {
        String manifest = text("sharing-manifest.json");
        String envelope = text("sharing-envelope.json");
        assertThrows(NullPointerException.class, () -> LegacyVaultReader.read(null, envelope, bob));
        assertThrows(NullPointerException.class, () -> LegacyVaultReader.read(manifest, null, bob));
        assertThrows(NullPointerException.class, () -> LegacyVaultReader.read(manifest, envelope, null));
    }

    // --- Helpers --------------------------------------------------------------------------------

    private static List<AltAccount> read(String repo, VaultIdentity who) throws IOException {
        return LegacyVaultReader.read(text(repo + "-manifest.json"), text(repo + "-envelope.json"), who);
    }

    private static List<AltAccount> expected(String repo) throws IOException {
        List<AltAccount> list = AltAccountJson.gson()
                .fromJson(text(repo + "-expected.json"), new TypeToken<List<AltAccount>>() {}.getType());
        assertNotNull(list);
        return list;
    }

    private static WrappedIdentity identity(String name) throws IOException {
        return new Gson().fromJson(text("identity-" + name + ".json"), WrappedIdentity.class);
    }

    private static String text(String name) throws IOException {
        try (InputStream in = LegacyVaultReaderTest.class.getResourceAsStream("/legacy-vault-0.4/" + name)) {
            Objects.requireNonNull(in, name);
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static String edit(String json, Consumer<JsonObject> change) {
        JsonObject o = JsonParser.parseString(json).getAsJsonObject();
        change.accept(o);
        return o.toString();
    }

    private static JsonObject member(JsonObject manifest, int index) {
        return manifest.getAsJsonArray("members").get(index).getAsJsonObject();
    }

    private static String identityId(VaultIdentity id) {
        return id.identityId();
    }

    /** Changes the first base64 character, so the bytes differ and the string stays base64. */
    private static String flipFirst(String base64) {
        char c = base64.charAt(0);
        return (c == 'A' ? 'B' : 'A') + base64.substring(1);
    }

    private static AltsException assertKind(Kind kind, Executable call) {
        AltsException e = assertThrows(AltsException.class, call);
        assertEquals(kind, e.kind(), e.getMessage());
        // One prefix for every failure, the shared AVP helpers' included, so a log line says where it came from.
        assertTrue(e.getMessage().startsWith("Vault 0.4 import: "), e.getMessage());
        return e;
    }
}

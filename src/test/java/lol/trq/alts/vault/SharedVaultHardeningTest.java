package lol.trq.alts.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.google.gson.Gson;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import lol.trq.alts.crypto.CryptoException;
import lol.trq.alts.crypto.Ed25519;
import lol.trq.alts.crypto.PayloadCipher;
import lol.trq.alts.crypto.VaultIdentity;
import lol.trq.alts.crypto.X25519;
import lol.trq.alts.crypto.X25519HkdfAesGcmKeyWrap;
import lol.trq.alts.model.AccountType;
import lol.trq.alts.model.AltAccount;
import lol.trq.alts.vault.transport.EncryptedEnvelope;
import lol.trq.alts.vault.transport.IssuerSignedKeyBindingVerifier;
import lol.trq.alts.vault.transport.KeyBindingVerifier;
import lol.trq.alts.vault.transport.MemberEntry;
import lol.trq.alts.vault.transport.VaultManifest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * The checks a client makes on what a server hands it: rollback floors, epoch and scheme agreement,
 * key-binding verification before every wrap, and malformed input surfacing as checked exceptions.
 */
class SharedVaultHardeningTest {

    private static KeyPair issuer;
    private static VaultIdentity alice;
    private static VaultIdentity bob;
    private static VaultIdentity mallory;

    private final SharedVault trusting =
            new SharedVault(new X25519HkdfAesGcmKeyWrap(), KeyBindingVerifier.trustTransport());
    private SharedVault verifying;

    @BeforeAll
    static void identities() throws Exception {
        issuer = Ed25519.newKeyPair();
        alice = VaultIdentity.create("a".toCharArray());
        bob = VaultIdentity.create("b".toCharArray());
        mallory = VaultIdentity.create("m".toCharArray());
    }

    private SharedVault verifying() {
        if (verifying == null) {
            verifying = new SharedVault(
                    new X25519HkdfAesGcmKeyWrap(), new IssuerSignedKeyBindingVerifier(issuer.getPublic()));
        }
        return verifying;
    }

    private static MemberPublicKey pub(VaultIdentity id) throws Exception {
        return new MemberPublicKey(id.identityId(), x25519(id));
    }

    private static String x25519(VaultIdentity id) throws Exception {
        return Base64.getEncoder().encodeToString(X25519.encodePublicKey(id.keyAgreementPublicKey()));
    }

    private static String issuerSig(MemberPublicKey keys) throws Exception {
        byte[] message = IssuerSignedKeyBindingVerifier.bindingMessage(keys.ed25519PublicKey(), keys.x25519PublicKey());
        return Base64.getEncoder().encodeToString(Ed25519.sign(issuer.getPrivate(), message));
    }

    private static List<AltAccount> alts(String name) {
        return List.of(new AltAccount(
                "uuid-" + name, name, "token-" + name, AccountType.MICROSOFT, 1000L, null, null, null, null, null, 0L));
    }

    private static VaultManifest withMembers(VaultManifest base, List<MemberEntry> members) {
        return new VaultManifest(
                base.repoId(),
                base.schemeId(),
                base.keyEpoch(),
                base.payloadVersion(),
                members,
                base.shareRefreshTokens());
    }

    private static VaultManifest rotatedManifest(VaultManifest base, SharedVault.RotationResult rotation) {
        return new VaultManifest(
                base.repoId(),
                base.schemeId(),
                rotation.newKeyEpoch(),
                rotation.context().payloadVersion(),
                rotation.rewrappedMembers(),
                base.shareRefreshTokens());
    }

    // --- rollback and downgrade ---------------------------------------------------------------

    @Test
    void rejectsEnvelopeSealedUnderAnotherKeyEpoch() throws Exception {
        SharedVault.CreatedRepo created = trusting.createRepo(alice, alts("v1"));
        SharedVault.RotationResult rotation = trusting.rotateKey(created.context(), alts("v2"), created.manifest());

        // The old context still holds the epoch-0 key; an epoch-1 envelope is not for it.
        assertThrows(VaultException.class, () -> trusting.decryptPayload(created.context(), rotation.envelope(), 0));
        // And the reverse: a replayed epoch-0 envelope is refused by the rotated context.
        assertThrows(VaultException.class, () -> trusting.decryptPayload(rotation.context(), created.envelope(), 0));
    }

    @Test
    void rejectsManifestNamingAnotherScheme() throws Exception {
        SharedVault.CreatedRepo created = trusting.createRepo(alice, alts("v1"));
        VaultManifest other = new VaultManifest(
                created.manifest().repoId(),
                "some-weaker-scheme-v0",
                created.manifest().keyEpoch(),
                created.manifest().payloadVersion(),
                created.manifest().members(),
                false);

        assertThrows(VaultException.class, () -> trusting.openRepo(other, alice));
    }

    @Test
    void rejectsManifestBelowThePinnedKeyEpoch() throws Exception {
        SharedVault.CreatedRepo created = trusting.createRepo(alice, alts("v1"));
        SharedVault.RotationResult rotation = trusting.rotateKey(created.context(), alts("v2"), created.manifest());
        RepoPin pin = rotation.context().pin();
        assertEquals(new RepoPin(1L, 2L), pin);

        // A server replays the pre-rotation manifest: it is internally valid, only stale.
        assertThrows(VaultException.class, () -> trusting.openRepo(created.manifest(), alice, pin));

        // The current manifest still opens at exactly the pin.
        RepoContext reopened = trusting.openRepo(rotatedManifest(created.manifest(), rotation), alice, pin);
        assertEquals(pin, reopened.pin());
    }

    @Test
    void rejectsManifestBelowThePinnedPayloadVersion() throws Exception {
        SharedVault.CreatedRepo created = trusting.createRepo(alice, alts("v1"));
        RepoPin pin = new RepoPin(0L, 5L);

        assertThrows(VaultException.class, () -> trusting.openRepo(created.manifest(), alice, pin));
    }

    @Test
    void openWithoutAPinReportsTheObservedFloor() throws Exception {
        SharedVault.CreatedRepo created = trusting.createRepo(alice, alts("v1"));

        RepoContext opened = trusting.openRepo(created.manifest(), alice, RepoPin.none());

        assertEquals(new RepoPin(0L, 1L), opened.pin());
        assertEquals(new RepoPin(3L, 9L), new RepoPin(3L, 1L).advancedTo(new RepoPin(0L, 9L)));
        assertThrows(IllegalArgumentException.class, () -> new RepoPin(-1L, 0L));
        assertThrows(IllegalArgumentException.class, () -> new RepoPin(0L, -1L));
    }

    @Test
    void rejectsMemberEntryFromAnotherEpochThanTheManifest() throws Exception {
        SharedVault.CreatedRepo created = trusting.createRepo(alice, alts("v1"));
        VaultManifest relabelled = new VaultManifest(
                created.manifest().repoId(),
                created.manifest().schemeId(),
                4L,
                created.manifest().payloadVersion(),
                created.manifest().members(),
                false);

        // The entry is the epoch-0 wrap; presenting it as epoch 4 must not yield an "epoch 4" key.
        assertThrows(VaultException.class, () -> trusting.openRepo(relabelled, alice));
    }

    // --- key-binding verification -------------------------------------------------------------

    @Test
    void addMemberWrapsOnlyToKeysTheVerifierAccepts() throws Exception {
        SharedVault vault = verifying();
        SharedVault.CreatedRepo created = vault.createRepo(alice, alts("v1"));
        String sig = issuerSig(pub(bob));

        MemberEntry entry = vault.addMember(created.context(), pub(bob), sig);

        assertEquals(sig, entry.keyBindingSig());
        VaultManifest manifest = withMembers(
                created.manifest(), List.of(created.manifest().members().get(0), entry));
        assertEquals(alts("v1"), vault.decryptPayload(vault.openRepo(manifest, bob), created.envelope(), 0));
    }

    @Test
    void addMemberRefusesUnsignedOrSubstitutedKeys() throws Exception {
        SharedVault vault = verifying();
        SharedVault.CreatedRepo created = vault.createRepo(alice, alts("v1"));

        assertThrows(VaultException.class, () -> vault.addMember(created.context(), pub(bob), null));

        // Bob's identity, the attacker's X25519 key, and the signature issued for Bob's real pair.
        MemberPublicKey substituted = new MemberPublicKey(bob.identityId(), x25519(mallory));
        String realSig = issuerSig(pub(bob));
        assertThrows(VaultException.class, () -> vault.addMember(created.context(), substituted, realSig));
    }

    @Test
    @SuppressWarnings("deprecation")
    void deprecatedAddMemberStillRunsTheVerifier() throws Exception {
        SharedVault vault = verifying();
        SharedVault.CreatedRepo created = vault.createRepo(alice, alts("v1"));

        assertThrows(CryptoException.class, () -> vault.addMember(created.context(), pub(bob)));
        assertThrows(
                CryptoException.class,
                () -> vault.rotateKey(created.context(), alts("v2"), List.of(pub(alice), pub(bob))));
        // With an explicit trust-the-transport choice the old signatures keep working.
        assertEquals(
                bob.identityId(),
                trusting.addMember(created.context(), pub(bob)).ed25519PublicKey());
    }

    @Test
    void rotateKeyVerifiesTheServedRosterAndKeepsSignatures() throws Exception {
        SharedVault vault = verifying();
        SharedVault.CreatedRepo created = vault.createRepo(alice, alts("v1"));
        String sig = issuerSig(pub(bob));
        MemberEntry bobEntry = vault.addMember(created.context(), pub(bob), sig);
        VaultManifest manifest = withMembers(
                created.manifest(), List.of(created.manifest().members().get(0), bobEntry));

        SharedVault.RotationResult rotation = vault.rotateKey(created.context(), alts("v2"), manifest);

        assertEquals(2, rotation.rewrappedMembers().size());
        assertEquals(sig, rotation.rewrappedMembers().get(1).keyBindingSig());
        RepoContext bobCtx = vault.openRepo(rotatedManifest(manifest, rotation), bob);
        assertEquals(alts("v2"), vault.decryptPayload(bobCtx, rotation.envelope(), 0));
    }

    @Test
    void rotateKeyRefusesARosterWithASubstitutedMemberKey() throws Exception {
        SharedVault vault = verifying();
        SharedVault.CreatedRepo created = vault.createRepo(alice, alts("v1"));
        MemberEntry bobEntry = vault.addMember(created.context(), pub(bob), issuerSig(pub(bob)));
        // The server keeps Bob's id and signature but swaps in a key it controls.
        MemberEntry swapped = new MemberEntry(
                bobEntry.ed25519PublicKey(),
                x25519(mallory),
                bobEntry.wrappedDataKey(),
                bobEntry.keyEpoch(),
                bobEntry.keyBindingSig());
        VaultManifest served = withMembers(
                created.manifest(), List.of(created.manifest().members().get(0), swapped));

        assertThrows(VaultException.class, () -> vault.rotateKey(created.context(), alts("v2"), served));
    }

    @Test
    void rotateKeyRefusesARosterThatMisstatesTheCaller() throws Exception {
        SharedVault.CreatedRepo created = trusting.createRepo(alice, alts("v1"));
        MemberEntry own = created.manifest().members().get(0);
        MemberEntry ownSwapped =
                new MemberEntry(own.ed25519PublicKey(), x25519(mallory), own.wrappedDataKey(), own.keyEpoch());
        MemberEntry bobEntry = trusting.addMember(created.context(), pub(bob), null);

        // The caller's own X25519 key replaced.
        assertThrows(
                VaultException.class,
                () -> trusting.rotateKey(
                        created.context(), alts("v2"), withMembers(created.manifest(), List.of(ownSwapped))));
        // The caller dropped from the roster, which would lock them out of their own rotation.
        assertThrows(
                VaultException.class,
                () -> trusting.rotateKey(
                        created.context(), alts("v2"), withMembers(created.manifest(), List.of(bobEntry))));
        // A roster for some other repository.
        VaultManifest foreign =
                new VaultManifest("another-repo", created.manifest().schemeId(), 0L, 1L, List.of(own), false);
        assertThrows(VaultException.class, () -> trusting.rotateKey(created.context(), alts("v2"), foreign));
    }

    @Test
    void removeMemberRotatesToEveryoneElse() throws Exception {
        SharedVault.CreatedRepo created = trusting.createRepo(alice, alts("v1"));
        MemberEntry bobEntry = trusting.addMember(created.context(), pub(bob), null);
        MemberEntry malloryEntry = trusting.addMember(created.context(), pub(mallory), null);
        VaultManifest manifest = withMembers(
                created.manifest(), List.of(created.manifest().members().get(0), bobEntry, malloryEntry));

        SharedVault.RotationResult rotation =
                trusting.removeMember(created.context(), alts("v2"), manifest, mallory.identityId());

        VaultManifest rotated = rotatedManifest(manifest, rotation);
        assertEquals(2, rotated.members().size());
        assertNull(rotated.findMember(mallory.identityId()));
        assertEquals(alts("v2"), trusting.decryptPayload(trusting.openRepo(rotated, bob), rotation.envelope(), 0));

        assertThrows(
                VaultException.class,
                () -> trusting.removeMember(created.context(), alts("v2"), rotated, mallory.identityId()));
        assertThrows(
                VaultException.class,
                () -> trusting.removeMember(created.context(), alts("v2"), manifest, alice.identityId()));
    }

    // --- malformed, server-controlled input ---------------------------------------------------

    @Test
    void malformedEnvelopeBase64IsAVaultException() throws Exception {
        SharedVault.CreatedRepo created = trusting.createRepo(alice, alts("v1"));
        EncryptedEnvelope good = created.envelope();
        EncryptedEnvelope badIv = new EncryptedEnvelope(
                good.repoId(), good.payloadVersion(), good.keyEpoch(), "not base64!", good.ciphertext());
        EncryptedEnvelope badCiphertext =
                new EncryptedEnvelope(good.repoId(), good.payloadVersion(), good.keyEpoch(), good.iv(), "***");

        assertThrows(VaultException.class, () -> trusting.decryptPayload(created.context(), badIv, 0));
        assertThrows(VaultException.class, () -> trusting.decryptPayload(created.context(), badCiphertext, 0));
    }

    @Test
    void malformedMemberKeyIsACryptoException() throws Exception {
        SharedVault.CreatedRepo created = trusting.createRepo(alice, alts("v1"));

        assertThrows(
                CryptoException.class,
                () -> trusting.addMember(
                        created.context(), new MemberPublicKey(bob.identityId(), "not base64!"), null));
        assertThrows(
                CryptoException.class,
                () -> trusting.addMember(created.context(), new MemberPublicKey(bob.identityId(), "c2hvcnQ="), null));
    }

    @Test
    void nullEntriesInAPeersPayloadAreDropped() throws Exception {
        SharedVault.CreatedRepo created = trusting.createRepo(alice, alts("v1"));
        String json = "{\"alts\":[null," + new Gson().toJson(alts("kept").get(0)) + ",null],\"payloadVersion\":2}";

        List<AltAccount> recovered = trusting.decryptPayload(created.context(), seal(created.context(), json), 0);

        assertEquals(alts("kept"), recovered);
    }

    @Test
    void aPayloadThatIsNotAnAltListIsAVaultException() throws Exception {
        SharedVault.CreatedRepo created = trusting.createRepo(alice, alts("v1"));

        assertThrows(
                VaultException.class,
                () -> trusting.decryptPayload(created.context(), seal(created.context(), "{\"alts\":"), 0));
        assertThrows(
                VaultException.class,
                () -> trusting.decryptPayload(created.context(), seal(created.context(), "{\"alts\":7}"), 0));
    }

    @Test
    void nullEntriesInACallersListAreDroppedOnEncrypt() throws Exception {
        SharedVault.CreatedRepo created = trusting.createRepo(alice, alts("v1"));
        List<AltAccount> withNull = new ArrayList<>(alts("kept"));
        withNull.add(null);

        EncryptedEnvelope envelope = trusting.encryptPayload(created.context(), withNull);

        assertEquals(alts("kept"), trusting.decryptPayload(created.context(), envelope, 0));
    }

    @Test
    void anObjectTheServerNeverServedIsAVaultException() throws Exception {
        SharedVault.CreatedRepo created = trusting.createRepo(alice, alts("v1"));

        assertThrows(VaultException.class, () -> trusting.openRepo(null, alice));
        assertThrows(VaultException.class, () -> trusting.decryptPayload(created.context(), null, 0));
        assertThrows(
                VaultException.class, () -> trusting.rotateKey(created.context(), alts("v2"), (VaultManifest) null));
        assertThrows(
                VaultException.class,
                () -> trusting.removeMember(created.context(), alts("v2"), null, bob.identityId()));
    }

    @Test
    void aServedObjectMissingARequiredFieldNeverReachesTheVaultHalfBuilt() {
        // The transport records refuse a null required field when they are constructed, which is where a
        // host's JSON layer builds them; nothing downstream has to wonder whether repoId is there.
        com.google.gson.Gson gson = new com.google.gson.Gson();
        assertThrows(
                RuntimeException.class,
                () -> gson.fromJson("{\"schemeId\":\"x\",\"members\":[]}", VaultManifest.class));
        assertThrows(
                RuntimeException.class,
                () -> gson.fromJson("{\"repoId\":\"r\",\"schemeId\":\"x\"}", VaultManifest.class));
        assertThrows(
                RuntimeException.class,
                () -> gson.fromJson(
                        "{\"iv\":\"AA==\",\"ciphertext\":\"AA==\"}",
                        lol.trq.alts.vault.transport.EncryptedEnvelope.class));
        assertThrows(RuntimeException.class, () -> gson.fromJson("{\"x25519PublicKey\":\"AA==\"}", MemberEntry.class));
    }

    @Test
    void aNullMemberEntryInAManifestDoesNotBreakLookup() throws Exception {
        SharedVault.CreatedRepo created = trusting.createRepo(alice, alts("v1"));
        List<MemberEntry> members = new ArrayList<>();
        members.add(null);
        members.add(created.manifest().members().get(0));
        VaultManifest served = withMembers(created.manifest(), members);

        assertNotEquals(null, trusting.openRepo(served, alice));
        assertThrows(VaultException.class, () -> trusting.openRepo(served, bob));
        assertThrows(VaultException.class, () -> trusting.rotateKey(created.context(), alts("v2"), served));
    }

    /** Seals arbitrary plaintext exactly as a member holding the data key could. */
    private static EncryptedEnvelope seal(RepoContext ctx, String json) throws Exception {
        long version = ctx.payloadVersion() + 1;
        byte[] iv = PayloadCipher.newIv();
        byte[] aad = PayloadCipher.aad(ctx.repoId(), version, ctx.dataKey().epoch());
        byte[] ciphertext =
                PayloadCipher.encrypt(ctx.dataKey().secretKey(), iv, aad, json.getBytes(StandardCharsets.UTF_8));
        Base64.Encoder b64 = Base64.getEncoder();
        return new EncryptedEnvelope(
                ctx.repoId(), version, ctx.dataKey().epoch(), b64.encodeToString(iv), b64.encodeToString(ciphertext));
    }
}

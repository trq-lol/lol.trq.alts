package lol.trq.alts.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
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

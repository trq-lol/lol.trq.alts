package lol.trq.alts.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import javax.crypto.SecretKey;
import lol.trq.alts.crypto.CryptoException;
import lol.trq.alts.crypto.KeyWrapScheme;
import lol.trq.alts.crypto.WrappedKey;
import lol.trq.alts.crypto.X25519;
import lol.trq.alts.crypto.X25519HkdfAesGcmKeyWrap;
import lol.trq.alts.model.AccountType;
import lol.trq.alts.model.AltAccount;
import lol.trq.alts.vault.transport.KeyBindingVerifier;
import lol.trq.alts.vault.transport.MemberEntry;
import lol.trq.alts.vault.transport.VaultManifest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * The repository data key is wrapped to another member's key only once the verifier has vouched for
 * that key. Not afterwards, and not speculatively: a wrap computed for a key that then fails
 * verification is the data key encrypted for whoever substituted it.
 */
class VerifyBeforeWrapTest {

    private static VaultIdentity alice;
    private static VaultIdentity bob;

    /** A real scheme that writes down every wrap it performs, next to the verifier's own log. */
    private static final class RecordingScheme implements KeyWrapScheme {

        private final KeyWrapScheme real = new X25519HkdfAesGcmKeyWrap();
        private final List<String> log;

        RecordingScheme(List<String> log) {
            this.log = log;
        }

        @Override
        public String schemeId() {
            return real.schemeId();
        }

        @Override
        public WrappedKey wrap(SecretKey dataKey, PublicKey recipientPublicKey) throws CryptoException {
            log.add("wrap:" + Base64.getEncoder().encodeToString(X25519.encodePublicKey(recipientPublicKey)));
            return real.wrap(dataKey, recipientPublicKey);
        }

        @Override
        public SecretKey unwrap(WrappedKey blob, PrivateKey recipientPrivateKey) throws CryptoException {
            return real.unwrap(blob, recipientPrivateKey);
        }
    }

    @BeforeAll
    static void identities() throws Exception {
        alice = VaultIdentity.create("a".toCharArray());
        bob = VaultIdentity.create("b".toCharArray());
    }

    private static String x25519(VaultIdentity id) throws Exception {
        return Base64.getEncoder().encodeToString(X25519.encodePublicKey(id.keyAgreementPublicKey()));
    }

    private static MemberPublicKey pub(VaultIdentity id) throws Exception {
        return new MemberPublicKey(id.identityId(), x25519(id));
    }

    private static List<AltAccount> alts() {
        return List.of(AltAccount.of("uuid-1", "Alex", "token", AccountType.MICROSOFT));
    }

    @Test
    void nothingIsWrappedToAKeyTheVerifierRefuses() throws Exception {
        List<String> log = new ArrayList<>();
        KeyBindingVerifier refusing = (repoId, entry) -> {
            throw new VaultException("not bound");
        };
        SharedVault vault = new SharedVault(new RecordingScheme(log), refusing);
        SharedVault.CreatedRepo created = vault.createRepo(alice, alts());
        log.clear();

        assertThrows(VaultException.class, () -> vault.addMember(created.context(), pub(bob), "sig"));

        assertEquals(List.of(), log, "the data key must not be wrapped, even to be thrown away, for a refused key");
    }

    @Test
    void theVerifierRunsBeforeTheWrapItAuthorises() throws Exception {
        List<String> log = new ArrayList<>();
        KeyBindingVerifier logging = (repoId, entry) -> {
            log.add("verify:" + entry.x25519PublicKey());
            return new MemberPublicKey(entry.ed25519PublicKey(), entry.x25519PublicKey());
        };
        SharedVault vault = new SharedVault(new RecordingScheme(log), logging);
        SharedVault.CreatedRepo created = vault.createRepo(alice, alts());
        log.clear();

        MemberEntry entry = vault.addMember(created.context(), pub(bob), "sig");

        assertEquals(List.of("verify:" + x25519(bob), "wrap:" + x25519(bob)), log);
        assertEquals("sig", entry.keyBindingSig(), "the signature travels with the entry it vouched for");
    }

    @Test
    void aRotationWrapsNothingForARosterMemberTheVerifierRefuses() throws Exception {
        List<String> log = new ArrayList<>();
        KeyBindingVerifier acceptsNobody = (repoId, entry) -> {
            throw new VaultException("not bound");
        };
        SharedVault setup = new SharedVault(new X25519HkdfAesGcmKeyWrap(), KeyBindingVerifier.trustTransport());
        SharedVault.CreatedRepo created = setup.createRepo(alice, alts());
        MemberEntry bobEntry = setup.addMember(created.context(), pub(bob), null);
        VaultManifest roster = new VaultManifest(
                created.manifest().repoId(),
                created.manifest().schemeId(),
                created.manifest().keyEpoch(),
                created.manifest().payloadVersion(),
                List.of(created.manifest().members().get(0), bobEntry),
                false);

        SharedVault vault = new SharedVault(new RecordingScheme(log), acceptsNobody);

        assertThrows(VaultException.class, () -> vault.rotateKey(created.context(), alts(), roster));

        assertEquals(
                List.of(),
                log.stream().filter(line -> line.equals("wrap:" + safe(bob))).toList(),
                "the new data key must never be wrapped to the member who failed verification");
    }

    private static String safe(VaultIdentity id) {
        try {
            return x25519(id);
        } catch (Exception impossible) {
            throw new AssertionError(impossible);
        }
    }

    @Test
    void aVerifierWrittenAgainstTheEntryFormIsNeverHandedARealWrappedKey() throws Exception {
        List<WrappedKey> seen = new ArrayList<>();
        KeyBindingVerifier inspecting = (repoId, entry) -> {
            seen.add(entry.wrappedDataKey());
            return new MemberPublicKey(entry.ed25519PublicKey(), entry.x25519PublicKey());
        };
        SharedVault vault = new SharedVault(new X25519HkdfAesGcmKeyWrap(), inspecting);
        SharedVault.CreatedRepo created = vault.createRepo(alice, alts());

        vault.addMember(created.context(), pub(bob), "sig");

        assertEquals(1, seen.size());
        assertEquals("", seen.get(0).ciphertext(), "verification happens before any key material is wrapped");
    }
}

package lol.trq.alts.vault;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure;
import lol.trq.alts.crypto.Ed25519;
import lol.trq.alts.crypto.Pbkdf2;
import lol.trq.alts.crypto.X25519;
import lol.trq.alts.internal.avp.AvpCrypto;
import lol.trq.alts.internal.avp.Challenge;
import lol.trq.alts.internal.avp.Commits;
import lol.trq.alts.internal.avp.Tokens;
import lol.trq.alts.internal.avp.WrappedKey;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

/** Create / unlock / recovery round-trips for the vault identity. */
class VaultIdentityTest {

    @Test
    void createThenUnlockWithSamePassphrase() throws Exception {
        VaultIdentity created = VaultIdentity.create("correct horse".toCharArray());
        WrappedIdentity stored = created.export();

        VaultIdentity unlocked = VaultIdentity.unlock(stored, "correct horse".toCharArray());

        assertEquals(created.identityId(), unlocked.identityId());

        // The unlocked private key still signs verifiably against the original public identity.
        byte[] nonce = "a 0.4 server challenge nonce".getBytes(StandardCharsets.UTF_8);
        byte[] sig = unlocked.signChallenge(nonce);
        assertTrue(Ed25519.verify(created.identityPublicKey(), nonce, sig));

        // The unlocked X25519 key unwraps a data key wrapped to the original public key.
        byte[] dataKey = AvpCrypto.randomBytes(32);
        WrappedKey blob = AvpCrypto.wrap(
                X25519.encodePublicKey(created.keyAgreementPublicKey()), dataKey, AvpCrypto.WrapLabel.DATA_KEY);
        byte[] scalar = X25519.encodePrivateKey(unlocked.keyAgreementPrivateKey());
        assertArrayEquals(dataKey, AvpCrypto.unwrap(scalar, blob, AvpCrypto.WrapLabel.DATA_KEY));
    }

    @Test
    void unlockFailsWithWrongPassphrase() throws Exception {
        WrappedIdentity stored = VaultIdentity.create("right".toCharArray()).export();
        assertKind(AltsFailure.Kind.CRYPTO, () -> VaultIdentity.unlock(stored, "wrong".toCharArray()));
    }

    @Test
    void identityIdMatchesStoredPublicKey() throws Exception {
        VaultIdentity id = VaultIdentity.create("pw".toCharArray());
        assertEquals(id.export().ed25519PublicKey(), id.identityId());
    }

    @Test
    void recoveryCodeRestoresIdentity() throws Exception {
        VaultIdentity id = VaultIdentity.create("pw".toCharArray());
        String code = RecoveryCode.newCode();
        WrappedIdentity withRecovery = id.withRecovery(code);
        assertTrue(withRecovery.hasRecovery());

        VaultIdentity restored = VaultIdentity.unlockWithRecovery(withRecovery, code);
        assertEquals(id.identityId(), restored.identityId());

        // Recovery preserves the passphrase path too.
        assertEquals(
                id.identityId(),
                VaultIdentity.unlock(withRecovery, "pw".toCharArray()).identityId());
    }

    @Test
    void recoveryFailsWithWrongCodeAndWhenAbsent() throws Exception {
        VaultIdentity id = VaultIdentity.create("pw".toCharArray());
        WrappedIdentity withRecovery = id.withRecovery(RecoveryCode.newCode());
        assertKind(
                AltsFailure.Kind.CRYPTO, () -> VaultIdentity.unlockWithRecovery(withRecovery, RecoveryCode.newCode()));
        // No recovery sealing present.
        assertKind(AltsFailure.Kind.INVALID_INPUT, () -> VaultIdentity.unlockWithRecovery(id.export(), "anything"));
    }

    @Test
    void distinctIdentitiesDiffer() throws Exception {
        assertNotEquals(
                VaultIdentity.create("pw".toCharArray()).identityId(),
                VaultIdentity.create("pw".toCharArray()).identityId());
    }

    private static String flipFirstByte(String base64) {
        byte[] raw = Base64.getDecoder().decode(base64);
        raw[0] ^= 0x01;
        return Base64.getEncoder().encodeToString(raw);
    }

    private static WrappedIdentity with(WrappedIdentity s, String ed, String x, String salt, int iterations) {
        return new WrappedIdentity(
                ed,
                x,
                salt,
                iterations,
                s.wrappedPrivateMaterial(),
                s.recoverySalt(),
                s.recoveryWrappedPrivateMaterial());
    }

    @Test
    void unlockRejectsASwappedKeyAgreementPublicKey() throws Exception {
        VaultIdentity victim = VaultIdentity.create("pw".toCharArray());
        WrappedIdentity stored = victim.withRecovery("recovery-code");
        // Whoever can edit the stored record (a synced backup) points the X25519 key at their own.
        String attackerKey = Base64.getEncoder()
                .encodeToString(X25519.encodePublicKey(X25519.newKeyPair().getPublic()));
        WrappedIdentity tampered =
                with(stored, stored.ed25519PublicKey(), attackerKey, stored.kdfSalt(), stored.kdfIterations());

        assertKind(AltsFailure.Kind.CRYPTO, () -> VaultIdentity.unlock(tampered, "pw".toCharArray()));
        assertKind(AltsFailure.Kind.CRYPTO, () -> VaultIdentity.unlockWithRecovery(tampered, "recovery-code"));
    }

    @Test
    void unlockRejectsASwappedIdentityPublicKey() throws Exception {
        WrappedIdentity stored = VaultIdentity.create("pw".toCharArray()).export();
        String otherIdentity = Base64.getEncoder()
                .encodeToString(Ed25519.encodePublicKey(Ed25519.newKeyPair().getPublic()));
        WrappedIdentity tampered =
                with(stored, otherIdentity, stored.x25519PublicKey(), stored.kdfSalt(), stored.kdfIterations());

        assertKind(AltsFailure.Kind.CRYPTO, () -> VaultIdentity.unlock(tampered, "pw".toCharArray()));
    }

    @Test
    void unlockRejectsAnOutOfRangeIterationCount() throws Exception {
        WrappedIdentity stored = VaultIdentity.create("pw".toCharArray()).export();

        for (int iterations :
                new int[] {0, -1, 1, Pbkdf2.MIN_ITERATIONS - 1, Pbkdf2.MAX_ITERATIONS + 1, Integer.MAX_VALUE}) {
            WrappedIdentity tampered =
                    with(stored, stored.ed25519PublicKey(), stored.x25519PublicKey(), stored.kdfSalt(), iterations);
            assertKind(AltsFailure.Kind.INVALID_INPUT, () -> VaultIdentity.unlock(tampered, "pw".toCharArray()));
        }
    }

    @Test
    void unlockReportsAMalformedRecordAsInvalidInput() throws Exception {
        WrappedIdentity s = VaultIdentity.create("pw".toCharArray()).withRecovery("recovery-code");
        char[] pw = "pw".toCharArray();

        assertKind(
                AltsFailure.Kind.INVALID_INPUT,
                () -> VaultIdentity.unlock(
                        with(s, s.ed25519PublicKey(), s.x25519PublicKey(), "not base64!", s.kdfIterations()), pw));
        assertKind(
                AltsFailure.Kind.INVALID_INPUT,
                () -> VaultIdentity.unlock(
                        with(s, s.ed25519PublicKey(), s.x25519PublicKey(), "", s.kdfIterations()), pw));
        assertKind(
                AltsFailure.Kind.INVALID_INPUT,
                () -> VaultIdentity.unlock(
                        with(s, "not base64!", s.x25519PublicKey(), s.kdfSalt(), s.kdfIterations()), pw));
        assertKind(
                AltsFailure.Kind.INVALID_INPUT,
                () -> VaultIdentity.unlock(
                        with(s, s.ed25519PublicKey(), "not base64!", s.kdfSalt(), s.kdfIterations()), pw));
        WrappedIdentity badMaterial = new WrappedIdentity(
                s.ed25519PublicKey(), s.x25519PublicKey(), s.kdfSalt(), s.kdfIterations(), "***", "***", "***");
        assertKind(AltsFailure.Kind.INVALID_INPUT, () -> VaultIdentity.unlock(badMaterial, pw));
        assertKind(
                AltsFailure.Kind.INVALID_INPUT, () -> VaultIdentity.unlockWithRecovery(badMaterial, "recovery-code"));
        // A flipped byte in a well-formed sealing is still an authentication failure, not a crash.
        WrappedIdentity flipped = new WrappedIdentity(
                s.ed25519PublicKey(),
                s.x25519PublicKey(),
                s.kdfSalt(),
                s.kdfIterations(),
                flipFirstByte(s.wrappedPrivateMaterial()),
                null,
                null);
        assertKind(AltsFailure.Kind.CRYPTO, () -> VaultIdentity.unlock(flipped, pw));
    }

    @Test
    void aKeyOfTheWrongLengthOrAMissingFieldIsInvalidInput() throws Exception {
        WrappedIdentity s = VaultIdentity.create("pw".toCharArray()).export();
        char[] pw = "pw".toCharArray();
        String shortKey = Base64.getEncoder().encodeToString(new byte[31]);
        assertKind(
                AltsFailure.Kind.INVALID_INPUT,
                () -> VaultIdentity.unlock(with(s, shortKey, s.x25519PublicKey(), s.kdfSalt(), s.kdfIterations()), pw));
        assertKind(
                AltsFailure.Kind.INVALID_INPUT,
                () -> VaultIdentity.unlock(
                        with(s, s.ed25519PublicKey(), shortKey, s.kdfSalt(), s.kdfIterations()), pw));
        assertKind(AltsFailure.Kind.INVALID_INPUT, () -> VaultIdentity.unlock(s, null));
        // A stored record that lost a field (for example Gson reading a truncated file) is refused as input.
        assertKind(
                AltsFailure.Kind.INVALID_INPUT,
                () -> new WrappedIdentity(null, s.x25519PublicKey(), s.kdfSalt(), 600_000, "x", null, null));
        assertKind(
                AltsFailure.Kind.INVALID_INPUT,
                () -> new WrappedIdentity(
                        s.ed25519PublicKey(), s.x25519PublicKey(), s.kdfSalt(), 600_000, null, null, null));
    }

    @Test
    void theRecoveryKeyIsPbkdf2OfTheNormalizedCodeAtTheVaultIterationCount() throws Exception {
        byte[] salt = new byte[16];
        javax.crypto.SecretKey key = RecoveryCode.deriveKey("ab-cd ef", salt);
        assertArrayEquals(
                Pbkdf2.deriveKey("abcdef".toCharArray(), salt, 600_000).getEncoded(),
                key.getEncoded(),
                "dashes and whitespace are dropped, and 600000 iterations are used");
    }

    /**
     * The 0.4 export aid must not be a signing oracle for 0.5 structures (freeze record section 4): a
     * canonical leave string or commit-signature string handed over as a "nonce" is refused unsigned, and so
     * is anything outside 16 to 1024 bytes.
     */
    @Test
    void signChallengeRefusesAnAvpStructureOrAnOutOfRangeInput() throws Exception {
        VaultIdentity identity = VaultIdentity.create("pass".toCharArray());
        byte[] memberKey = Ed25519.encodePublicKey(identity.identityPublicKey());
        byte[] leave = Tokens.leaveMessage(
                new Tokens.LeaveRequest("RBhoUI0PUSR7tD5HpFC9lA", memberKey, 1767229200000L, new byte[64]));
        byte[] commitSig = Commits.sigMessage(new byte[32]);
        byte[] challenge = Challenge.message(new byte[32], memberKey, new byte[32]);
        assertEquals(54, commitSig.length, "within the length bounds: only the tag refuses it");

        for (byte[] refused : new byte[][] {
            leave,
            commitSig,
            challenge,
            "avp/anything-at-all".getBytes(StandardCharsets.US_ASCII),
            new byte[15],
            new byte[1025]
        }) {
            AltsException e = assertThrows(AltsException.class, () -> identity.signChallenge(refused));
            assertEquals(AltsFailure.Kind.INVALID_INPUT, e.kind());
        }

        byte[] tagNotAtTheStart = "x avp/0123456789abcdef".getBytes(StandardCharsets.US_ASCII);
        for (byte[] signed : new byte[][] {new byte[16], new byte[1024], tagNotAtTheStart}) {
            byte[] sig = identity.signChallenge(signed);
            assertTrue(Ed25519.verify(identity.identityPublicKey(), signed, sig));
        }
    }

    private static void assertKind(AltsFailure.Kind kind, Executable call) {
        AltsException e = assertThrows(AltsException.class, call);
        assertEquals(kind, e.kind(), e.getMessage());
    }
}

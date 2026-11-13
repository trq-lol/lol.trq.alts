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

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.internal.avp.AvpCrypto.WrapLabel;
import lol.trq.alts.internal.avp.Commits.Commit;
import lol.trq.alts.internal.avp.Manifest.SignedManifest;
import org.junit.jupiter.api.Test;

/**
 * {@code negative.json}: every MUST-reject case is rejected for its stated reason, and wherever a case
 * carries {@code base}, the construction with {@code base} restored is accepted, so the one mutation is
 * shown to be the cause. The count per operation is pinned, so no case goes unchecked.
 */
class NegativeVectorsTest {

    private static final List<JsonObject> CASES = Vectors.cases(Vectors.load("negative.json"), "cases", 34);

    /** What each op checks, and that it refuses for the reason the op names. */
    private static boolean accepts(JsonObject c) {
        String op = str(c, "op");
        return switch (op) {
            case "key-unwrap" ->
                opens(() -> AvpCrypto.unwrap(
                        b64(c, "recipientPrivateKeyB64"),
                        new WrappedKey(
                                AvpCrypto.SCHEME_ID,
                                b64(c, "ephemeralPublicKeyB64"),
                                b64(c, "ivB64"),
                                b64(c, "ciphertextB64")),
                        WrapLabel.DATA_KEY));
            case "wrap-unwrap" ->
                opens(() -> AvpCrypto.unwrap(
                        hex(c, "recipientPrivateKeyHex"),
                        Manifest.wrappedKeyFromJson(c.get("wrap")),
                        label(str(c, "info"))));
            case "payload-decrypt" -> {
                JsonObject aad = obj(c, "aad");
                yield opens(() -> AvpCrypto.aesGcmOpen(
                        hex(c, "dataKeyHex"),
                        b64(c, "ivB64"),
                        b64(c, "ciphertextB64"),
                        Commits.aadV2(
                                str(aad, "repoId"),
                                aad.get("keyEpoch").getAsLong(),
                                b64(aad, "author"),
                                Manifest.ids(aad, "parents"))));
            }
            case "ed25519-verify" ->
                Ed25519Strict.verify(hex(c, "publicKeyHex"), hex(c, "messageHex"), hex(c, "signatureHex"));
            case "manifest-verify" -> {
                SignedManifest m = Manifest.signedFromJson(c.get("signedManifest"));
                boolean ok = Manifest.verify(m);
                // The client rule that applies it: SPEC 6.1 rule 2, before the chain link.
                ManifestRules.Verdict v = ManifestRules.check(m, null);
                assertEquals(ok, v != ManifestRules.Verdict.BAD_SIGNATURE, str(c, "name") + " rule 2");
                yield ok;
            }
            case "manifest-link" -> {
                SignedManifest prev = Manifest.signedFromJson(c.get("prev"));
                SignedManifest next = Manifest.signedFromJson(c.get("next"));
                assertTrue(Manifest.verify(next), str(c, "name") + " next is validly signed");
                boolean links = Manifest.linksTo(next, prev);
                ManifestRules.Verdict v = ManifestRules.check(next, prev);
                assertEquals(links ? ManifestRules.Verdict.OK : ManifestRules.Verdict.NOT_LINKED, v, str(c, "name"));
                yield links;
            }
            case "commit-verify" -> Commits.verify(Commits.fromJson(c.get("commit")));
            case "acceptance-verify" ->
                Tokens.verifyAcceptance(Tokens.acceptanceFromJson(obj(c, "acceptance")), b64(c, "verifyHostKey"));
            case "leave-verify" -> Tokens.verifyLeave(Tokens.leaveFromJson(obj(c, "leave")));
            case "challenge-verify" ->
                Challenge.verify(b64(c, "hostKey"), b64(c, "ed25519PublicKey"), b64(c, "nonce"), b64(c, "signature"));
            default -> throw new AssertionError("an op this test does not know: " + op);
        };
    }

    private static WrapLabel label(String info) {
        for (WrapLabel l : WrapLabel.values()) {
            if (l.label().equals(info)) {
                return l;
            }
        }
        throw new AssertionError("an unknown wrap label");
    }

    /** True if it opens; false if it fails to authenticate, which must be a CRYPTO failure. */
    private static boolean opens(java.util.function.Supplier<byte[]> open) {
        try {
            open.get();
            return true;
        } catch (AltsException e) {
            assertEquals(Kind.CRYPTO, e.kind(), "an authentication failure is CRYPTO");
            return false;
        }
    }

    private static JsonObject restored(JsonObject c) {
        JsonObject out = c.deepCopy();
        for (Map.Entry<String, JsonElement> e : obj(c, "base").entrySet()) {
            out.add(e.getKey(), e.getValue().deepCopy());
        }
        return out;
    }

    @Test
    void everyCaseIsRejectedAndItsBaseAccepted() {
        Map<String, Integer> perOp = new TreeMap<>();
        int restoredCount = 0;
        for (JsonObject c : CASES) {
            String name = str(c, "name");
            assertEquals("reject", str(c, "expect"), name);
            assertFalse(accepts(c), name);
            perOp.merge(str(c, "op"), 1, Integer::sum);
            if (c.has("base")) {
                assertTrue(accepts(restored(c)), name + " with base restored");
                restoredCount++;
            }
        }
        assertEquals(
                Map.of(
                        "acceptance-verify", 2,
                        "challenge-verify", 3,
                        "commit-verify", 5,
                        "ed25519-verify", 9,
                        "key-unwrap", 5,
                        "leave-verify", 1,
                        "manifest-link", 1,
                        "manifest-verify", 2,
                        "payload-decrypt", 5,
                        "wrap-unwrap", 1),
                perOp);
        assertEquals(34 - 5 - 9, restoredCount, "every 0.5 case carries a base");
    }

    @Test
    void aChallengeSignatureIsNoCommitSignatureAndTheReverse() {
        Commit single = Commits.fromJson(
                Vectors.cases(Vectors.load("commit.json"), "cases", 3).get(1).get("commit"));
        byte[] alice = single.author();
        byte[] hostA = b64(Vectors.seedOf("a"), "hostKey");

        JsonObject asCommitSig = byName("challenge/signature-presented-as-commit-signature");
        byte[] sig29 = Commits.fromJson(asCommitSig.get("commit")).authorSignature();
        assertTrue(
                Challenge.verify(hostA, alice, single.commitId(), sig29),
                "it is a real challenge signature whose nonce is the commit id");

        JsonObject wholeMessage = byName("challenge/commit-sig-message-as-nonce");
        byte[] sig30 = Commits.fromJson(wholeMessage.get("commit")).authorSignature();
        byte[] commitSigMessage = Commits.sigMessage(single.commitId());
        assertEquals(54, commitSigMessage.length);
        assertTrue(
                Challenge.verify(hostA, alice, commitSigMessage, sig30),
                "it is a real challenge signature whose nonce is the whole commit-sig message");

        JsonObject asChallenge = byName("challenge/commit-signature-presented-as-challenge");
        assertArrayEquals(single.authorSignature(), b64(asChallenge, "signature"));
        assertArrayEquals(single.commitId(), b64(asChallenge, "nonce"));
        assertTrue(Commits.verify(single), "it is the real author signature");

        JsonObject otherHost = byName("challenge/made-for-other-host-key");
        assertTrue(Challenge.verify(
                b64(Vectors.seedOf("b"), "hostKey"),
                b64(otherHost, "ed25519PublicKey"),
                b64(otherHost, "nonce"),
                b64(otherHost, "signature")));

        JsonObject raw = byName("challenge/signature-over-raw-nonce");
        assertTrue(Ed25519Strict.verify(b64(raw, "ed25519PublicKey"), b64(raw, "nonce"), b64(raw, "signature")));
    }

    @Test
    void aMalformedCommitOrManifestNeverThrowsFromAVerifier() {
        Commit single = Commits.fromJson(
                Vectors.cases(Vectors.load("commit.json"), "cases", 3).get(1).get("commit"));
        Commit repeatedParent = new Commit(
                single.repoId(),
                single.commitId(),
                List.of(single.parents().get(0), single.parents().get(0)),
                single.manifestSeq(),
                single.manifestHash(),
                single.keyEpoch(),
                single.author(),
                single.iv(),
                single.ciphertext(),
                single.authorSignature());
        assertFalse(Commits.verify(repeatedParent));
        assertThrows(AltsException.class, () -> Commits.headerBytes(repeatedParent));
    }

    private static JsonObject byName(String name) {
        return CASES.stream()
                .filter(c -> str(c, "name").equals(name))
                .findFirst()
                .orElseThrow();
    }
}

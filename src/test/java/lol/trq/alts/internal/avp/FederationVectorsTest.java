package lol.trq.alts.internal.avp;

import static lol.trq.alts.internal.avp.Vectors.b64;
import static lol.trq.alts.internal.avp.Vectors.hex;
import static lol.trq.alts.internal.avp.Vectors.obj;
import static lol.trq.alts.internal.avp.Vectors.seedOf;
import static lol.trq.alts.internal.avp.Vectors.str;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.internal.avp.AvpCrypto.WrapLabel;
import lol.trq.alts.internal.avp.Tokens.Acceptance;
import lol.trq.alts.internal.avp.Tokens.InviteToken;
import lol.trq.alts.internal.avp.Tokens.LeaveRequest;
import lol.trq.alts.internal.avp.Tokens.LinkGrant;
import org.junit.jupiter.api.Test;

/**
 * {@code federation.json} (SPEC 3.3, 11): every token decoded, re-encoded byte for byte and accepted in
 * any field order; the acceptance and leave signatures over their CE messages; the link confirmation
 * codes and the link grant; the member and owner fingerprints; the {@code avp://} locators; and the
 * challenge transcripts with their signatures, which do not verify for another host key or over the raw
 * nonce.
 */
class FederationVectorsTest {

    private static final JsonObject ROOT = Vectors.load("federation.json");

    private static final Map<String, Function<JsonObject, JsonObject>> TYPED = Map.of(
            "InviteToken", o -> Tokens.toJson(Tokens.inviteFromJson(o)),
            "RepoLocator", o -> Tokens.toJson(Tokens.locatorFromJson(o)),
            "LinkRequest", o -> Tokens.toJson(Tokens.linkRequestFromJson(o)),
            "LinkGrant", o -> Tokens.toJson(Tokens.linkGrantFromJson(o)));

    @Test
    void everyTokenDecodesAndReencodesByteForByte() {
        for (JsonObject t : Vectors.cases(ROOT, "tokens", 5)) {
            String name = str(t, "name");
            Function<JsonObject, JsonObject> typed = TYPED.get(str(t, "schema"));
            JsonObject decoded = Tokens.decode(str(t, "base64url"));
            assertEquals(normal(t.get("decoded")), decoded, name + " decode oracle");

            JsonObject canonical = typed.apply(decoded);
            assertEquals(str(t, "canonicalJson"), new String(AvpJson.write(canonical), StandardCharsets.UTF_8), name);
            assertEquals(str(t, "base64url"), Tokens.encode(canonical), name);

            JsonObject reordered = reversedFields(decoded);
            String spaced = new String(AvpJson.write(reordered), StandardCharsets.UTF_8).replace(",", " ,\n ");
            JsonObject fromReordered = Tokens.decode(AvpBytes.base64Url(spaced.getBytes(StandardCharsets.UTF_8)));
            assertEquals(str(t, "base64url"), Tokens.encode(typed.apply(fromReordered)), name + " any order");
        }
    }

    @Test
    void aTokenWhoseVIsNotTheIntegerTwoOrWhoseTextIsPaddedIsRefused() {
        for (JsonObject t : Vectors.cases(ROOT, "tokens", 5)) {
            String name = str(t, "name");
            Function<JsonObject, JsonObject> typed = TYPED.get(str(t, "schema"));
            JsonObject decoded = Tokens.decode(str(t, "base64url"));
            for (String v : new String[] {"1", "3", "\"2\"", "2.0", "null"}) {
                JsonObject bad = decoded.deepCopy();
                bad.add("v", AvpJson.parse(v.getBytes(StandardCharsets.UTF_8)));
                String token = AvpBytes.base64Url(AvpJson.write(bad));
                assertEquals(
                        Kind.PROTOCOL,
                        assertThrows(AltsException.class, () -> typed.apply(Tokens.decode(token)))
                                .kind(),
                        name + " v=" + v);
            }
            JsonObject noV = decoded.deepCopy();
            noV.remove("v");
            String token = AvpBytes.base64Url(AvpJson.write(noV));
            assertThrows(AltsException.class, () -> typed.apply(Tokens.decode(token)), name + " without v");

            String text = str(t, "base64url");
            if (text.length() % 4 != 0) {
                String padded = text + "=".repeat(4 - text.length() % 4);
                assertEquals(
                        Kind.PROTOCOL,
                        assertThrows(AltsException.class, () -> Tokens.decode(padded))
                                .kind(),
                        name + " padded");
            }
            assertThrows(AltsException.class, () -> Tokens.decode("+" + text.substring(1)), name + " base64 alphabet");
        }
    }

    /**
     * SPEC 11.2: a repo locator names a 22-character base64url repository id and a 16-hex-digit owner
     * fingerprint; a pasted token or locator is trimmed of surrounding whitespace.
     */
    @Test
    void aRepoLocatorWithAMalformedIdOrFingerprintIsRefused() {
        JsonObject t = Vectors.cases(ROOT, "tokens", 5).get(1);
        assertEquals("RepoLocator", str(t, "schema"));
        JsonObject decoded = Tokens.decode(" \t" + str(t, "base64url") + "\r\n");
        assertEquals(str(t, "base64url"), Tokens.encode(Tokens.toJson(Tokens.locatorFromJson(decoded))));
        String[][] bad = {
            {"repoId", "RBhoUI0PUSR7tD5HpFC9l"},
            {"repoId", "RBhoUI0PUSR7tD5HpFC9lA="},
            {"repoId", "RBhoUI0PUSR7tD5HpFC9+A"},
            {"ownerFingerprint", "267B69E617FA4594"},
            {"ownerFingerprint", "267b69e617fa459"},
            {"ownerFingerprint", "267b-69e6-17fa-4594"}
        };
        for (String[] b : bad) {
            JsonObject o = decoded.deepCopy();
            o.addProperty(b[0], b[1]);
            AltsException e = assertThrows(AltsException.class, () -> Tokens.locatorFromJson(o), b[1]);
            assertEquals(Kind.PROTOCOL, e.kind(), b[1]);
        }
        JsonObject u = Vectors.cases(ROOT, "uris", 2).get(0);
        assertEquals(
                str(u, "repoId"), Tokens.parseUri("  " + str(u, "uri") + "\n").repoId());
    }

    @Test
    void theInviteAcceptanceIsSignedByTheJoinersHomeHostAndVerifiedAsTheOwnerMust() {
        JsonObject t = Vectors.cases(ROOT, "tokens", 5).get(0);
        assertEquals("InviteToken", str(t, "schema"));
        InviteToken invite = Tokens.inviteFromJson(Tokens.decode(str(t, "base64url")));
        Acceptance a = invite.acceptance();
        assertEquals(str(t, "acceptanceMessageHex"), Vectors.hex(Tokens.acceptanceMessage(a)));
        assertTrue(Tokens.verifyAcceptance(a, a.hostKey()));
        assertArrayEquals(b64(seedOf("b"), "hostKey"), a.hostKey());
        Acceptance resigned =
                Tokens.signAcceptance(a.repoId(), a.memberKey(), a.expiresAt(), hex(seedOf("b"), "ed25519SeedHex"));
        assertArrayEquals(a.signature(), resigned.signature());

        String repoId = a.repoId();
        assertTrue(Tokens.verifyInvite(invite, repoId, a.expiresAt() - 1));
        assertFalse(Tokens.verifyInvite(invite, repoId, a.expiresAt()), "expired at expiresAt");
        assertFalse(Tokens.verifyInvite(invite, "AAAAAAAAAAAAAAAAAAAAAA", a.expiresAt() - 1), "another repository");
        InviteToken otherHome = new InviteToken(
                invite.ed25519PublicKey(),
                invite.x25519PublicKey(),
                b64(seedOf("a"), "hostKey"),
                invite.homeHostLocator(),
                a);
        assertFalse(Tokens.verifyInvite(otherHome, repoId, a.expiresAt() - 1), "home host not the acceptor");
        InviteToken otherMember = new InviteToken(
                b64(seedOf("carol"), "ed25519PublicKey"),
                invite.x25519PublicKey(),
                invite.homeHostKey(),
                invite.homeHostLocator(),
                a);
        assertFalse(Tokens.verifyInvite(otherMember, repoId, a.expiresAt() - 1), "acceptance for another key");

        // SPEC 8.2: the acceptance signature itself, with every other condition still holding.
        byte[] flipped = a.signature();
        flipped[0] ^= 0x01;
        InviteToken badSignature = new InviteToken(
                invite.ed25519PublicKey(),
                invite.x25519PublicKey(),
                invite.homeHostKey(),
                invite.homeHostLocator(),
                new Acceptance(a.repoId(), a.memberKey(), a.hostKey(), a.expiresAt(), flipped));
        assertFalse(Tokens.verifyInvite(badSignature, repoId, a.expiresAt() - 1), "a flipped signature byte");
        long later = a.expiresAt() + 60_000;
        InviteToken extended = new InviteToken(
                invite.ed25519PublicKey(),
                invite.x25519PublicKey(),
                invite.homeHostKey(),
                invite.homeHostLocator(),
                new Acceptance(a.repoId(), a.memberKey(), a.hostKey(), later, a.signature()));
        assertFalse(Tokens.verifyInvite(extended, repoId, a.expiresAt() - 1), "expiresAt altered after signing");
    }

    @Test
    void everyLeaveRequestIsSignedOverItsCeMessage() {
        for (JsonObject l : Vectors.cases(ROOT, "leaves", 2)) {
            String name = str(l, "name");
            LeaveRequest leave = Tokens.leaveFromJson(obj(l, "decoded"));
            assertEquals(str(l, "signatureMessageHex"), Vectors.hex(Tokens.leaveMessage(leave)), name);
            assertTrue(Tokens.verifyLeave(leave), name);
            String label = name.substring(0, name.indexOf('-'));
            LeaveRequest resigned = Tokens.signLeave(leave.repoId(), leave.at(), hex(seedOf(label), "ed25519SeedHex"));
            assertArrayEquals(leave.signature(), resigned.signature(), name);
            assertEquals(normal(obj(l, "decoded")), Tokens.toJson(leave), name);
        }
    }

    /** SPEC 8.4, in order: signature, repository, a member of the tip, not the owner. */
    @Test
    void theOwnerChecksALeaveRequestBeforeActingOnIt() {
        List<JsonObject> states = Vectors.cases(Vectors.load("manifest.json"), "cases", 4);
        Manifest.ManifestState members =
                Manifest.signedFromJson(states.get(1).get("signedManifest")).state();
        Manifest.ManifestState bobRemoved =
                Manifest.signedFromJson(states.get(2).get("signedManifest")).state();
        List<JsonObject> leaves = Vectors.cases(ROOT, "leaves", 2);
        LeaveRequest alice = Tokens.leaveFromJson(obj(leaves.get(0), "decoded"));
        LeaveRequest bob = Tokens.leaveFromJson(obj(leaves.get(1), "decoded"));

        assertEquals(Tokens.LeaveVerdict.OK, Tokens.leaveVerdict(alice, members));
        assertEquals(Tokens.LeaveVerdict.OK, Tokens.leaveVerdict(bob, members));
        assertEquals(Tokens.LeaveVerdict.NOT_A_MEMBER, Tokens.leaveVerdict(bob, bobRemoved));

        byte[] flipped = alice.signature();
        flipped[5] ^= 0x01;
        LeaveRequest forged = new LeaveRequest(alice.repoId(), alice.memberKey(), alice.at(), flipped);
        assertEquals(Tokens.LeaveVerdict.BAD_SIGNATURE, Tokens.leaveVerdict(forged, members));

        LeaveRequest elsewhere =
                Tokens.signLeave("AAAAAAAAAAAAAAAAAAAAAA", alice.at(), hex(seedOf("alice"), "ed25519SeedHex"));
        assertEquals(Tokens.LeaveVerdict.WRONG_REPOSITORY, Tokens.leaveVerdict(elsewhere, members));

        LeaveRequest owner = Tokens.signLeave(alice.repoId(), alice.at(), hex(seedOf("owner"), "ed25519SeedHex"));
        assertEquals(Tokens.LeaveVerdict.OWNER, Tokens.leaveVerdict(owner, members));
        assertEquals("forbidden", Tokens.LeaveVerdict.OWNER.code().orElseThrow());
        assertEquals("bad_request", Tokens.LeaveVerdict.WRONG_REPOSITORY.code().orElseThrow());
    }

    @Test
    void theLinkCodesAndTheLinkGrantReproduce() {
        for (JsonObject c : Vectors.cases(ROOT, "linkCodes", 2)) {
            assertEquals(str(c, "code"), Tokens.linkConfirmationCode(b64(c, "ephemeralPublicKey")), str(c, "name"));
        }
        JsonObject grantCase = Vectors.cases(ROOT, "tokens", 5).get(4);
        JsonObject requestCase = Vectors.cases(ROOT, "tokens", 5).get(3);
        assertEquals("LinkGrant", str(grantCase, "schema"));
        JsonObject checker = obj(grantCase, "checker");
        byte[] linkPrivate = hex(checker, "linkEphemeralPrivateHex");
        byte[] linkPublic = Tokens.linkRequestFromJson(Tokens.decode(str(requestCase, "base64url")))
                .ephemeralPublicKey();
        assertArrayEquals(linkPublic, AvpCrypto.x25519Public(linkPrivate));

        LinkGrant grant = Tokens.linkGrantFromJson(Tokens.decode(str(grantCase, "base64url")));
        assertArrayEquals(hex(checker, "entropyHex"), Tokens.openLinkGrant(grant, linkPrivate));
        WrappedKey rewrapped = AvpCrypto.wrapWith(
                linkPublic,
                hex(checker, "entropyHex"),
                WrapLabel.OWNER_LINK,
                ManifestVectorsTest.sha256("avp/vectors/link-wrap-ephemeral"),
                Arrays.copyOf(ManifestVectorsTest.sha256("avp/vectors/link-wrap-iv"), 12));
        assertEquals(str(grantCase, "base64url"), Tokens.encode(Tokens.toJson(new LinkGrant(rewrapped))));

        LinkGrant fresh = Tokens.sealLinkGrant(hex(checker, "entropyHex"), linkPublic);
        assertArrayEquals(hex(checker, "entropyHex"), Tokens.openLinkGrant(fresh, linkPrivate));
        assertEquals(
                Kind.CRYPTO,
                assertThrows(AltsException.class, () -> AvpCrypto.unwrap(linkPrivate, grant.wrap(), WrapLabel.DATA_KEY))
                        .kind(),
                "the grant does not open under the data key label");
    }

    @Test
    void theFingerprintsReproduce() {
        JsonObject f = obj(ROOT, "fingerprints");
        for (JsonObject m : Vectors.cases(f, "members", 3)) {
            assertEquals(
                    str(m, "fingerprint"),
                    Tokens.memberFingerprint(b64(m, "ed25519PublicKey"), b64(m, "x25519PublicKey")),
                    str(m, "label"));
        }
        JsonObject owner = obj(f, "owner");
        assertEquals(str(owner, "ownerFingerprint"), Tokens.ownerFingerprint(b64(owner, "ownerKey")));
        JsonObject locator = Tokens.decode(str(Vectors.cases(ROOT, "tokens", 5).get(1), "base64url"));
        assertEquals(str(owner, "ownerFingerprint"), str(locator, "ownerFingerprint"));
    }

    @Test
    void theAvpLocatorsParseAndFormat() {
        for (JsonObject u : Vectors.cases(ROOT, "uris", 2)) {
            Tokens.AvpUri parsed = Tokens.parseUri(str(u, "uri"));
            assertEquals(str(u, "host"), parsed.hostLocator(), str(u, "name"));
            assertEquals(str(u, "repoId"), parsed.repoId(), str(u, "name"));
            assertEquals(str(u, "uri"), parsed.toString(), str(u, "name"));
        }
        for (String bad : new String[] {
            "https://a.vault.example/RBhoUI0PUSR7tD5HpFC9lA",
            "avp:///RBhoUI0PUSR7tD5HpFC9lA",
            "avp://a.vault.example/RBhoUI0PUSR7tD5HpFC9l",
            "avp://a.vault.example/RBhoUI0PUSR7tD5HpFC9lA=",
            "avp://a.vault.example/RBhoUI0PUSR7tD5HpFC9+A"
        }) {
            assertThrows(AltsException.class, () -> Tokens.parseUri(bad), bad);
        }
    }

    @Test
    void everyChallengeTranscriptAndSignatureReproduces() {
        List<byte[]> nonces = List.of(
                ManifestVectorsTest.sha256("avp/vectors/challenge-nonce/0"), sha512("avp/vectors/challenge-nonce/1"));
        List<JsonObject> cases = Vectors.cases(ROOT, "challenges", 2);
        for (int i = 0; i < cases.size(); i++) {
            JsonObject c = cases.get(i);
            String name = str(c, "name");
            byte[] hostKey = b64(c, "hostKey");
            byte[] key = b64(c, "ed25519PublicKey");
            byte[] nonce = b64(c, "nonce");
            byte[] signature = b64(c, "signature");
            assertArrayEquals(nonces.get(i), nonce, name + " documented nonce");
            assertArrayEquals(b64(seedOf(str(c, "host").substring(0, 1)), "hostKey"), hostKey, name);
            assertEquals(str(c, "messageHex"), Vectors.hex(Challenge.message(hostKey, key, nonce)), name);

            byte[] seed = hex(seedOf(str(c, "signer")), "ed25519SeedHex");
            assertArrayEquals(signature, Challenge.sign(hostKey, seed, nonce), name);
            assertTrue(Challenge.verify(hostKey, key, nonce, signature), name);

            String other = str(c, "host").equals("a.vault.example") ? "b" : "a";
            assertFalse(Challenge.verify(b64(seedOf(other), "hostKey"), key, nonce, signature), name + " other host");
            assertFalse(Ed25519Strict.verify(key, nonce, signature), name + " is not a raw-nonce signature");
            for (byte[] otherKey : new byte[][] {new byte[32], AvpCrypto.randomBytes(32)}) {
                byte[] forOther = Challenge.sign(otherKey, seed, nonce);
                assertFalse(Challenge.verify(hostKey, key, nonce, forOther), name + " made for another host key");
            }
            byte[] rawNonce = Ed25519Strict.sign(seed, nonce);
            assertFalse(Challenge.verify(hostKey, key, nonce, rawNonce), name + " raw-nonce signature refused");
        }
    }

    @Test
    void aClientRefusesToSignANonceShorterThanTheSpecAllows() {
        JsonObject c = Vectors.cases(ROOT, "challenges", 2).get(0);
        byte[] seed = hex(seedOf("alice"), "ed25519SeedHex");
        assertEquals(
                Kind.PROTOCOL,
                assertThrows(AltsException.class, () -> Challenge.sign(b64(c, "hostKey"), seed, new byte[31]))
                        .kind());
    }

    private static JsonObject normal(JsonElement json) {
        return AvpJson.object(AvpJson.parse(AvpJson.write(json)), "case");
    }

    private static JsonObject reversedFields(JsonObject o) {
        List<String> keys = new ArrayList<>(o.keySet());
        Collections.reverse(keys);
        JsonObject out = new JsonObject();
        for (String k : keys) {
            JsonElement v = o.get(k);
            out.add(k, v.isJsonObject() ? reversedFields(v.getAsJsonObject()) : v.deepCopy());
        }
        return out;
    }

    private static byte[] sha512(String s) {
        try {
            return java.security.MessageDigest.getInstance("SHA-512").digest(s.getBytes(StandardCharsets.UTF_8));
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}

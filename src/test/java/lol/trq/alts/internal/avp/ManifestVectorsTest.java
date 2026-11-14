package lol.trq.alts.internal.avp;

import static lol.trq.alts.internal.avp.Vectors.b64;
import static lol.trq.alts.internal.avp.Vectors.hex;
import static lol.trq.alts.internal.avp.Vectors.obj;
import static lol.trq.alts.internal.avp.Vectors.str;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import lol.trq.alts.internal.avp.AvpCrypto.WrapLabel;
import lol.trq.alts.internal.avp.Manifest.ManifestState;
import lol.trq.alts.internal.avp.Manifest.MemberEntry;
import lol.trq.alts.internal.avp.Manifest.Removal;
import lol.trq.alts.internal.avp.Manifest.SignedManifest;
import org.junit.jupiter.api.Test;

/**
 * {@code manifest.json} (SPEC 4.1, 4.2): the four-state owner-signed chain. Each case's CE bytes, owner
 * signature, {@code manifestHash} and (at seq 1) repository id are reproduced from the seeds, every
 * wrapped data key is reproduced from its documented derivation, the chain passes the client's SPEC 6.1
 * rules, and the encoding does not depend on the order of the wire lists (stored descending on purpose).
 */
class ManifestVectorsTest {

    private static final JsonObject ROOT = Vectors.load("manifest.json");
    private static final JsonObject SEEDS = ROOT.getAsJsonObject("seeds");

    private static List<JsonObject> cases() {
        return Vectors.cases(ROOT, "cases", 4);
    }

    @Test
    void everyStateReproducesItsBytesSignatureHashAndRepoId() {
        byte[] ownerSeed = hex(obj(SEEDS, "owner"), "ed25519SeedHex");
        for (JsonObject c : cases()) {
            String name = str(c, "name");
            JsonObject expected = obj(c, "expected");
            SignedManifest m = Manifest.signedFromJson(c.get("signedManifest"));

            assertEquals(str(expected, "stateHex"), Vectors.hex(Manifest.encode(m.state())), name);
            SignedManifest resigned = Manifest.sign(m.state(), ownerSeed);
            assertArrayEquals(m.ownerSignature(), resigned.ownerSignature(), name + " signature");
            assertTrue(Manifest.verify(m), name);
            assertEquals(str(expected, "manifestHashHex"), Vectors.hex(Manifest.hash(m)), name);
            if (expected.has("repoId")) {
                assertEquals(1, m.state().manifestSeq());
                assertEquals(
                        str(expected, "repoId"),
                        Manifest.deriveRepoId(m.state().ownerKey(), m.state().genesisNonce()));
                assertEquals(22, str(expected, "repoId").length());
            }
            assertEquals(
                    str(expected, "stateHex"),
                    Vectors.hex(Manifest.encode(roundTrip(m).state())),
                    name);
        }
    }

    @Test
    void theEncodingDoesNotDependOnTheWireListOrder() {
        for (JsonObject c : cases()) {
            ManifestState s = Manifest.signedFromJson(c.get("signedManifest")).state();
            List<Removal> removals = new ArrayList<>();
            for (Removal r : s.removals()) {
                removals.add(new Removal(r.memberKey(), r.removedAtSeq(), reversed(r.frontier())));
            }
            ManifestState shuffled = new ManifestState(
                    s.repoId(),
                    s.manifestSeq(),
                    s.prevManifestHash(),
                    s.ownerKey(),
                    s.genesisNonce(),
                    s.schemeId(),
                    s.keyEpoch(),
                    s.shareRefreshTokens(),
                    reversed(s.hosts()),
                    reversed(s.members()),
                    reversed(removals));
            assertEquals(str(obj(c, "expected"), "stateHex"), Vectors.hex(Manifest.encode(shuffled)), str(c, "name"));
        }
    }

    @Test
    void everyWrappedDataKeyIsTheDocumentedWrapAndOpensForItsMember() {
        Map<String, JsonObject> byKey = new HashMap<>();
        byKey.put(str(obj(SEEDS, "owner"), "ownerKey"), labelled(obj(SEEDS, "owner"), "owner"));
        for (JsonElement e : SEEDS.getAsJsonArray("members")) {
            byKey.put(str(e.getAsJsonObject(), "ed25519PublicKey"), e.getAsJsonObject());
        }
        Map<Long, byte[]> dataKeys = new HashMap<>();
        for (JsonElement e : SEEDS.getAsJsonArray("dataKeys")) {
            dataKeys.put(e.getAsJsonObject().get("keyEpoch").getAsLong(), hex(e.getAsJsonObject(), "dataKeyHex"));
        }
        int wraps = 0;
        for (JsonObject c : cases()) {
            for (MemberEntry m :
                    Manifest.signedFromJson(c.get("signedManifest")).state().members()) {
                JsonObject seed = byKey.get(AvpBytes.base64(m.ed25519PublicKey()));
                String label = str(seed, "label");
                long epoch = m.keyEpoch();
                byte[] ephemeral = sha256("avp/vectors/wrap-ephemeral/" + epoch + "/" + label);
                byte[] iv = Arrays.copyOf(sha256("avp/vectors/wrap-iv/" + epoch + "/" + label), 12);
                WrappedKey made =
                        AvpCrypto.wrapWith(m.x25519PublicKey(), dataKeys.get(epoch), WrapLabel.DATA_KEY, ephemeral, iv);
                assertEquals(made.schemeId(), m.wrappedDataKey().schemeId());
                assertArrayEquals(made.ephemeralPublicKey(), m.wrappedDataKey().ephemeralPublicKey(), label);
                assertArrayEquals(made.iv(), m.wrappedDataKey().iv(), label);
                assertArrayEquals(made.ciphertext(), m.wrappedDataKey().ciphertext(), label);
                assertArrayEquals(
                        dataKeys.get(epoch),
                        AvpCrypto.unwrap(hex(seed, "x25519PrivateHex"), m.wrappedDataKey(), WrapLabel.DATA_KEY));
                wraps++;
            }
        }
        assertEquals(1 + 4 + 3 + 3, wraps, "every member entry of the four states");
    }

    @Test
    void theChainPassesTheClientRulesInOrder() {
        SignedManifest prev = null;
        for (JsonObject c : cases()) {
            SignedManifest m = Manifest.signedFromJson(c.get("signedManifest"));
            assertEquals(ManifestRules.Verdict.OK, ManifestRules.check(m, prev), str(c, "name"));
            if (prev != null) {
                assertTrue(Manifest.linksTo(m, prev));
            }
            prev = m;
        }
    }

    @Test
    void theSeedsGiveTheKeysTheStatesName() {
        JsonObject owner = obj(SEEDS, "owner");
        OwnerKeys keys = OwnerKeys.fromEntropy(hex(owner, "entropyHex"));
        assertArrayEquals(b64(owner, "ownerKey"), keys.ownerKey());
        assertArrayEquals(b64(owner, "x25519PublicKey"), keys.x25519Public());
        for (String list : List.of("members", "hosts")) {
            for (JsonElement e : SEEDS.getAsJsonArray(list)) {
                JsonObject s = e.getAsJsonObject();
                byte[] pub = Ed25519Strict.publicKey(hex(s, "ed25519SeedHex"));
                assertArrayEquals(b64(s, list.equals("hosts") ? "hostKey" : "ed25519PublicKey"), pub);
            }
        }
    }

    private static SignedManifest roundTrip(SignedManifest m) {
        byte[] wire = AvpJson.write(Manifest.toJson(m));
        return Manifest.signedFromJson(AvpJson.parse(wire));
    }

    private static JsonObject labelled(JsonObject seed, String label) {
        JsonObject out = seed.deepCopy();
        out.addProperty("label", label);
        return out;
    }

    private static <T> List<T> reversed(List<T> items) {
        List<T> out = new ArrayList<>(items);
        java.util.Collections.reverse(out);
        return out;
    }

    static byte[] sha256(String s) {
        return AvpCrypto.sha256(s.getBytes(StandardCharsets.UTF_8));
    }
}

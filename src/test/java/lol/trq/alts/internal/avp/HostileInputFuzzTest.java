package lol.trq.alts.internal.avp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.TreeMap;
import lol.trq.alts.AltsException;
import lol.trq.alts.internal.avp.AvpCrypto.WrapLabel;
import lol.trq.alts.internal.avp.Commits.Commit;
import lol.trq.alts.internal.avp.Manifest.SignedManifest;
import org.junit.jupiter.api.Test;

/**
 * Hostile input at every entry point of the AVP constructions raises only {@link AltsException}: never an
 * unchecked JDK or Gson exception, an error, or a hang. Each round mutates a vector item (a node replaced
 * by garbage or removed, or its text truncated, bit-flipped or extended) and feeds it to the decoders and
 * checks, and calls the primitives with lengths drawn at random. The seed is fixed, so a failure
 * reproduces.
 */
class HostileInputFuzzTest {

    private final Map<String, Integer> escapes = new TreeMap<>();
    private final Random rnd = new Random(20261113L);
    private final MessageDigest inputs = sha256();
    private int calls;

    /** The digest of every input the rounds generate, pinned so a change to the generator is a visible one. */
    private static final String INPUT_DIGEST = "efb81a4c63df4cc1f9dfd1de61bf33dfb0c23aaa280f7d196ecb83552e305561";

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Bytes from the seeded source only, so every run feeds the same inputs. */
    private byte[] bytes(int n) {
        byte[] out = new byte[n];
        rnd.nextBytes(out);
        return out;
    }

    /** Records a generated input in the digest and hands it back. */
    private byte[] fed(byte[] input) {
        inputs.update(input);
        inputs.update((byte) 0);
        return input;
    }

    private interface Op {
        void run() throws Exception;
    }

    private void call(String where, Op op) {
        calls++;
        try {
            op.run();
        } catch (AltsException expected) {
            // fine
        } catch (Throwable t) {
            escapes.merge(where + " -> " + t.getClass().getName(), 1, Integer::sum);
        }
    }

    private JsonElement garbage() {
        return switch (rnd.nextInt(12)) {
            case 0 -> JsonNull.INSTANCE;
            case 1 -> new JsonPrimitive("x");
            case 2 -> new JsonPrimitive(1);
            case 3 -> new JsonPrimitive(-1);
            case 4 -> new JsonPrimitive(new BigDecimal("9223372036854775808"));
            case 5 -> new JsonPrimitive(new BigDecimal("1e400"));
            case 6 -> new JsonArray();
            case 7 -> new JsonObject();
            case 8 -> new JsonPrimitive("AAAA");
            case 9 -> new JsonPrimitive("AA==");
            case 10 -> new JsonPrimitive(true);
            default -> new JsonPrimitive(AvpBytes.base64(bytes(rnd.nextInt(70))));
        };
    }

    /** Replaces one random node of a deep copy (or removes a member). */
    private JsonElement mutate(JsonElement root) {
        JsonElement copy = root.deepCopy();
        List<Object[]> slots = new ArrayList<>();
        collect(copy, slots);
        if (slots.isEmpty()) {
            return garbage();
        }
        Object[] slot = slots.get(rnd.nextInt(slots.size()));
        if (slot[0] instanceof JsonObject o) {
            if (rnd.nextInt(4) == 0) {
                o.remove((String) slot[1]);
            } else {
                o.add((String) slot[1], garbage());
            }
        } else {
            ((JsonArray) slot[0]).set((Integer) slot[1], garbage());
        }
        return copy;
    }

    private static void collect(JsonElement e, List<Object[]> out) {
        if (e.isJsonObject()) {
            for (String k : e.getAsJsonObject().keySet()) {
                out.add(new Object[] {e.getAsJsonObject(), k});
                collect(e.getAsJsonObject().get(k), out);
            }
        } else if (e.isJsonArray()) {
            JsonArray a = e.getAsJsonArray();
            for (int i = 0; i < a.size(); i++) {
                out.add(new Object[] {a, i});
                collect(a.get(i), out);
            }
        }
    }

    private byte[] mangle(byte[] text) {
        byte[] b = text.clone();
        switch (rnd.nextInt(4)) {
            case 0 -> {
                return java.util.Arrays.copyOf(b, rnd.nextInt(b.length + 1));
            }
            case 1 -> b[rnd.nextInt(b.length)] ^= (byte) (1 << rnd.nextInt(8));
            case 2 -> b[rnd.nextInt(b.length)] = (byte) 0xff;
            default -> {
                return AvpBytes.concat(b, "  {}".getBytes(StandardCharsets.UTF_8));
            }
        }
        return b;
    }

    @Test
    void hostileInputOnlyEverRaisesAltsException() {
        JsonObject manifests = Vectors.load("manifest.json");
        JsonObject commits = Vectors.load("commit.json");
        JsonObject merge = Vectors.load("merge.json");
        JsonObject fed = Vectors.load("federation.json");
        List<JsonElement> states = new ArrayList<>();
        manifests
                .getAsJsonArray("cases")
                .forEach(c -> states.add(c.getAsJsonObject().get("signedManifest")));
        List<JsonElement> cs = new ArrayList<>();
        commits.getAsJsonArray("cases").forEach(c -> cs.add(c.getAsJsonObject().get("commit")));
        List<JsonElement> payloads = new ArrayList<>();
        merge.getAsJsonArray("cases")
                .forEach(c -> c.getAsJsonObject().getAsJsonArray("inputs").forEach(payloads::add));
        List<JsonElement> tokens = new ArrayList<>();
        fed.getAsJsonArray("tokens").forEach(t -> tokens.add(t.getAsJsonObject().get("decoded")));
        List<JsonElement> leaves = new ArrayList<>();
        fed.getAsJsonArray("leaves").forEach(t -> leaves.add(t.getAsJsonObject().get("decoded")));
        SignedManifest genesis = Manifest.signedFromJson(states.get(0));

        for (int round = 0; round < 3000; round++) {
            // Manifests
            JsonElement mj = mutate(states.get(rnd.nextInt(states.size())));
            byte[] mtext = fed(rnd.nextBoolean() ? AvpJson.write(mj) : mangle(AvpJson.write(states.get(0))));
            call("manifest", () -> {
                SignedManifest m = Manifest.signedFromJson(AvpJson.parse(mtext));
                ManifestRules.check(m, null);
                ManifestRules.check(m, genesis);
                ManifestRules.check(genesis, m);
                Manifest.verify(m);
                Manifest.linksTo(m, genesis);
                Manifest.linksTo(genesis, m);
                Manifest.hash(m);
                Manifest.toJson(m);
            });
            // Commits
            JsonElement cj = mutate(cs.get(rnd.nextInt(cs.size())));
            byte[] ctext = fed(rnd.nextBoolean() ? AvpJson.write(cj) : mangle(AvpJson.write(cs.get(0))));
            call("commit", () -> {
                Commit c = Commits.fromJson(AvpJson.parse(ctext));
                Commits.verify(c);
                Commits.shapeOk(c);
                Commits.id(c);
                Commits.open(c, fed(bytes(rnd.nextBoolean() ? 32 : rnd.nextInt(40))));
            });
            // Payloads
            JsonElement pj = mutate(payloads.get(rnd.nextInt(payloads.size())));
            byte[] ptext = fed(rnd.nextBoolean() ? AvpJson.write(pj) : mangle(AvpJson.write(payloads.get(0))));
            call("payload", () -> {
                Payload p = Payload.parse(ptext);
                Payload q = Payload.merge(List.of(p, Payload.parse(AvpJson.write(payloads.get(0)))));
                q.stripRefresh().encode();
                new Hlc(0, 0).observeAll(q);
                p.toString();
            });
            // Tokens
            JsonElement tj = mutate(tokens.get(rnd.nextInt(tokens.size())));
            byte[] ttext = fed(rnd.nextBoolean() ? AvpJson.write(tj) : mangle(AvpJson.write(tokens.get(0))));
            String tok =
                    rnd.nextInt(5) == 0 ? new String(ttext, StandardCharsets.ISO_8859_1) : AvpBytes.base64Url(ttext);
            call("token", () -> {
                JsonObject o = Tokens.decode(tok);
                try {
                    Tokens.InviteToken t = Tokens.inviteFromJson(o);
                    Tokens.verifyInvite(t, "RBhoUI0PUSR7tD5HpFC9lA", 0);
                } catch (AltsException e) {
                    // next
                }
                try {
                    Tokens.locatorFromJson(o);
                } catch (AltsException e) {
                    // next
                }
                try {
                    Tokens.linkRequestFromJson(o);
                } catch (AltsException e) {
                    // next
                }
                Tokens.LinkGrant g = Tokens.linkGrantFromJson(o);
                Tokens.openLinkGrant(g, fed(bytes(32)));
            });
            JsonElement lj = mutate(leaves.get(rnd.nextInt(leaves.size())));
            fed(AvpJson.write(lj));
            call("leave", () -> {
                Tokens.LeaveRequest l = Tokens.leaveFromJson(AvpJson.object(AvpJson.parse(AvpJson.write(lj)), "l"));
                Tokens.verifyLeave(l);
                Tokens.leaveVerdict(l, genesis.state());
            });
            // Raw primitives with wrong lengths
            byte[] a = fed(bytes(rnd.nextInt(40)));
            byte[] b = fed(bytes(rnd.nextInt(70)));
            byte[] n = fed(bytes(rnd.nextInt(80)));
            call("ed25519.verify", () -> Ed25519Strict.verify(a, n, b));
            call("challenge.verify", () -> Challenge.verify(a, a, n, b));
            call("challenge.sign", () -> Challenge.sign(a, a, n));
            call("ed25519.sign", () -> Ed25519Strict.sign(a, n));
            call("ed25519.publicKey", () -> Ed25519Strict.publicKey(a));
            call("x25519", () -> AvpCrypto.x25519(a, rnd.nextBoolean() ? new byte[32] : a));
            call(
                    "unwrap",
                    () -> AvpCrypto.unwrap(
                            a,
                            new WrappedKey(rnd.nextBoolean() ? AvpCrypto.SCHEME_ID : "x", a, b, n),
                            rnd.nextBoolean() ? WrapLabel.DATA_KEY : WrapLabel.OWNER_LINK));
            call("gcm.open", () -> AvpCrypto.aesGcmOpen(a, b, n, a));
            call("hkdf", () -> AvpCrypto.hkdf(a, b, n, rnd.nextInt(20000) - 10));
            String s = new String(n, StandardCharsets.ISO_8859_1);
            call("fromBase64", () -> AvpBytes.fromBase64(s, "x"));
            call("fromBase64Url", () -> AvpBytes.fromBase64Url(s, "x"));
            call("fromBase64Len", () -> AvpBytes.fromBase64(AvpBytes.base64(a), 32, "x"));
            call("parseUri", () -> Tokens.parseUri("avp://" + s));
            call("parseUri2", () -> Tokens.parseUri(s));
            call("bip39", () -> Bip39.mnemonicToEntropy(s));
            call("bip39.seed", () -> Bip39.mnemonicToSeed(s, s));
            call("ownerKeys.fromSeed", () -> OwnerKeys.fromSeed(b));
            call("bip39.entropy", () -> Bip39.entropyToMnemonic(a));
            call("sealLinkGrant", () -> Tokens.sealLinkGrant(a, b));
            call("json", () -> AvpJson.parse(n));
        }
        // Targeted
        call("deep", () -> AvpJson.parse("[".repeat(100_000).getBytes(StandardCharsets.UTF_8)));
        call(
                "hugeint",
                () -> AvpJson.int64(
                        AvpJson.object(
                                AvpJson.parse(
                                        ("{\"v\":1" + "0".repeat(200_000) + "}").getBytes(StandardCharsets.UTF_8)),
                                "o"),
                        "v"));
        call("hugeexp", () -> Payload.parse("{\"v\":2e999999999,\"accounts\":{}}".getBytes(StandardCharsets.UTF_8)));
        call(
                "int64overflow",
                () -> Payload.parse(
                        "{\"v\":2,\"accounts\":{\"u\":{\"fields\":{\"f\":{\"value\":1,\"at\":9223372036854775808,\"n\":0,\"by\":\"x\"}}}}}"
                                .getBytes(StandardCharsets.UTF_8)));
        call("bom", () -> AvpJson.parse("﻿{}".getBytes(StandardCharsets.UTF_8)));
        call("hlc.max", () -> {
            Hlc h = new Hlc(Long.MAX_VALUE, Long.MAX_VALUE);
            h.tick(0, "x");
            h.tick(0, "x");
        });

        assertEquals(75_006, calls, "every round ran, and the same number of calls each run");
        assertEquals(INPUT_DIGEST, HexFormat.of().formatHex(inputs.digest()), "the same inputs each run");
        assertTrue(escapes.isEmpty(), escapes.toString());
    }
}

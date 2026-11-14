package lol.trq.alts.internal.avp;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

/**
 * Manifest states and their owner signature (AVP SPEC 4.2): the records, the canonical bytes {@code S},
 * {@code ownerSignature}, {@code manifestHash}, the repository id, and the HTTP/JSON wire form.
 *
 * <p>The records copy every array and list they are given; their accessors return the record's own
 * arrays, which callers must not modify. Records compare arrays by identity, so compare two states by
 * {@link #hash(SignedManifest)} or by their encoding. Nothing in a manifest is secret: a wrapped data key
 * is ciphertext.
 *
 * <p>Ported from the Alt Vault Protocol reference implementation (MIT).
 *
 * @author trq
 * @since 1.0.0
 */
public final class Manifest {

    private Manifest() {}

    /**
     * A host that replicates the repository.
     *
     * @param hostKey the 32-byte Ed25519 host key, by which the host is matched
     * @param locator the dialing hint, {@code host} or {@code host:port}
     */
    public record HostRef(byte[] hostKey, String locator) {
        /** Copies the key. */
        public HostRef {
            hostKey = hostKey.clone();
        }
    }

    /**
     * A member as the owner signed it.
     *
     * @param ed25519PublicKey the member's 32-byte Ed25519 key, its member id
     * @param x25519PublicKey the member's 32-byte X25519 key
     * @param wrappedDataKey the data key of {@code keyEpoch} wrapped to {@code x25519PublicKey}
     * @param keyEpoch the epoch of the wrapped data key
     * @param homeHostKey the 32-byte host key of the member's home host
     */
    public record MemberEntry(
            byte[] ed25519PublicKey,
            byte[] x25519PublicKey,
            WrappedKey wrappedDataKey,
            long keyEpoch,
            byte[] homeHostKey) {
        /** Copies the keys. */
        public MemberEntry {
            ed25519PublicKey = ed25519PublicKey.clone();
            x25519PublicKey = x25519PublicKey.clone();
            homeHostKey = homeHostKey.clone();
        }
    }

    /**
     * A removed member and its signed removal cutoff (SPEC 7.3).
     *
     * @param memberKey the removed member's 32-byte Ed25519 key
     * @param removedAtSeq the {@code manifestSeq} of the state that removed it
     * @param frontier the 32-byte commit ids of the cutoff
     */
    public record Removal(byte[] memberKey, long removedAtSeq, List<byte[]> frontier) {
        /** Copies the key and the ids. */
        public Removal {
            memberKey = memberKey.clone();
            frontier = copyIds(frontier);
        }
    }

    /**
     * One manifest state.
     *
     * @param repoId the repository id
     * @param manifestSeq {@code 1} at genesis, {@code +1} per state
     * @param prevManifestHash the previous state's {@code manifestHash}; empty at seq 1
     * @param ownerKey the 32-byte owner Ed25519 key
     * @param genesisNonce 16 random bytes at seq 1; empty after
     * @param schemeId the wrap scheme id
     * @param keyEpoch the current data key epoch
     * @param shareRefreshTokens the refresh-token policy (SPEC 5.1)
     * @param hosts the hosts that replicate the repository
     * @param members the members, the owner included
     * @param removals every member ever removed, cumulative
     */
    public record ManifestState(
            String repoId,
            long manifestSeq,
            byte[] prevManifestHash,
            byte[] ownerKey,
            byte[] genesisNonce,
            String schemeId,
            long keyEpoch,
            boolean shareRefreshTokens,
            List<HostRef> hosts,
            List<MemberEntry> members,
            List<Removal> removals) {
        /** Copies the arrays and lists. */
        public ManifestState {
            prevManifestHash = prevManifestHash.clone();
            ownerKey = ownerKey.clone();
            genesisNonce = genesisNonce.clone();
            hosts = List.copyOf(hosts);
            members = List.copyOf(members);
            removals = List.copyOf(removals);
        }

        /**
         * The member entry of a key.
         *
         * @param key an Ed25519 public key
         * @return its entry, if it is a member of this state
         */
        public Optional<MemberEntry> member(byte[] key) {
            return members.stream()
                    .filter(m -> AvpBytes.same(m.ed25519PublicKey(), key))
                    .findFirst();
        }

        /**
         * Whether a key is a member of this state.
         *
         * @param key an Ed25519 public key
         * @return whether a member has it
         */
        public boolean hasMember(byte[] key) {
            return member(key).isPresent();
        }

        /**
         * Whether a host key is in this state's {@code hosts}.
         *
         * @param key a host key
         * @return whether a host has it
         */
        public boolean hasHost(byte[] key) {
            return hosts.stream().anyMatch(h -> AvpBytes.same(h.hostKey(), key));
        }

        /**
         * The removal of a key.
         *
         * @param key an Ed25519 public key
         * @return its removal, if the key was ever removed
         */
        public Optional<Removal> removalOf(byte[] key) {
            return removals.stream()
                    .filter(r -> AvpBytes.same(r.memberKey(), key))
                    .findFirst();
        }
    }

    /**
     * A manifest state with its owner signature.
     *
     * @param state the state
     * @param ownerSignature the 64-byte {@code Ed25519-Sign(ownerKey, S)}
     */
    public record SignedManifest(ManifestState state, byte[] ownerSignature) {
        /** Copies the signature. */
        public SignedManifest {
            ownerSignature = ownerSignature.clone();
        }
    }

    static List<byte[]> copyIds(List<byte[]> ids) {
        List<byte[]> out = new ArrayList<>(ids.size());
        for (byte[] id : ids) {
            out.add(id.clone());
        }
        return List.copyOf(out);
    }

    // --- Encoding, signature, hash ---------------------------------------------------------------

    /**
     * The canonical bytes {@code S} of a state (SPEC 4.2). Hosts are sorted by {@code hostKey}, members by
     * {@code ed25519PublicKey}, removals by {@code memberKey}, and each frontier by id, so the order of a
     * wire list never matters.
     *
     * @param s the state
     * @return {@code S}
     * @throws lol.trq.alts.AltsException of kind {@code PROTOCOL} if a list repeats a key
     */
    public static byte[] encode(ManifestState s) {
        Ce w = Ce.tag(Ce.MANIFEST)
                .str(s.repoId())
                .i64(s.manifestSeq())
                .bytes(s.prevManifestHash())
                .bytes(s.ownerKey())
                .bytes(s.genesisNonce())
                .str(s.schemeId())
                .i64(s.keyEpoch())
                .bool(s.shareRefreshTokens());

        List<HostRef> hosts = sortedBy(s.hosts(), HostRef::hostKey, "host key");
        w.count(hosts.size());
        for (HostRef h : hosts) {
            w.bytes(h.hostKey()).str(h.locator());
        }

        List<MemberEntry> members = sortedBy(s.members(), MemberEntry::ed25519PublicKey, "member key");
        w.count(members.size());
        for (MemberEntry m : members) {
            WrappedKey wk = m.wrappedDataKey();
            w.bytes(m.ed25519PublicKey())
                    .bytes(m.x25519PublicKey())
                    .str(wk.schemeId())
                    .bytes(wk.ephemeralPublicKey())
                    .bytes(wk.iv())
                    .bytes(wk.ciphertext())
                    .i64(m.keyEpoch())
                    .bytes(m.homeHostKey());
        }

        List<Removal> removals = sortedBy(s.removals(), Removal::memberKey, "removed member key");
        w.count(removals.size());
        for (Removal r : removals) {
            w.bytes(r.memberKey()).i64(r.removedAtSeq());
            List<byte[]> frontier = AvpBytes.sortedUnique(r.frontier(), "frontier commit id");
            w.count(frontier.size());
            for (byte[] id : frontier) {
                w.bytes(id);
            }
        }
        return w.finish();
    }

    private static <T> List<T> sortedBy(List<T> items, Function<T, byte[]> key, String what) {
        List<T> out = new ArrayList<>(items);
        out.sort((a, b) -> AvpBytes.compare(key.apply(a), key.apply(b)));
        for (int k = 1; k < out.size(); k++) {
            if (AvpBytes.compare(key.apply(out.get(k - 1)), key.apply(out.get(k))) == 0) {
                throw AvpFailures.protocol("a " + what + " appears twice in a manifest state");
            }
        }
        return out;
    }

    /**
     * Signs a state with the owner key: {@code ownerSignature = Ed25519-Sign(ownerKey, S)}.
     *
     * @param s the state
     * @param ownerSeed the owner's 32-byte Ed25519 seed, whose public key is {@code s.ownerKey()}
     * @return the signed manifest
     */
    public static SignedManifest sign(ManifestState s, byte[] ownerSeed) {
        return new SignedManifest(s, Ed25519Strict.sign(ownerSeed, encode(s)));
    }

    /**
     * {@code manifestHash = SHA-256(S || ownerSignature)}, the raw 64-byte signature appended with no
     * length prefix (SPEC 4.2).
     *
     * @param m the signed manifest
     * @return the 32-byte hash
     * @throws lol.trq.alts.AltsException of kind {@code PROTOCOL} if the state does not encode
     */
    public static byte[] hash(SignedManifest m) {
        return AvpCrypto.sha256(AvpBytes.concat(encode(m.state()), m.ownerSignature()));
    }

    /**
     * Verifies the owner signature over {@code S} under {@code ownerKey}, strictly (SPEC 4.2, 6.1 rule 2).
     *
     * @param m the signed manifest
     * @return whether the state encodes and the signature verifies; a malformed state is simply false
     * @throws NullPointerException if an argument or one of its fields is null
     */
    public static boolean verify(SignedManifest m) {
        byte[] s;
        try {
            s = encode(m.state());
        } catch (RuntimeException malformed) {
            return false;
        }
        return Ed25519Strict.verify(m.state().ownerKey(), s, m.ownerSignature());
    }

    /**
     * Whether a state links to {@code prev} (SPEC 6.3): its seq is one more and its {@code
     * prevManifestHash} is {@code prev}'s {@code manifestHash}.
     *
     * @param next the later state
     * @param prev the earlier state
     * @return whether it links; a malformed state is simply false
     * @throws NullPointerException if an argument or one of its fields is null
     */
    public static boolean linksTo(SignedManifest next, SignedManifest prev) {
        long seq = prev.state().manifestSeq();
        if (seq == Long.MAX_VALUE || next.state().manifestSeq() != seq + 1) {
            return false;
        }
        try {
            return AvpBytes.same(next.state().prevManifestHash(), hash(prev));
        } catch (RuntimeException malformed) {
            return false;
        }
    }

    /**
     * The repository id (SPEC 4.2): {@code base64url-nopad(SHA-256(CE(tag "avp/repo-id/v1", bytes(ownerKey),
     * bytes(genesisNonce)))[0..16])}, 22 characters.
     *
     * @param ownerKey the 32-byte owner key
     * @param genesisNonce the 16-byte genesis nonce
     * @return the repository id
     * @throws lol.trq.alts.AltsException of kind {@code PROTOCOL} if a length is wrong
     */
    public static String deriveRepoId(byte[] ownerKey, byte[] genesisNonce) {
        if (ownerKey.length != 32 || genesisNonce.length != 16) {
            throw AvpFailures.protocol("a repository id needs a 32-byte owner key and a 16-byte nonce");
        }
        byte[] digest = AvpCrypto.sha256(
                Ce.tag(Ce.REPO_ID).bytes(ownerKey).bytes(genesisNonce).finish());
        return AvpBytes.base64Url(Arrays.copyOf(digest, 16));
    }

    // --- Wire form ---------------------------------------------------------------------------------

    /**
     * Decodes a {@code SignedManifest} from its HTTP/JSON form. Unknown fields are ignored; an absent
     * {@code prevManifestHash} or {@code genesisNonce} is empty, an absent {@code shareRefreshTokens} is
     * {@code false} (SPEC 5.1), and absent {@code removals} are none.
     *
     * @param json the value
     * @return the signed manifest
     * @throws lol.trq.alts.AltsException of kind {@code PROTOCOL} if a field is missing, has the wrong
     *     type, or a fixed binary field has the wrong length
     */
    public static SignedManifest signedFromJson(JsonElement json) {
        JsonObject o = AvpJson.object(json, "a signed manifest");
        return new SignedManifest(stateFromJson(AvpJson.required(o, "state")), AvpJson.bytes(o, "ownerSignature", 64));
    }

    /**
     * Decodes a {@code ManifestState} from its HTTP/JSON form.
     *
     * @param json the value
     * @return the state
     * @throws lol.trq.alts.AltsException as {@link #signedFromJson(JsonElement)}
     */
    public static ManifestState stateFromJson(JsonElement json) {
        JsonObject o = AvpJson.object(json, "a manifest state");
        List<HostRef> hosts = new ArrayList<>();
        for (JsonElement h : AvpJson.array(AvpJson.required(o, "hosts"), "hosts")) {
            JsonObject ho = AvpJson.object(h, "a host");
            hosts.add(new HostRef(AvpJson.bytes(ho, "hostKey", 32), AvpJson.string(ho, "locator")));
        }
        List<MemberEntry> members = new ArrayList<>();
        for (JsonElement m : AvpJson.array(AvpJson.required(o, "members"), "members")) {
            JsonObject mo = AvpJson.object(m, "a member");
            members.add(new MemberEntry(
                    AvpJson.bytes(mo, "ed25519PublicKey", 32),
                    AvpJson.bytes(mo, "x25519PublicKey", 32),
                    wrappedKeyFromJson(AvpJson.required(mo, "wrappedDataKey")),
                    AvpJson.int64(mo, "keyEpoch"),
                    AvpJson.bytes(mo, "homeHostKey", 32)));
        }
        List<Removal> removals = new ArrayList<>();
        JsonArray removalArray = AvpJson.optional(o, "removals")
                .map(r -> AvpJson.array(r, "removals"))
                .orElseGet(JsonArray::new);
        for (JsonElement r : removalArray) {
            JsonObject ro = AvpJson.object(r, "a removal");
            removals.add(new Removal(
                    AvpJson.bytes(ro, "memberKey", 32), AvpJson.int64(ro, "removedAtSeq"), ids(ro, "frontier")));
        }
        boolean share = AvpJson.optional(o, "shareRefreshTokens").isPresent() && AvpJson.bool(o, "shareRefreshTokens");
        return new ManifestState(
                AvpJson.string(o, "repoId"),
                AvpJson.int64(o, "manifestSeq"),
                AvpJson.optionalBytes(o, "prevManifestHash"),
                AvpJson.bytes(o, "ownerKey", 32),
                AvpJson.optionalBytes(o, "genesisNonce"),
                AvpJson.string(o, "schemeId"),
                AvpJson.int64(o, "keyEpoch"),
                share,
                hosts,
                members,
                removals);
    }

    /**
     * Decodes a {@code WrappedKey} from its HTTP/JSON form.
     *
     * @param json the value
     * @return the wrapped key
     * @throws lol.trq.alts.AltsException of kind {@code PROTOCOL} if a field is missing or has the wrong
     *     type, or the ephemeral key or IV has the wrong length
     */
    public static WrappedKey wrappedKeyFromJson(JsonElement json) {
        JsonObject o = AvpJson.object(json, "a wrapped key");
        return new WrappedKey(
                AvpJson.string(o, "schemeId"),
                AvpJson.bytes(o, "ephemeralPublicKey", 32),
                AvpJson.bytes(o, "iv", 12),
                AvpJson.bytes(o, "ciphertext"));
    }

    /**
     * The HTTP/JSON form of a signed manifest, fields in the proto order, lists in their own order.
     *
     * @param m the signed manifest
     * @return the object
     */
    public static JsonObject toJson(SignedManifest m) {
        JsonObject o = new JsonObject();
        o.add("state", toJson(m.state()));
        o.addProperty("ownerSignature", AvpBytes.base64(m.ownerSignature()));
        return o;
    }

    /**
     * The HTTP/JSON form of a state.
     *
     * @param s the state
     * @return the object
     */
    public static JsonObject toJson(ManifestState s) {
        JsonObject o = new JsonObject();
        o.addProperty("repoId", s.repoId());
        o.addProperty("manifestSeq", s.manifestSeq());
        o.addProperty("prevManifestHash", AvpBytes.base64(s.prevManifestHash()));
        o.addProperty("ownerKey", AvpBytes.base64(s.ownerKey()));
        o.addProperty("genesisNonce", AvpBytes.base64(s.genesisNonce()));
        o.addProperty("schemeId", s.schemeId());
        o.addProperty("keyEpoch", s.keyEpoch());
        o.addProperty("shareRefreshTokens", s.shareRefreshTokens());
        JsonArray hosts = new JsonArray();
        for (HostRef h : s.hosts()) {
            JsonObject ho = new JsonObject();
            ho.addProperty("hostKey", AvpBytes.base64(h.hostKey()));
            ho.addProperty("locator", h.locator());
            hosts.add(ho);
        }
        o.add("hosts", hosts);
        JsonArray members = new JsonArray();
        for (MemberEntry m : s.members()) {
            JsonObject mo = new JsonObject();
            mo.addProperty("ed25519PublicKey", AvpBytes.base64(m.ed25519PublicKey()));
            mo.addProperty("x25519PublicKey", AvpBytes.base64(m.x25519PublicKey()));
            mo.add("wrappedDataKey", toJson(m.wrappedDataKey()));
            mo.addProperty("keyEpoch", m.keyEpoch());
            mo.addProperty("homeHostKey", AvpBytes.base64(m.homeHostKey()));
            members.add(mo);
        }
        o.add("members", members);
        JsonArray removals = new JsonArray();
        for (Removal r : s.removals()) {
            JsonObject ro = new JsonObject();
            ro.addProperty("memberKey", AvpBytes.base64(r.memberKey()));
            ro.addProperty("removedAtSeq", r.removedAtSeq());
            ro.add("frontier", idsJson(r.frontier()));
            removals.add(ro);
        }
        o.add("removals", removals);
        return o;
    }

    /**
     * The HTTP/JSON form of a wrapped key.
     *
     * @param wk the wrapped key
     * @return the object
     */
    public static JsonObject toJson(WrappedKey wk) {
        JsonObject o = new JsonObject();
        o.addProperty("schemeId", wk.schemeId());
        o.addProperty("ephemeralPublicKey", AvpBytes.base64(wk.ephemeralPublicKey()));
        o.addProperty("iv", AvpBytes.base64(wk.iv()));
        o.addProperty("ciphertext", AvpBytes.base64(wk.ciphertext()));
        return o;
    }

    static List<byte[]> ids(JsonObject o, String key) {
        List<byte[]> out = new ArrayList<>();
        for (JsonElement id : AvpJson.array(AvpJson.required(o, key), key)) {
            out.add(AvpBytes.fromBase64(AvpJson.string(id, key), 32, "an id in " + key));
        }
        return out;
    }

    static JsonArray idsJson(List<byte[]> ids) {
        JsonArray out = new JsonArray();
        for (byte[] id : ids) {
            out.add(AvpBytes.base64(id));
        }
        return out;
    }
}

package lol.trq.alts.vault;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.SortedMap;
import java.util.TreeMap;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.internal.avp.AvpBytes;
import lol.trq.alts.internal.avp.AvpJson;
import lol.trq.alts.internal.avp.Payload;
import lol.trq.alts.internal.vault.EngineState;

/**
 * What one member device keeps of a repository between runs, for the host to persist and pass back to {@link
 * SharedVault#resume}: the verified chain as its state hashes, whose last is the pin a rollback must not go
 * below (AVP SPEC 6.4); every data key this device has held, by epoch, so old-epoch heads stay readable; the
 * clock (SPEC 5); the merged payload; whether this member left; the member it belongs to; and its home host,
 * key and locator, so {@link VaultHosts#connect(VaultSnapshot)} reaches it by key.
 *
 * <p>It names the member by its member id and does not hold the identity: the host keeps the identity on its
 * own ({@link WrappedIdentity} for a member, {@link OwnerIdentity#entropy()} for the owner) and passes it to
 * {@code resume}, which refuses an identity that is not the one named here.
 *
 * <p>It holds secrets (the data keys and the accounts' credentials), so persist its {@link #toJson()}
 * encrypted, for example in {@link lol.trq.alts.store.HostSecrets}, never in plain text. {@link #toString()}
 * shows neither.
 *
 * @author trq
 * @since 1.0.0
 */
public final class VaultSnapshot {

    /** The version of the JSON form. */
    private static final int VERSION = 1;

    private final EngineState state;
    private final String memberId;
    private final HostRef homeHost;

    VaultSnapshot(EngineState state, String memberId, HostRef homeHost) {
        this.state = Objects.requireNonNull(state, "state");
        this.memberId = Objects.requireNonNull(memberId, "memberId");
        this.homeHost = Objects.requireNonNull(homeHost, "homeHost");
    }

    /**
     * The JSON form to persist. A secret.
     *
     * @return compact JSON
     * @since 1.0.0
     */
    public String toJson() {
        JsonObject o = new JsonObject();
        o.addProperty("v", VERSION);
        o.addProperty("repoId", state.repoId());
        o.addProperty("memberId", memberId);
        o.addProperty("homeHostKey", homeHost.hostKey());
        o.addProperty("homeHostLocator", homeHost.locator());
        JsonArray chain = new JsonArray();
        for (byte[] h : state.chainHashes()) {
            chain.add(AvpBytes.base64(h));
        }
        o.add("chain", chain);
        JsonObject keys = new JsonObject();
        SortedMap<Long, byte[]> retained = state.retainedKeys();
        try {
            retained.forEach((epoch, key) -> keys.addProperty(Long.toString(epoch), AvpBytes.base64(key)));
        } finally {
            retained.values().forEach(k -> java.util.Arrays.fill(k, (byte) 0));
        }
        o.add("epochKeys", keys);
        o.addProperty("hlcAt", state.hlcAt());
        o.addProperty("hlcN", state.hlcN());
        o.add("payload", state.local().toJson());
        o.addProperty("left", state.left());
        return new String(AvpJson.write(o), StandardCharsets.UTF_8);
    }

    /**
     * Reads a snapshot from its JSON form.
     *
     * @param json what {@link #toJson()} returned
     * @return the snapshot
     * @throws AltsException of kind {@code INVALID_INPUT} if the text is not a snapshot of this version
     * @since 1.0.0
     */
    public static VaultSnapshot fromJson(String json) {
        Objects.requireNonNull(json, "json");
        try {
            JsonObject o = AvpJson.object(AvpJson.parse(json.getBytes(StandardCharsets.UTF_8)), "a vault snapshot");
            if (AvpJson.int64(o, "v") != VERSION) {
                throw VaultFutures.invalid("the vault snapshot is not of a version this library reads");
            }
            List<byte[]> chain = new ArrayList<>();
            for (JsonElement h : AvpJson.array(AvpJson.required(o, "chain"), "chain")) {
                chain.add(AvpBytes.fromBase64(AvpJson.string(h, "a chain hash"), 32, "a chain hash"));
            }
            SortedMap<Long, byte[]> keys = new TreeMap<>();
            for (Map.Entry<String, JsonElement> e : AvpJson.object(AvpJson.required(o, "epochKeys"), "epochKeys")
                    .entrySet()) {
                long epoch = Long.parseLong(e.getKey());
                if (epoch < 0) {
                    throw VaultFutures.invalid("a vault snapshot epoch is never negative");
                }
                keys.put(epoch, AvpBytes.fromBase64(AvpJson.string(e.getValue(), "an epoch key"), 32, "an epoch key"));
            }
            String memberId = AvpJson.string(o, "memberId");
            String hostKey = AvpJson.string(o, "homeHostKey");
            AvpBytes.fromBase64(memberId, 32, "the member id");
            AvpBytes.fromBase64(hostKey, 32, "the home host key");
            EngineState state = new EngineState(
                    AvpJson.string(o, "repoId"),
                    chain,
                    keys,
                    AvpJson.int64(o, "hlcAt"),
                    AvpJson.int64(o, "hlcN"),
                    Payload.fromJson(AvpJson.required(o, "payload")),
                    AvpJson.bool(o, "left"));
            keys.values().forEach(k -> java.util.Arrays.fill(k, (byte) 0));
            return new VaultSnapshot(state, memberId, new HostRef(hostKey, AvpJson.string(o, "homeHostLocator")));
        } catch (RuntimeException malformed) {
            if (malformed instanceof AltsException e && e.kind() == Kind.INVALID_INPUT) {
                throw e;
            }
            // The parser's message may name a field; the library's own names the snapshot only.
            throw new AltsException(
                    AltsFailure.of(Kind.INVALID_INPUT, "Vault: this is not a valid vault snapshot"), malformed);
        }
    }

    /**
     * The repository.
     *
     * @return the repository id
     * @since 1.0.0
     */
    public String repoId() {
        return state.repoId();
    }

    /**
     * The member this snapshot belongs to.
     *
     * @return the member id
     * @since 1.0.0
     */
    public String memberId() {
        return memberId;
    }

    /**
     * The member's home host, by key; {@link VaultHosts#connect(VaultSnapshot)} reaches it.
     *
     * @return the home host
     * @since 1.0.0
     */
    public HostRef homeHost() {
        return homeHost;
    }

    /**
     * The seq of the pinned state, the highest this device verified.
     *
     * @return the seq
     * @since 1.0.0
     */
    public long pinnedSeq() {
        return state.chainHashes().size();
    }

    /**
     * Whether this member left the repository; such a snapshot does not resume.
     *
     * @return whether it left
     * @since 1.0.0
     */
    public boolean left() {
        return state.left();
    }

    EngineState state() {
        return state;
    }

    /**
     * The repository, the pin and counts only; never a key or an account.
     *
     * @return a description
     */
    @Override
    public String toString() {
        return "VaultSnapshot[" + state.repoId() + ", seq " + pinnedSeq() + ", " + state.epochKeyCount()
                + " epoch keys, left=" + state.left() + "]";
    }
}

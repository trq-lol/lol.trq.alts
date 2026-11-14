package lol.trq.alts.internal.avp;

import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.SortedMap;
import java.util.TreeMap;

/**
 * Payload v2 (AVP SPEC 5): the plaintext of a commit, its per-account, per-field merge, the deletion
 * rule, and the refresh-token strip of SPEC 5.1.
 *
 * <pre>
 * { "v": 2, "accounts": { "&lt;uuid&gt;": Account } }
 * Account = { "deleted"?: Stamp, "fields": { name: Field }, "bans": { serverId: Field } }
 * Field   = { "value": json, "at": int64, "n": int64, "by": memberId }
 * Stamp   = { "at": int64, "n": int64, "by": memberId }
 * </pre>
 *
 * <p>A payload holds credentials ({@code accessToken}, {@code refreshToken}), so no type here prints a
 * field value: {@link #toString()} and the record {@code toString}s show stamps and counts only. The
 * values are Gson trees, deep-copied in and out.
 *
 * <p>Ported from the Alt Vault Protocol reference implementation (MIT).
 *
 * @param accounts the accounts by player UUID
 * @author trq
 * @since 1.0.0
 */
public record Payload(SortedMap<String, Account> accounts) {

    /** The fields SPEC 5.1 strips while the refresh-token policy is not {@code true}. */
    public static final List<String> REFRESH_FIELDS = List.of("refreshToken", "expiresAt");

    /** An empty payload. */
    public static final Payload EMPTY = new Payload(new TreeMap<>());

    /** Copies the map. */
    public Payload {
        accounts = Collections.unmodifiableSortedMap(new TreeMap<>(accounts));
    }

    /**
     * A stamp {@code (at, n, by)}: ordered by {@code at}, then {@code n}, then {@code by} compared by its
     * UTF-8 bytes; the greatest wins.
     *
     * @param at epoch milliseconds
     * @param n the counter
     * @param by the writer's member id
     */
    public record Stamp(long at, long n, String by) implements Comparable<Stamp> {
        @Override
        public int compareTo(Stamp o) {
            if (at != o.at) {
                return Long.compare(at, o.at);
            }
            if (n != o.n) {
                return Long.compare(n, o.n);
            }
            return Arrays.compareUnsigned(by.getBytes(StandardCharsets.UTF_8), o.by.getBytes(StandardCharsets.UTF_8));
        }

        static Stamp fromJson(JsonElement json, String what) {
            JsonObject o = AvpJson.object(json, what);
            return new Stamp(AvpJson.int64(o, "at"), AvpJson.int64(o, "n"), AvpJson.string(o, "by"));
        }

        JsonObject toJson() {
            JsonObject o = new JsonObject();
            o.addProperty("at", at);
            o.addProperty("n", n);
            o.addProperty("by", by);
            return o;
        }
    }

    /**
     * One last-writer-wins register: a value and its stamp.
     *
     * @param value the value, a Gson tree ({@link JsonNull} for null)
     * @param stamp its stamp
     */
    public record Field(JsonElement value, Stamp stamp) {
        /** Copies the value. */
        public Field {
            value = value == null ? JsonNull.INSTANCE : value.deepCopy();
        }

        /**
         * The value.
         *
         * @return a copy of the value
         */
        @Override
        public JsonElement value() {
            return value.deepCopy();
        }

        /**
         * The stamp only; a value may be a credential.
         *
         * @return a description
         */
        @Override
        public String toString() {
            return "Field[" + stamp + "]";
        }

        static Field fromJson(JsonElement json, String what) {
            JsonObject o = AvpJson.object(json, what);
            return new Field(o.has("value") ? o.get("value") : JsonNull.INSTANCE, Stamp.fromJson(o, what));
        }

        JsonObject toJson() {
            JsonObject o = new JsonObject();
            o.add("value", value.deepCopy());
            o.addProperty("at", stamp.at());
            o.addProperty("n", stamp.n());
            o.addProperty("by", stamp.by());
            return o;
        }
    }

    /**
     * One account.
     *
     * @param deleted the deletion marker, if any
     * @param fields the fields by name
     * @param bans the ban registers by server id
     */
    public record Account(Optional<Stamp> deleted, SortedMap<String, Field> fields, SortedMap<String, Field> bans) {
        /** Copies the maps. */
        public Account {
            fields = Collections.unmodifiableSortedMap(new TreeMap<>(fields));
            bans = Collections.unmodifiableSortedMap(new TreeMap<>(bans));
        }

        /**
         * Whether the account is deleted (SPEC 5): its marker exists and is greater than every field stamp
         * and every ban stamp, so an edit after a deletion brings it back.
         *
         * @return whether it is deleted
         */
        public boolean isDeleted() {
            if (deleted.isEmpty()) {
                return false;
            }
            Stamp d = deleted.get();
            for (Field f : fields.values()) {
                if (f.stamp().compareTo(d) >= 0) {
                    return false;
                }
            }
            for (Field f : bans.values()) {
                if (f.stamp().compareTo(d) >= 0) {
                    return false;
                }
            }
            return true;
        }

        /**
         * The field names, ban servers and marker; never a value.
         *
         * @return a description
         */
        @Override
        public String toString() {
            return "Account[fields=" + fields.keySet() + ", bans=" + bans.keySet() + ", deleted=" + deleted + "]";
        }

        static Account fromJson(JsonElement json) {
            JsonObject o = AvpJson.object(json, "an account");
            Optional<Stamp> deleted = AvpJson.optional(o, "deleted").map(d -> Stamp.fromJson(d, "deleted"));
            return new Account(deleted, registers(o, "fields"), registers(o, "bans"));
        }

        private static SortedMap<String, Field> registers(JsonObject account, String key) {
            SortedMap<String, Field> out = new TreeMap<>();
            Optional<JsonElement> present = AvpJson.optional(account, key);
            if (present.isPresent()) {
                for (Map.Entry<String, JsonElement> e :
                        AvpJson.object(present.get(), key).entrySet()) {
                    out.put(e.getKey(), Field.fromJson(e.getValue(), key));
                }
            }
            return out;
        }

        JsonObject toJson() {
            JsonObject o = new JsonObject();
            deleted.ifPresent(d -> o.add("deleted", d.toJson()));
            o.add("fields", registersJson(fields));
            o.add("bans", registersJson(bans));
            return o;
        }

        private static JsonObject registersJson(SortedMap<String, Field> registers) {
            JsonObject o = new JsonObject();
            registers.forEach((k, v) -> o.add(k, v.toJson()));
            return o;
        }
    }

    /**
     * Decodes a payload.
     *
     * @param json the value
     * @return the payload
     * @throws lol.trq.alts.AltsException of kind {@code PROTOCOL} if it is not of the payload v2 shape or
     *     its {@code v} is not the integer 2, which a client treats as an unreadable head (SPEC 7.5)
     */
    public static Payload fromJson(JsonElement json) {
        JsonObject o = AvpJson.object(json, "a payload");
        if (AvpJson.int64(o, "v") != 2) {
            throw AvpFailures.protocol("the payload is not version 2");
        }
        SortedMap<String, Account> accounts = new TreeMap<>();
        for (Map.Entry<String, JsonElement> e :
                AvpJson.object(AvpJson.required(o, "accounts"), "accounts").entrySet()) {
            accounts.put(e.getKey(), Account.fromJson(e.getValue()));
        }
        return new Payload(accounts);
    }

    /**
     * Decodes a payload from its UTF-8 JSON plaintext.
     *
     * @param plaintext the decrypted bytes
     * @return the payload
     * @throws lol.trq.alts.AltsException of kind {@code PROTOCOL} as {@link #fromJson(JsonElement)}
     */
    public static Payload parse(byte[] plaintext) {
        return fromJson(AvpJson.parse(plaintext));
    }

    /**
     * The JSON form: {@code v}, then the accounts sorted by UUID, each with its marker, fields and bans.
     *
     * @return the object
     */
    public JsonObject toJson() {
        JsonObject out = new JsonObject();
        out.addProperty("v", 2);
        JsonObject list = new JsonObject();
        accounts.forEach((k, v) -> list.add(k, v.toJson()));
        out.add("accounts", list);
        return out;
    }

    /**
     * The compact UTF-8 JSON a commit encrypts.
     *
     * @return the bytes, which the caller zeroes once sealed
     */
    public byte[] encode() {
        return AvpJson.write(toJson());
    }

    /**
     * Merges payloads (SPEC 5): the union of the accounts; per account, each field name and each ban
     * server id takes the register with the greatest stamp; {@code deleted} is the greatest marker. The
     * merge is commutative, associative and idempotent.
     *
     * <p>Two registers with equal stamps and different values cannot come from conformant writers, and SPEC
     * 5 leaves their merge implementation-defined. This client keeps the one whose value has the greater
     * compact JSON encoding ({@link AvpJson#write}), compared as unsigned bytes, so the merge stays
     * commutative even for such input.
     *
     * @param payloads the payloads
     * @return the merge
     */
    public static Payload merge(List<Payload> payloads) {
        SortedMap<String, Account> out = new TreeMap<>();
        for (Payload p : payloads) {
            p.accounts().forEach((uuid, account) -> out.merge(uuid, account, Payload::mergeAccounts));
        }
        return new Payload(out);
    }

    private static Account mergeAccounts(Account a, Account b) {
        Optional<Stamp> deleted = a.deleted();
        if (b.deleted().isPresent() && (deleted.isEmpty() || b.deleted().get().compareTo(deleted.get()) > 0)) {
            deleted = b.deleted();
        }
        return new Account(deleted, mergeRegisters(a.fields(), b.fields()), mergeRegisters(a.bans(), b.bans()));
    }

    private static SortedMap<String, Field> mergeRegisters(SortedMap<String, Field> a, SortedMap<String, Field> b) {
        SortedMap<String, Field> out = new TreeMap<>(a);
        b.forEach((k, f) -> out.merge(k, f, Payload::greater));
        return out;
    }

    /**
     * The register with the greater stamp; at an equal stamp, the one whose compact JSON value is greater
     * as unsigned bytes (the first if the bytes are equal too, which are then the same value).
     */
    private static Field greater(Field x, Field y) {
        int c = y.stamp().compareTo(x.stamp());
        if (c != 0) {
            return c > 0 ? y : x;
        }
        byte[] xs = AvpJson.write(x.value);
        byte[] ys = AvpJson.write(y.value);
        try {
            return Arrays.compareUnsigned(ys, xs) > 0 ? y : x;
        } finally {
            // A value may be a credential.
            Arrays.fill(xs, (byte) 0);
            Arrays.fill(ys, (byte) 0);
        }
    }

    /**
     * Removes the {@code refreshToken} and {@code expiresAt} registers, stamps included, from every account
     * (SPEC 5.1).
     *
     * @return the stripped payload
     */
    public Payload stripRefresh() {
        SortedMap<String, Account> out = new TreeMap<>();
        accounts.forEach((uuid, a) -> {
            SortedMap<String, Field> fields = new TreeMap<>(a.fields());
            REFRESH_FIELDS.forEach(fields::remove);
            out.put(uuid, new Account(a.deleted(), fields, a.bans()));
        });
        return new Payload(out);
    }

    /**
     * The payload as a client may use or write it under a policy (SPEC 5.1): unchanged when the latest
     * verified state shares refresh tokens, stripped otherwise.
     *
     * @param shareRefreshTokens the policy of the latest verified state; false when unknown
     * @return this payload, or its strip
     */
    public Payload underPolicy(boolean shareRefreshTokens) {
        return shareRefreshTokens ? this : stripRefresh();
    }

    /**
     * Counts only; a payload holds credentials.
     *
     * @return a description
     */
    @Override
    public String toString() {
        return "Payload[" + accounts.size() + " accounts]";
    }
}

package lol.trq.alts.vault;

import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.SortedMap;
import lol.trq.alts.internal.avp.Payload;
import lol.trq.alts.internal.vault.PayloadEditor;
import lol.trq.alts.model.AccountType;
import lol.trq.alts.model.AltAccount;
import lol.trq.alts.model.BanInfo;

/**
 * Payload v2 (AVP SPEC 5) to and from {@link AltAccount} and {@link BanInfo}. The field names are exactly the
 * SPEC's: {@code username}, {@code accessToken}, {@code refreshToken}, {@code expiresAt}, {@code type}, {@code
 * lastUsed}, {@code lastUsedBy}, {@code sourceClient}, {@code sourceUser}; a ban register per server id holds
 * {@code {banned, observedAt, source, detail, observedBy}} or {@code null}.
 *
 * <p>The values come from other members, so reading is tolerant (SPEC 5: absence of any field is tolerated):
 * a field that is absent or of the wrong JSON type reads as absent, {@code 0} for the two times and for
 * {@code expiresAt}, {@code null} otherwise, and an unknown {@code type} reads as {@code null}.
 *
 * @author trq
 * @since 1.0.0
 */
final class AccountMapping {

    /** The SPEC 5 field names, in the SPEC's order. */
    static final List<String> FIELDS = List.of(
            "username",
            "accessToken",
            "refreshToken",
            "expiresAt",
            "type",
            "lastUsed",
            "lastUsedBy",
            "sourceClient",
            "sourceUser");

    private AccountMapping() {}

    // --- Read ------------------------------------------------------------------------------------

    /**
     * The account a payload entry describes.
     *
     * @param uuid the payload's key, the player UUID
     * @param a the entry
     * @return the account
     */
    static AltAccount toAccount(String uuid, Payload.Account a) {
        SortedMap<String, Payload.Field> f = a.fields();
        Map<String, BanInfo> bans = new LinkedHashMap<>();
        a.bans().forEach((server, register) -> {
            BanInfo ban = ban(register.value());
            if (ban != null) {
                bans.put(server, ban);
            }
        });
        return new AltAccount(
                uuid,
                string(f, "username"),
                string(f, "accessToken"),
                type(string(f, "type")),
                int64(f, "lastUsed"),
                string(f, "lastUsedBy"),
                bans.isEmpty() ? null : bans,
                string(f, "sourceClient"),
                string(f, "sourceUser"),
                string(f, "refreshToken"),
                int64(f, "expiresAt"));
    }

    private static JsonElement value(SortedMap<String, Payload.Field> fields, String name) {
        Payload.Field field = fields.get(name);
        return field == null ? JsonNull.INSTANCE : field.value();
    }

    private static String string(SortedMap<String, Payload.Field> fields, String name) {
        return string(value(fields, name));
    }

    private static String string(JsonElement v) {
        return v.isJsonPrimitive() && v.getAsJsonPrimitive().isString() ? v.getAsString() : null;
    }

    private static long int64(SortedMap<String, Payload.Field> fields, String name) {
        return int64(value(fields, name));
    }

    private static long int64(JsonElement v) {
        if (!v.isJsonPrimitive() || !v.getAsJsonPrimitive().isNumber()) {
            return 0L;
        }
        try {
            return v.getAsJsonPrimitive().getAsBigDecimal().longValueExact();
        } catch (ArithmeticException notAnInt64) {
            return 0L;
        }
    }

    private static AccountType type(String name) {
        if (name == null) {
            return null;
        }
        for (AccountType t : AccountType.values()) {
            if (t.name().equals(name)) {
                return t;
            }
        }
        return null;
    }

    /**
     * The ban a register value describes, or {@code null} for a cleared register or a value that is not an
     * object.
     *
     * @param v the register value
     * @return the ban, or null
     */
    static BanInfo ban(JsonElement v) {
        if (!v.isJsonObject()) {
            return null;
        }
        JsonObject o = v.getAsJsonObject();
        JsonElement banned = o.has("banned") ? o.get("banned") : JsonNull.INSTANCE;
        return new BanInfo(
                banned.isJsonPrimitive() && banned.getAsJsonPrimitive().isBoolean() && banned.getAsBoolean(),
                int64(o.has("observedAt") ? o.get("observedAt") : JsonNull.INSTANCE),
                string(o.has("source") ? o.get("source") : JsonNull.INSTANCE),
                string(o.has("detail") ? o.get("detail") : JsonNull.INSTANCE),
                string(o.has("observedBy") ? o.get("observedBy") : JsonNull.INSTANCE));
    }

    // --- Write -----------------------------------------------------------------------------------

    /**
     * The SPEC 5 field values of an account.
     *
     * @param a the account
     * @return the values by field name, in {@link #FIELDS} order; {@link JsonNull} for a null
     */
    static Map<String, JsonElement> fields(AltAccount a) {
        Map<String, JsonElement> out = new LinkedHashMap<>();
        out.put("username", text(a.username()));
        out.put("accessToken", text(a.accessToken()));
        out.put("refreshToken", text(a.refreshToken()));
        out.put("expiresAt", new JsonPrimitive(a.expiresAt()));
        out.put("type", text(a.type() == null ? null : a.type().name()));
        out.put("lastUsed", new JsonPrimitive(a.lastUsed()));
        out.put("lastUsedBy", text(a.lastUsedBy()));
        out.put("sourceClient", text(a.sourceClient()));
        out.put("sourceUser", text(a.sourceUser()));
        return out;
    }

    private static JsonElement text(String s) {
        return s == null ? JsonNull.INSTANCE : new JsonPrimitive(s);
    }

    /**
     * The register value of a ban.
     *
     * @param b the ban, or null to clear the register
     * @return the value
     */
    static JsonElement banJson(BanInfo b) {
        if (b == null) {
            return JsonNull.INSTANCE;
        }
        JsonObject o = new JsonObject();
        o.addProperty("banned", b.banned());
        o.addProperty("observedAt", b.observedAt());
        o.add("source", text(b.source()));
        o.add("detail", text(b.detail()));
        o.add("observedBy", text(b.observedBy()));
        return o;
    }

    /**
     * Writes an account into a payload edit, field by field: only a field whose value differs from the
     * copy's takes a fresh stamp, so a concurrent edit of another field on another device survives the merge
     * (SPEC 5). An account the copy does not hold, or holds deleted, takes every field, which brings a deleted
     * one back. Each ban the account carries is written the same way, per server id; a server the account does
     * not mention is left as it is.
     *
     * @param editor the edit
     * @param a the account
     */
    static void write(PayloadEditor editor, AltAccount a) {
        Payload.Account current = editor.payload().accounts().get(a.uuid());
        boolean all = current == null || current.isDeleted();
        for (Map.Entry<String, JsonElement> e : fields(a).entrySet()) {
            JsonElement before = current == null
                    ? JsonNull.INSTANCE
                    : Optional.ofNullable(current.fields().get(e.getKey()))
                            .map(Payload.Field::value)
                            .orElse(JsonNull.INSTANCE);
            if (all || !before.equals(e.getValue())) {
                editor.setField(a.uuid(), e.getKey(), e.getValue());
            }
        }
        if (a.bans() != null) {
            for (Map.Entry<String, BanInfo> b : a.bans().entrySet()) {
                JsonElement next = banJson(b.getValue());
                JsonElement before = current == null
                        ? JsonNull.INSTANCE
                        : Optional.ofNullable(current.bans().get(b.getKey()))
                                .map(Payload.Field::value)
                                .orElse(JsonNull.INSTANCE);
                if (all || !before.equals(next)) {
                    editor.setBan(a.uuid(), b.getKey(), next);
                }
            }
        }
    }
}

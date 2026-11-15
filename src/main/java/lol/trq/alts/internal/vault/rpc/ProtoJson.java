package lol.trq.alts.internal.vault.rpc;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.internal.vault.rpc.AvpProto.Field;
import lol.trq.alts.internal.vault.rpc.AvpProto.Message;

/**
 * Converts the HTTP/JSON bodies of AVP to the proto3 messages of {@code avp.Vault} and back, without a
 * protobuf runtime. Both sides use the same field names (camelCase in JSON), and binary values are base64
 * strings in both, so the conversion is structural and the bodies the client already builds and verifies
 * cross unchanged.
 *
 * <p>{@link #encode} writes the canonical encoding of AVP's {@code grpc.json}: fields in ascending number,
 * scalars at their default and empty repeated fields left out, absent messages left out. {@link #decode}
 * yields the full form: every scalar present with its default, every repeated field an array, absent
 * messages omitted. Both are pinned by the vendored vectors.
 *
 * @author trq
 * @since 1.1.0
 */
public final class ProtoJson {

    /** How deep messages may nest in a decoded message; AVP's own schema goes five deep. */
    static final int MAX_DEPTH = 16;

    private ProtoJson() {}

    /**
     * Encodes a JSON body as the named message.
     *
     * @param message the full message name, {@code avp.PushRequest}
     * @param json the body, in the HTTP/JSON profile's shape
     * @return the proto3 bytes
     * @throws AltsException of kind {@link Kind#INVALID_INPUT} if the body has a member the message lacks or a
     *     value of the wrong type: the library builds these bodies itself, so this guards against its own bug
     * @throws IllegalArgumentException if AVP has no such message
     */
    public static byte[] encode(String message, JsonObject json) {
        ProtoWire.Writer w = new ProtoWire.Writer();
        write(AvpProto.message(message), json, w);
        return w.toByteArray();
    }

    /**
     * Decodes the named message to its JSON body. Unknown field numbers are skipped, as proto3 requires.
     *
     * @param message the full message name, {@code avp.PushResponse}
     * @param bytes the proto3 bytes
     * @return the body in its full form
     * @throws AltsException of kind {@link Kind#PROTOCOL} for a wrong wire type, a truncated field, a varint over
     *     ten bytes, a length past the end, invalid UTF-8, or nesting deeper than sixteen
     * @throws IllegalArgumentException if AVP has no such message
     */
    public static JsonObject decode(String message, byte[] bytes) {
        return read(AvpProto.message(message), new ProtoWire.Reader(bytes), 1);
    }

    private static AltsException invalid(String what) {
        return new AltsException(Kind.INVALID_INPUT, "Vault: a request body cannot be encoded (" + what + ")");
    }

    private static void write(Message m, JsonObject json, ProtoWire.Writer w) {
        for (String key : json.keySet()) {
            if (m.byJson(key) == null) {
                throw invalid("unknown member");
            }
        }
        for (Field f : m.fields()) {
            JsonElement v = json.get(f.json());
            if (v == null || v.isJsonNull()) {
                continue;
            }
            if (f.repeated()) {
                if (!v.isJsonArray()) {
                    throw invalid("not an array");
                }
                for (JsonElement e : v.getAsJsonArray()) {
                    writeOne(f, e, w, true);
                }
            } else {
                writeOne(f, v, w, false);
            }
        }
    }

    private static void writeOne(Field f, JsonElement v, ProtoWire.Writer w, boolean always) {
        switch (f.kind()) {
            case STRING -> {
                String s = primitive(v).isString() ? v.getAsString() : null;
                if (s == null) {
                    throw invalid("not a string");
                }
                if (always || !s.isEmpty()) {
                    w.bytes(f.number(), s.getBytes(StandardCharsets.UTF_8));
                }
            }
            case INT64 -> {
                JsonPrimitive p = primitive(v);
                if (!p.isNumber()) {
                    throw invalid("not a number");
                }
                long n;
                try {
                    n = p.getAsBigDecimal().longValueExact();
                } catch (ArithmeticException | NumberFormatException e) {
                    throw invalid("not an int64");
                }
                if (always || n != 0) {
                    w.tag(f.number(), ProtoWire.VARINT);
                    w.varint(n);
                }
            }
            case BOOL -> {
                JsonPrimitive p = primitive(v);
                if (!p.isBoolean()) {
                    throw invalid("not a boolean");
                }
                if (always || p.getAsBoolean()) {
                    w.tag(f.number(), ProtoWire.VARINT);
                    w.varint(p.getAsBoolean() ? 1 : 0);
                }
            }
            case MESSAGE -> {
                if (!v.isJsonObject()) {
                    throw invalid("not an object");
                }
                ProtoWire.Writer inner = new ProtoWire.Writer();
                write(AvpProto.message(f.message()), v.getAsJsonObject(), inner);
                w.bytes(f.number(), inner.toByteArray());
            }
        }
    }

    private static JsonPrimitive primitive(JsonElement v) {
        if (!v.isJsonPrimitive()) {
            throw invalid("not a scalar");
        }
        return v.getAsJsonPrimitive();
    }

    private static JsonObject read(Message m, ProtoWire.Reader r, int depth) {
        if (depth > MAX_DEPTH) {
            throw ProtoWire.malformed("nested too deep");
        }
        Map<Integer, JsonElement> seen = new HashMap<>();
        while (!r.atEnd()) {
            int tag = r.tag();
            int number = tag >>> 3;
            int wireType = tag & 7;
            Field f = m.byNumber(number);
            if (f == null) {
                r.skip(wireType);
                continue;
            }
            int expected = f.kind() == AvpProto.Kind.STRING || f.kind() == AvpProto.Kind.MESSAGE
                    ? ProtoWire.LEN
                    : ProtoWire.VARINT;
            if (wireType != expected) {
                throw ProtoWire.malformed("wrong wire type");
            }
            JsonElement value =
                    switch (f.kind()) {
                        case STRING -> new JsonPrimitive(r.string());
                        case INT64 -> new JsonPrimitive(r.varint());
                        case BOOL -> new JsonPrimitive(r.varint() != 0);
                        case MESSAGE -> read(AvpProto.message(f.message()), r.slice(), depth + 1);
                    };
            if (f.repeated()) {
                ((JsonArray) seen.computeIfAbsent(number, k -> new JsonArray())).add(value);
            } else if (f.kind() == AvpProto.Kind.MESSAGE && seen.get(number) instanceof JsonObject prior) {
                merge(prior, value.getAsJsonObject());
            } else {
                seen.put(number, value);
            }
        }
        JsonObject out = new JsonObject();
        for (Field f : m.fields()) {
            JsonElement v = seen.get(f.number());
            if (v != null) {
                out.add(f.json(), v);
            } else if (f.repeated()) {
                out.add(f.json(), new JsonArray());
            } else {
                switch (f.kind()) {
                    case STRING -> out.addProperty(f.json(), "");
                    case INT64 -> out.addProperty(f.json(), 0L);
                    case BOOL -> out.addProperty(f.json(), false);
                    case MESSAGE -> {}
                }
            }
        }
        return out;
    }

    /**
     * Merges a later occurrence of a singular message field into the earlier one, as proto3 does: a scalar
     * the later one carries replaces, a repeated field appends, a message merges.
     */
    private static void merge(JsonObject into, JsonObject later) {
        for (Map.Entry<String, JsonElement> e : later.entrySet()) {
            JsonElement prior = into.get(e.getKey());
            JsonElement v = e.getValue();
            if (prior != null && prior.isJsonArray() && v.isJsonArray()) {
                prior.getAsJsonArray().addAll(v.getAsJsonArray());
            } else if (prior != null && prior.isJsonObject() && v.isJsonObject()) {
                merge(prior.getAsJsonObject(), v.getAsJsonObject());
            } else if (prior == null || !isDefault(v)) {
                into.add(e.getKey(), v);
            }
        }
    }

    private static boolean isDefault(JsonElement v) {
        if (!v.isJsonPrimitive()) {
            return false;
        }
        JsonPrimitive p = v.getAsJsonPrimitive();
        return (p.isString() && p.getAsString().isEmpty())
                || (p.isBoolean() && !p.getAsBoolean())
                || (p.isNumber() && p.getAsLong() == 0);
    }
}

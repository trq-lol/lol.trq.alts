package lol.trq.alts.internal.avp;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import com.google.gson.Strictness;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import java.io.IOException;
import java.io.StringReader;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Strict JSON for AVP items, over Gson's tree types.
 *
 * <p>{@link #parse(byte[])} reads one RFC 8259 value from strict UTF-8 and nothing after it, refuses a
 * duplicate object key, and keeps an integer literal exact: an integer that fits {@code long} becomes a
 * {@link Long}, any other number a {@link BigDecimal}, so {@link #int64(JsonObject, String)} accepts only
 * an integer literal in range. {@link #write(JsonElement)} writes compact JSON in the tree's own member
 * order without HTML escaping, which is the token form of SPEC 11.1. Every decoding failure is an {@link
 * lol.trq.alts.AltsException} of kind {@code PROTOCOL} whose message names a field, never a value.
 *
 * @author trq
 * @since 1.0.0
 */
public final class AvpJson {

    private static final Pattern INTEGER = Pattern.compile("-?(0|[1-9][0-9]*)");
    private static final int MAX_DEPTH = 64;
    private static final Gson WRITER =
            new GsonBuilder().disableHtmlEscaping().serializeNulls().create();

    private AvpJson() {}

    /**
     * Parses strict UTF-8 JSON.
     *
     * @param utf8 the bytes
     * @return the value
     * @throws lol.trq.alts.AltsException of kind {@code PROTOCOL} if the bytes are not one strict JSON
     *     value in UTF-8, or an object repeats a key
     */
    public static JsonElement parse(byte[] utf8) {
        String text;
        try {
            text = StandardCharsets.UTF_8
                    .newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(utf8))
                    .toString();
        } catch (CharacterCodingException e) {
            throw AvpFailures.protocol("JSON is not UTF-8");
        }
        try (JsonReader reader = new JsonReader(new StringReader(text))) {
            reader.setStrictness(Strictness.STRICT);
            JsonElement value = read(reader, 0);
            if (reader.peek() != JsonToken.END_DOCUMENT) {
                throw AvpFailures.protocol("JSON has data after its value");
            }
            return value;
        } catch (IOException | IllegalStateException | NumberFormatException e) {
            throw AvpFailures.protocol("JSON does not parse");
        }
    }

    private static JsonElement read(JsonReader reader, int depth) throws IOException {
        if (depth > MAX_DEPTH) {
            throw AvpFailures.protocol("JSON is nested too deeply");
        }
        switch (reader.peek()) {
            case BEGIN_OBJECT -> {
                JsonObject object = new JsonObject();
                reader.beginObject();
                while (reader.hasNext()) {
                    String name = reader.nextName();
                    if (object.has(name)) {
                        throw AvpFailures.protocol("a JSON object repeats a key");
                    }
                    object.add(name, read(reader, depth + 1));
                }
                reader.endObject();
                return object;
            }
            case BEGIN_ARRAY -> {
                JsonArray array = new JsonArray();
                reader.beginArray();
                while (reader.hasNext()) {
                    array.add(read(reader, depth + 1));
                }
                reader.endArray();
                return array;
            }
            case STRING -> {
                return new JsonPrimitive(reader.nextString());
            }
            case NUMBER -> {
                return number(reader.nextString());
            }
            case BOOLEAN -> {
                return new JsonPrimitive(reader.nextBoolean());
            }
            case NULL -> {
                reader.nextNull();
                return JsonNull.INSTANCE;
            }
            default -> throw AvpFailures.protocol("JSON does not parse");
        }
    }

    private static JsonPrimitive number(String literal) {
        if (INTEGER.matcher(literal).matches()) {
            BigInteger value = new BigInteger(literal);
            if (value.bitLength() < 64) {
                return new JsonPrimitive(value.longValue());
            }
        }
        return new JsonPrimitive(new BigDecimal(literal));
    }

    /**
     * Writes compact JSON, members in the tree's order, without HTML escaping.
     *
     * @param value the value
     * @return the UTF-8 bytes
     */
    public static byte[] write(JsonElement value) {
        return WRITER.toJson(value).getBytes(StandardCharsets.UTF_8);
    }

    /**
     * The value as an object.
     *
     * @param value the value
     * @param what what it should be, for the failure message
     * @return the object
     * @throws lol.trq.alts.AltsException of kind {@code PROTOCOL} if it is not an object
     */
    public static JsonObject object(JsonElement value, String what) {
        if (value == null || !value.isJsonObject()) {
            throw AvpFailures.protocol(what + " is not a JSON object");
        }
        return value.getAsJsonObject();
    }

    /**
     * The value as an array.
     *
     * @param value the value
     * @param what what it should be, for the failure message
     * @return the array
     * @throws lol.trq.alts.AltsException of kind {@code PROTOCOL} if it is not an array
     */
    public static JsonArray array(JsonElement value, String what) {
        if (value == null || !value.isJsonArray()) {
            throw AvpFailures.protocol(what + " is not a JSON array");
        }
        return value.getAsJsonArray();
    }

    /**
     * A member that must be present (and not {@code null}).
     *
     * @param object the object
     * @param key the member name
     * @return the value
     * @throws lol.trq.alts.AltsException of kind {@code PROTOCOL} if it is absent or null
     */
    public static JsonElement required(JsonObject object, String key) {
        JsonElement value = object.get(key);
        if (value == null || value.isJsonNull()) {
            throw AvpFailures.protocol("the field " + key + " is missing");
        }
        return value;
    }

    /**
     * A member that may be absent; {@code null} counts as absent.
     *
     * @param object the object
     * @param key the member name
     * @return the value, if present
     */
    public static Optional<JsonElement> optional(JsonObject object, String key) {
        JsonElement value = object.get(key);
        return value == null || value.isJsonNull() ? Optional.empty() : Optional.of(value);
    }

    /**
     * A required string member.
     *
     * @param object the object
     * @param key the member name
     * @return the string
     * @throws lol.trq.alts.AltsException of kind {@code PROTOCOL} if it is absent or not a string
     */
    public static String string(JsonObject object, String key) {
        return string(required(object, key), key);
    }

    /**
     * A value that must be a string.
     *
     * @param value the value
     * @param what what it is, for the failure message
     * @return the string
     * @throws lol.trq.alts.AltsException of kind {@code PROTOCOL} if it is not a string
     */
    public static String string(JsonElement value, String what) {
        if (!value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString()) {
            throw AvpFailures.protocol("the field " + what + " is not a string");
        }
        return value.getAsString();
    }

    /**
     * A required int64 member, written as an integer literal.
     *
     * @param object the object
     * @param key the member name
     * @return the integer
     * @throws lol.trq.alts.AltsException of kind {@code PROTOCOL} if it is absent, not an integer
     *     literal, or out of the int64 range
     */
    public static long int64(JsonObject object, String key) {
        JsonElement value = required(object, key);
        if (value.isJsonPrimitive() && value.getAsJsonPrimitive().isNumber()) {
            Number n = value.getAsNumber();
            if (n instanceof Long || n instanceof Integer || n instanceof Short || n instanceof Byte) {
                return n.longValue();
            }
            // A number from another parser keeps its literal: only an integer literal in range counts.
            String literal = value.getAsString();
            if (INTEGER.matcher(literal).matches()) {
                BigInteger exact = new BigInteger(literal);
                if (exact.bitLength() < 64) {
                    return exact.longValue();
                }
            }
        }
        throw AvpFailures.protocol("the field " + key + " is not an int64 integer");
    }

    /**
     * A required boolean member.
     *
     * @param object the object
     * @param key the member name
     * @return the boolean
     * @throws lol.trq.alts.AltsException of kind {@code PROTOCOL} if it is absent or not a boolean
     */
    public static boolean bool(JsonObject object, String key) {
        JsonElement value = required(object, key);
        if (!value.isJsonPrimitive() || !value.getAsJsonPrimitive().isBoolean()) {
            throw AvpFailures.protocol("the field " + key + " is not a boolean");
        }
        return value.getAsBoolean();
    }

    /**
     * A required member holding canonical base64 of exactly {@code length} bytes.
     *
     * @param object the object
     * @param key the member name
     * @param length the required length
     * @return the bytes
     * @throws lol.trq.alts.AltsException of kind {@code PROTOCOL} if it is absent, not canonical base64,
     *     or of another length
     */
    public static byte[] bytes(JsonObject object, String key, int length) {
        return AvpBytes.fromBase64(string(object, key), length, "the field " + key);
    }

    /**
     * A required member holding canonical base64 of any length.
     *
     * @param object the object
     * @param key the member name
     * @return the bytes
     * @throws lol.trq.alts.AltsException of kind {@code PROTOCOL} if it is absent or not canonical
     *     base64
     */
    public static byte[] bytes(JsonObject object, String key) {
        return AvpBytes.fromBase64(string(object, key), "the field " + key);
    }

    /**
     * An optional member holding canonical base64; absent is empty.
     *
     * @param object the object
     * @param key the member name
     * @return the bytes, empty when absent
     */
    public static byte[] optionalBytes(JsonObject object, String key) {
        Optional<JsonElement> value = optional(object, key);
        return value.isEmpty() ? new byte[0] : AvpBytes.fromBase64(string(value.get(), key), "the field " + key);
    }
}

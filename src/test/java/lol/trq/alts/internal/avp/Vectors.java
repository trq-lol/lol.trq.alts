package lol.trq.alts.internal.avp;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

/** Loads the vendored AVP 0.5 vectors ({@code src/test/resources/avp-vectors}) and decodes their values. */
final class Vectors {

    private static final HexFormat HEX = HexFormat.of();

    private Vectors() {}

    static JsonObject load(String file) {
        try (InputStream in = Vectors.class.getResourceAsStream("/avp-vectors/" + file)) {
            Objects.requireNonNull(in, "missing vendored vector " + file);
            return JsonParser.parseReader(new InputStreamReader(in, StandardCharsets.UTF_8))
                    .getAsJsonObject();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * The objects of an array, asserting how many there are, so a case added upstream (or one this copy
     * lost) fails the test instead of going unchecked.
     */
    static List<JsonObject> cases(JsonObject root, String key, int expectedCount) {
        JsonArray array = root.getAsJsonArray(key);
        assertEquals(expectedCount, array.size(), key + " case count");
        List<JsonObject> out = new ArrayList<>();
        for (JsonElement e : array) {
            out.add(e.getAsJsonObject());
        }
        return out;
    }

    static byte[] hex(JsonObject o, String key) {
        return HEX.parseHex(o.get(key).getAsString());
    }

    static byte[] hex(String s) {
        return HEX.parseHex(s);
    }

    static String hex(byte[] b) {
        return HEX.formatHex(b);
    }

    static byte[] b64(JsonObject o, String key) {
        return Base64.getDecoder().decode(o.get(key).getAsString());
    }

    static byte[] b64(String s) {
        return Base64.getDecoder().decode(s);
    }

    static String str(JsonObject o, String key) {
        return o.get(key).getAsString();
    }

    static JsonObject obj(JsonObject o, String key) {
        return o.getAsJsonObject(key);
    }

    /** A member, host or owner of the {@code manifest.json} seeds by its label. */
    static JsonObject seedOf(String label) {
        JsonObject seeds = load("manifest.json").getAsJsonObject("seeds");
        if (label.equals("owner")) {
            return seeds.getAsJsonObject("owner");
        }
        for (String list : List.of("members", "hosts")) {
            for (JsonElement e : seeds.getAsJsonArray(list)) {
                if (e.getAsJsonObject().get("label").getAsString().equals(label)) {
                    return e.getAsJsonObject();
                }
            }
        }
        throw new IllegalArgumentException(label);
    }
}

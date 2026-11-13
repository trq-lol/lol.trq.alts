package lol.trq.alts.internal.avp;

import static lol.trq.alts.internal.avp.Vectors.str;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.internal.avp.Payload.Stamp;
import org.junit.jupiter.api.Test;

/**
 * {@code merge.json} (SPEC 5, 5.1): every case merged in every order of its inputs gives the expected
 * payload; merging the expected payload with any input or itself gives it again; merge is associative;
 * the deletion state of each account is as expected; the strip cases drop {@code refreshToken} and
 * {@code expiresAt} with their stamps. The {@code hlc} cases pin the clock step by step.
 */
class MergeVectorsTest {

    private static final JsonObject ROOT = Vectors.load("merge.json");

    private static Payload payload(JsonElement json) {
        // Through the library's own strict reader, as a decrypted plaintext would come.
        return Payload.parse(AvpJson.write(json));
    }

    private static JsonElement normal(JsonElement json) {
        return AvpJson.parse(AvpJson.write(json));
    }

    private static Payload finish(boolean strip, Payload p) {
        return strip ? p.stripRefresh() : p;
    }

    private static <T> List<List<T>> permutations(List<T> xs) {
        if (xs.isEmpty()) {
            return List.of(List.of());
        }
        List<List<T>> out = new ArrayList<>();
        for (int i = 0; i < xs.size(); i++) {
            List<T> rest = new ArrayList<>(xs);
            T head = rest.remove(i);
            for (List<T> p : permutations(rest)) {
                List<T> one = new ArrayList<>();
                one.add(head);
                one.addAll(p);
                out.add(one);
            }
        }
        return out;
    }

    @Test
    void everyCaseMergesToItsExpectedPayloadInEveryOrder() {
        int permutationsChecked = 0;
        for (JsonObject c : Vectors.cases(ROOT, "cases", 9)) {
            String name = str(c, "name");
            boolean strip = c.has("stripRefresh") && c.get("stripRefresh").getAsBoolean();
            List<Payload> inputs = new ArrayList<>();
            for (JsonElement e : c.getAsJsonArray("inputs")) {
                inputs.add(payload(e));
            }
            assertTrue(inputs.size() >= 2, name);
            JsonElement expectedJson = normal(c.get("expected"));
            Payload expected = payload(c.get("expected"));
            assertEquals(expectedJson, expected.toJson(), name + " expected round trip");

            for (List<Payload> perm : permutations(inputs)) {
                assertEquals(expectedJson, finish(strip, Payload.merge(perm)).toJson(), name + " permutation");
                permutationsChecked++;
            }
            List<Payload> withExpected = new ArrayList<>(inputs);
            withExpected.add(expected);
            for (Payload input : withExpected) {
                assertEquals(
                        expectedJson,
                        finish(strip, Payload.merge(List.of(expected, input))).toJson(),
                        name);
                assertEquals(
                        expectedJson,
                        finish(strip, Payload.merge(List.of(input, expected))).toJson(),
                        name);
            }
            for (Payload input : inputs) {
                assertEquals(
                        Payload.merge(List.of(input)).toJson(),
                        Payload.merge(List.of(input, input)).toJson(),
                        name + " self merge");
            }
            for (Payload a : inputs) {
                for (Payload b : inputs) {
                    for (Payload d : inputs) {
                        JsonObject left = Payload.merge(List.of(Payload.merge(List.of(a, b)), d))
                                .toJson();
                        JsonObject right = Payload.merge(List.of(a, Payload.merge(List.of(b, d))))
                                .toJson();
                        assertEquals(left, right, name + " associative");
                        assertEquals(left, Payload.merge(List.of(a, b, d)).toJson(), name + " associative flat");
                    }
                }
            }

            Payload merged = finish(strip, Payload.merge(inputs));
            JsonObject wantDeleted = c.getAsJsonObject("expectedDeleted");
            assertEquals(
                    new TreeSet<>(wantDeleted.keySet()),
                    new TreeSet<>(merged.accounts().keySet()),
                    name);
            for (Map.Entry<String, JsonElement> e : wantDeleted.entrySet()) {
                assertEquals(
                        e.getValue().getAsBoolean(),
                        merged.accounts().get(e.getKey()).isDeleted(),
                        name + " deleted " + e.getKey());
            }

            if (strip) {
                Payload unstripped = Payload.merge(inputs);
                assertTrue(hasAny(unstripped), name + " the unstripped merge carries a refresh field");
                assertFalse(hasAny(merged), name + " the stripped merge carries none");
                assertEquals(merged.toJson(), unstripped.underPolicy(false).toJson(), name);
                assertEquals(unstripped.toJson(), unstripped.underPolicy(true).toJson(), name);
            }
        }
        assertEquals(2 + 6 + 2 + 2 + 2 + 6 + 2 + 2 + 2, permutationsChecked, "every permutation of every case");
    }

    @Test
    void stripThenDeletedTurnsALiveAccountDeleted() {
        JsonObject c = Vectors.cases(ROOT, "cases", 9).stream()
                .filter(x -> str(x, "name").equals("strip-then-deleted"))
                .findFirst()
                .orElseThrow();
        List<Payload> inputs = new ArrayList<>();
        c.getAsJsonArray("inputs").forEach(e -> inputs.add(payload(e)));
        String uuid = c.getAsJsonObject("expectedDeleted").keySet().iterator().next();
        Payload unstripped = Payload.merge(inputs);
        assertFalse(unstripped.accounts().get(uuid).isDeleted(), "live before the strip");
        assertTrue(unstripped.stripRefresh().accounts().get(uuid).isDeleted(), "deleted after it");
    }

    @Test
    void theClockFollowsEveryStep() {
        int steps = 0;
        for (JsonObject h : Vectors.cases(ROOT, "hlc", 3)) {
            String name = str(h, "name");
            JsonObject start = h.getAsJsonObject("start");
            Hlc clock = new Hlc(start.get("at").getAsLong(), start.get("n").getAsLong());
            for (JsonElement e : h.getAsJsonArray("steps")) {
                JsonObject step = e.getAsJsonObject();
                JsonObject expect = step.getAsJsonObject("expect");
                if (str(step, "op").equals("tick")) {
                    Stamp s = clock.tick(step.get("now").getAsLong(), "by");
                    assertEquals(expect.get("at").getAsLong(), s.at(), name);
                    assertEquals(expect.get("n").getAsLong(), s.n(), name);
                } else {
                    assertEquals("observe", str(step, "op"));
                    JsonObject st = step.getAsJsonObject("stamp");
                    clock.observe(
                            new Stamp(st.get("at").getAsLong(), st.get("n").getAsLong(), str(st, "by")));
                }
                assertEquals(expect.get("at").getAsLong(), clock.at(), name);
                assertEquals(expect.get("n").getAsLong(), clock.n(), name);
                steps++;
            }
        }
        assertEquals(4 + 6 + 2, steps);
    }

    @Test
    void observingAPayloadMakesTheNextTickGreaterThanEveryStampInIt() {
        for (JsonObject c : Vectors.cases(ROOT, "cases", 9)) {
            for (JsonElement e : c.getAsJsonArray("inputs")) {
                Payload p = payload(e);
                Hlc clock = new Hlc(0, 0);
                clock.observeAll(p);
                Stamp next = clock.tick(0, "");
                p.accounts().values().forEach(a -> {
                    a.deleted().ifPresent(d -> assertTrue(next.compareTo(d) > 0));
                    a.fields().values().forEach(f -> assertTrue(next.compareTo(f.stamp()) > 0));
                    a.bans().values().forEach(f -> assertTrue(next.compareTo(f.stamp()) > 0));
                });
            }
        }
    }

    @Test
    void stampsCompareByByAsUtf8BytesNotUtf16() {
        // U+FB01 is ef ac 81 in UTF-8 and U+1F600 is f0 9f 98 80: the emoji is greater by bytes, while a
        // UTF-16 compare (fb01 against d83d) would pick the ligature.
        assertTrue(new Stamp(1, 0, "😀").compareTo(new Stamp(1, 0, "ﬁ")) > 0);
        assertTrue(new Stamp(1, 0, "a").compareTo(new Stamp(1, 0, "Z")) > 0);
        assertTrue(new Stamp(1, 1, "A").compareTo(new Stamp(1, 0, "z")) > 0, "n before by");
        assertTrue(new Stamp(2, 0, "A").compareTo(new Stamp(1, 9, "z")) > 0, "at before n");
    }

    @Test
    void aPayloadOfAnotherShapeOrVersionIsUnreadable() {
        for (String bad : new String[] {
            "{\"v\":1,\"accounts\":{}}",
            "{\"accounts\":{}}",
            "{\"v\":2}",
            "{\"v\":2.0,\"accounts\":{}}",
            "{\"v\":2,\"accounts\":[]}",
            "{\"v\":2,\"accounts\":{\"u\":{\"fields\":{\"username\":{\"value\":1}}}}}",
            "{\"v\":2,\"v\":2,\"accounts\":{}}",
            "[]"
        }) {
            AltsException e =
                    assertThrows(AltsException.class, () -> Payload.parse(bad.getBytes(StandardCharsets.UTF_8)), bad);
            assertEquals(Kind.PROTOCOL, e.kind(), bad);
        }
        assertEquals(
                "{\"v\":2,\"accounts\":{}}",
                new String(
                        Payload.parse("{\"v\":2,\"accounts\":{}}".getBytes(StandardCharsets.UTF_8))
                                .encode(),
                        StandardCharsets.UTF_8));
    }

    @Test
    void aPayloadNeverPrintsAValue() {
        String json = "{\"v\":2,\"accounts\":{\"u\":{\"fields\":{\"accessToken\":"
                + "{\"value\":\"secret-token-value\",\"at\":1,\"n\":0,\"by\":\"x\"}},\"bans\":{}}}}";
        Payload p = Payload.parse(json.getBytes(StandardCharsets.UTF_8));
        assertFalse(p.toString().contains("secret-token-value"));
        assertFalse(p.accounts().get("u").toString().contains("secret-token-value"));
        assertFalse(p.accounts().get("u").fields().get("accessToken").toString().contains("secret-token-value"));
    }

    private static boolean hasAny(Payload p) {
        return p.accounts().values().stream()
                .anyMatch(a -> Payload.REFRESH_FIELDS.stream().anyMatch(a.fields()::containsKey));
    }
}

package lol.trq.alts.internal.avp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.google.gson.JsonObject;
import java.nio.charset.StandardCharsets;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure.Kind;
import org.junit.jupiter.api.Test;

/**
 * The strict reader every AVP item goes through: one JSON value in strict UTF-8, nothing after it, no
 * repeated key, and int64 only for an integer literal in range.
 */
class AvpJsonTest {

    private static void refused(byte[] input, String what) {
        AltsException e = assertThrows(AltsException.class, () -> AvpJson.parse(input), what);
        assertEquals(Kind.PROTOCOL, e.kind(), what);
    }

    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void dataAfterTheValueIsRefused() {
        refused(utf8("{}x"), "a stray character");
        refused(utf8("{} {}"), "a second value");
        assertEquals(new JsonObject(), AvpJson.parse(utf8(" {} \n")), "whitespace around one value is fine");
    }

    @Test
    void bytesThatAreNotUtf8AreRefused() {
        refused(new byte[] {'"', (byte) 0xff, '"'}, "a 0xff byte");
        refused(new byte[] {'"', (byte) 0xc0, (byte) 0xaf, '"'}, "the overlong encoding of /");
    }

    @Test
    void anInt64OutOfRangeIsRefusedAndTheBoundsAreKept() {
        for (String bad : new String[] {"9223372036854775808", "-9223372036854775809", "1.0", "1e2"}) {
            JsonObject o = AvpJson.object(AvpJson.parse(utf8("{\"n\":" + bad + "}")), "o");
            AltsException e = assertThrows(AltsException.class, () -> AvpJson.int64(o, "n"), bad);
            assertEquals(Kind.PROTOCOL, e.kind(), bad);
        }
        assertEquals(
                Long.MAX_VALUE,
                AvpJson.int64(AvpJson.object(AvpJson.parse(utf8("{\"n\":9223372036854775807}")), "o"), "n"));
        assertEquals(
                Long.MIN_VALUE,
                AvpJson.int64(AvpJson.object(AvpJson.parse(utf8("{\"n\":-9223372036854775808}")), "o"), "n"));
    }

    @Test
    void aRepeatedKeyIsRefused() {
        refused(utf8("{\"a\":1,\"a\":1}"), "the same key twice");
        refused(utf8("{\"o\":{\"a\":1,\"b\":2,\"a\":3}}"), "a repeated key in a nested object");
    }
}

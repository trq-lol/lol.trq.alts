package lol.trq.alts.internal.vault.rpc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure.Kind;
import org.junit.jupiter.api.Test;

/**
 * The hand-written proto codec against the AVP {@code grpc.json} vectors: every request and reply body of
 * {@code avp.Vault} encodes to the vector's bytes and decodes back to its full JSON form, and a malformed
 * message is a protocol failure, never a raw exception.
 */
class ProtoJsonVectorsTest {

    private static final HexFormat HEX = HexFormat.of();

    private static List<JsonObject> cases() throws IOException {
        try (InputStream in = ProtoJsonVectorsTest.class.getResourceAsStream("/avp-vectors/grpc.json")) {
            Objects.requireNonNull(in, "missing vendored vector grpc.json");
            JsonObject root = JsonParser.parseReader(new InputStreamReader(in, StandardCharsets.UTF_8))
                    .getAsJsonObject();
            JsonArray array = root.getAsJsonArray("cases");
            assertEquals(18, array.size(), "grpc.json case count");
            List<JsonObject> out = new ArrayList<>();
            for (JsonElement e : array) {
                out.add(e.getAsJsonObject());
            }
            return out;
        }
    }

    private static JsonObject vector(String name) throws IOException {
        return cases().stream()
                .filter(c -> c.get("name").getAsString().equals(name))
                .findFirst()
                .orElseThrow();
    }

    private static void assertProtocol(String message, String hex) {
        AltsException e = assertThrows(AltsException.class, () -> ProtoJson.decode(message, HEX.parseHex(hex)));
        assertEquals(Kind.PROTOCOL, e.kind());
    }

    @Test
    void everyCaseEncodesToItsBytes() throws IOException {
        for (JsonObject c : cases()) {
            String name = c.get("name").getAsString();
            byte[] bytes = ProtoJson.encode(c.get("message").getAsString(), c.getAsJsonObject("json"));
            assertEquals(c.get("protoHex").getAsString(), HEX.formatHex(bytes), name);
        }
    }

    @Test
    void everyCaseDecodesToItsJson() throws IOException {
        for (JsonObject c : cases()) {
            String name = c.get("name").getAsString();
            JsonObject json = ProtoJson.decode(
                    c.get("message").getAsString(),
                    HEX.parseHex(c.get("protoHex").getAsString()));
            assertEquals(c.getAsJsonObject("json"), json, name);
            assertEquals(
                    new ArrayList<>(c.getAsJsonObject("json").keySet()),
                    new ArrayList<>(json.keySet()),
                    name + " member order");
        }
    }

    @Test
    void unknownFieldsAreSkipped() throws IOException {
        JsonObject c = vector("push-response");
        // field 15, varint 1; field 14, fixed64; field 13, length 2; field 12, fixed32
        String extra = "7801" + "710102030405060708" + "6a02abcd" + "6501020304";
        JsonObject json = ProtoJson.decode(
                "avp.PushResponse", HEX.parseHex(c.get("protoHex").getAsString() + extra));
        assertEquals(c.getAsJsonObject("json"), json);
    }

    @Test
    void aWrongWireTypeIsProtocol() {
        assertProtocol("avp.HostInfo", "0801");
        assertProtocol("avp.AuthToken", "1203616263");
    }

    @Test
    void aTruncatedMessageIsProtocol() throws IOException {
        String hex = vector("host-info").get("protoHex").getAsString();
        assertProtocol("avp.HostInfo", hex.substring(0, hex.length() - 2));
        assertProtocol("avp.AuthToken", "10");
        assertProtocol("avp.AuthToken", "10a0c7");
    }

    @Test
    void anOverlongVarintIsProtocol() {
        assertProtocol("avp.AuthToken", "10" + "ff".repeat(10) + "01");
        assertProtocol("avp.AuthToken", "10" + "ff".repeat(9) + "02");
    }

    @Test
    void aLengthPastTheEndIsProtocol() {
        assertProtocol("avp.HostInfo", "0a05302e35");
        assertProtocol("avp.HostInfo", "0affffffff0f302e35");
    }

    @Test
    void invalidUtf8IsProtocol() {
        assertProtocol("avp.HostInfo", "0a02c328");
    }

    @Test
    void fieldNumberZeroAndGroupsAreProtocol() {
        assertProtocol("avp.HostInfo", "0001");
        assertProtocol("avp.HostInfo", "7b7c");
    }

    @Test
    void anUnknownJsonMemberIsRefusedOnEncode() {
        JsonObject json = new JsonObject();
        json.addProperty("nonce", "x");
        json.addProperty("extra", "y");
        AltsException e = assertThrows(AltsException.class, () -> ProtoJson.encode("avp.AuthChallenge", json));
        assertEquals(Kind.INVALID_INPUT, e.kind());
    }

    @Test
    void aNegativeInt64RoundTrips() {
        JsonObject json = new JsonObject();
        json.addProperty("token", "t");
        json.addProperty("expiresAt", -1L);
        byte[] bytes = ProtoJson.encode("avp.AuthToken", json);
        assertEquals("0a0174" + "10" + "ff".repeat(9) + "01", HEX.formatHex(bytes));
        assertEquals(json, ProtoJson.decode("avp.AuthToken", bytes));
    }
}

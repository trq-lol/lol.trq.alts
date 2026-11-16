package lol.trq.alts.internal.vault;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import lol.trq.alts.spi.VaultRpcChannel.Reply;
import org.junit.jupiter.api.Test;

/** What {@link Reply} enforces of the channel contract, so a host's adapter cannot hand the library a bad one. */
class VaultRpcChannelContractTest {

    @Test
    void statusRefusesOkAndCodesOutsideOneToSixteen() {
        for (int code : new int[] {0, -1, 17}) {
            assertThrows(IllegalArgumentException.class, () -> Reply.status(code, "x", Map.of()), "code " + code);
        }
        for (int code = 1; code <= 16; code++) {
            Reply r = Reply.status(code, "x", Map.of());
            assertFalse(r.isOk());
            assertEquals(code, r.code());
        }
    }

    @Test
    void statusLowercasesKeysAndDropsBinKeys() {
        Map<String, String> trailers = new LinkedHashMap<>();
        trailers.put("Retry-After", "3");
        trailers.put("grpc-status-details-bin", "AAAA");
        trailers.put("Trace-BIN", "AAAA");
        trailers.put("avp-error-detail", "café");
        trailers.put("x-other", "kept");
        Reply r = Reply.status(9, "missing_parents", trailers);
        assertEquals(Map.of("retry-after", "3", "x-other", "kept"), r.trailers());
        assertThrows(UnsupportedOperationException.class, () -> r.trailers().put("a", "b"));
        assertEquals("missing_parents", r.statusMessage());
    }

    @Test
    void replyToStringLeavesTheMessageOut() {
        byte[] secret = "a-bearer-looking-secret".getBytes(StandardCharsets.UTF_8);
        String text = Reply.ok(secret).toString();
        assertFalse(text.contains("a-bearer-looking-secret"), text);
        assertFalse(text.contains(HexFormat.of().formatHex(secret)), text);
        assertFalse(text.contains(Base64.getEncoder().encodeToString(secret)), text);
        assertTrue(text.contains(String.valueOf(secret.length)), text);
    }

    @Test
    void aReplyIsAValueAndCopiesItsMessage() {
        byte[] bytes = {1, 2, 3};
        Reply r = Reply.ok(bytes);
        bytes[0] = 9;
        assertArrayEquals(new byte[] {1, 2, 3}, r.message());
        r.message()[1] = 9;
        assertArrayEquals(new byte[] {1, 2, 3}, r.message());
        assertTrue(r.isOk());
        assertEquals(0, r.code());
        assertEquals(Reply.ok(new byte[] {1, 2, 3}), r);
        assertEquals(Reply.ok(new byte[] {1, 2, 3}).hashCode(), r.hashCode());
        assertNotEquals(Reply.ok(new byte[] {1, 2}), r);
        assertEquals(Reply.status(5, "not_found", Map.of()), Reply.status(5, "not_found", Map.of()));
        assertNotEquals(Reply.status(5, "not_found", Map.of()), Reply.status(5, "nope", Map.of()));
        assertEquals(0, Reply.status(5, "not_found", Map.of()).message().length);
    }
}

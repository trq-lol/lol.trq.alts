package lol.trq.alts.account;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import lol.trq.alts.net.NetTestHooks;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A caller-supplied name is one path segment. Concatenated raw, a name carrying a slash or a question
 * mark addressed a different endpoint than the one asked for; these pin the encoding, on the URL that is
 * built and on the path that actually arrives.
 */
class EndpointEncodingTest {

    private LoopbackServices server;

    @BeforeEach
    void setUp() throws IOException {
        NetTestHooks.resetHttp();
        server = new LoopbackServices();
    }

    @AfterEach
    void tearDown() {
        server.close();
    }

    /** A name is one path segment: characters that mean something in a URL must not re-address the request. */
    @Test
    void aNameIsEncodedIntoThePathItIsSentIn() throws Exception {
        server.canned(200, "{\"status\":\"NOT_ALLOWED\"}");

        server.services().name().checkAvailability("a/b c?d");
        assertEquals(
                "/minecraft/profile/name/a%2Fb%20c%3Fd/available", server.last().rawPath());

        server.canned(400, "{}");
        NameChangeResult result = server.services().name().change("../../skins");
        assertEquals("PUT", server.last().method());
        assertEquals("/minecraft/profile/name/..%2F..%2Fskins", server.last().rawPath());
        assertEquals(NameChangeResult.Outcome.INVALID_NAME, result.outcome());
    }

    @Test
    void nameEndpointsEncodeTheirSegment() {
        AccountEndpoints endpoints = new AccountEndpoints("https://services.example");

        assertEquals(
                "https://services.example/minecraft/profile/name/a%2Fb%3Fc%23d%20e/available",
                endpoints.nameAvailability("a/b?c#d e"));
        assertEquals(
                "https://services.example/minecraft/profile/name/..%2F..%2Fskins", endpoints.nameChange("../../skins"));
        assertEquals("https://services.example/minecraft/profile/name/a%2Bb", endpoints.nameChange("a+b"));
        assertEquals(
                "https://services.example/minecraft/profile/name/Plain_Name1/available",
                endpoints.nameAvailability("Plain_Name1"),
                "an ordinary name is unchanged by encoding");
        assertEquals("https://services.example/minecraft/profile/name/", endpoints.nameChange(null));
    }
}

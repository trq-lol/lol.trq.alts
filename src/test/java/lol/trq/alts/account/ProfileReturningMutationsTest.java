package lol.trq.alts.account;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import lol.trq.alts.net.HttpUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The two mutations that used to return nothing. Resetting a skin and hiding a cape are answered with
 * the profile like every other mutation, so a host can update what it shows without a second request.
 */
class ProfileReturningMutationsTest {

    private static final String PROFILE = "{\"id\":\"abc\",\"name\":\"Alex\",\"skins\":[],\"capes\":[]}";

    private LoopbackServices server;

    @BeforeEach
    void setUp() throws IOException {
        HttpUtil.resetForTests();
        server = new LoopbackServices();
        server.canned(200, PROFILE);
    }

    @AfterEach
    void tearDown() {
        server.close();
    }

    @Test
    void resettingTheSkinReturnsTheProfileWhenTheServiceSendsOne() throws Exception {
        PlayerProfile profile = server.services().skin().resetToDefault();

        assertEquals("DELETE", server.last().method());
        assertEquals("/minecraft/profile/skins/active", server.last().rawPath());
        assertEquals("Alex", profile.name());

        server.canned(204, "");
        assertNull(server.services().skin().resetToDefault(), "a bodiless confirmation is null, not a failure");
        server.services().skin().reset();
        assertEquals("DELETE", server.last().method(), "the void form still works");
    }

    @Test
    void hidingTheCapeReturnsTheProfileWhenTheServiceSendsOne() throws Exception {
        PlayerProfile profile = server.services().cape().hideActive();

        assertEquals("DELETE", server.last().method());
        assertEquals("/minecraft/profile/capes/active", server.last().rawPath());
        assertEquals("Alex", profile.name());

        server.canned(204, "");
        assertNull(server.services().cape().hideActive());
        server.services().cape().hide();
        assertEquals("DELETE", server.last().method());
    }

    @Test
    void resetAndHideFailuresCarryTheirStatus() {
        server.canned(401, "{}");
        assertTrue(assertThrows(
                        AccountException.class, () -> server.services().skin().resetToDefault())
                .tokenRefused());
        assertTrue(assertThrows(
                        AccountException.class, () -> server.services().cape().hideActive())
                .tokenRefused());

        server.rateLimited(1);
        assertTrue(assertThrows(
                        AccountException.class, () -> server.services().skin().resetToDefault())
                .rateLimited());
        assertTrue(assertThrows(
                        AccountException.class, () -> server.services().cape().hideActive())
                .rateLimited());
    }
}

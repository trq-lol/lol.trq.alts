package lol.trq.alts.account;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The privacy blocklist read. Ids leave the library dashed, like every other id it hands out, whichever
 * form the service or the caller used.
 */
class BlocklistServiceTest {

    private LoopbackServices server;

    @BeforeEach
    void setUp() throws IOException {
        server = new LoopbackServices();
    }

    @AfterEach
    void tearDown() {
        server.close();
    }

    @Test
    void theBlocklistIsReadAndItsIdsAreDashed() throws Exception {
        server.canned(
                200,
                "{\"blockedProfiles\":[\"069a79f444e94726a5befca90e38aaf5\","
                        + "\"853C80EF-3C37-49FD-AA49-938B674ADAE6\"]}");

        Blocklist blocklist = server.services().blocklist().fetch();

        assertEquals("GET", server.last().method());
        assertEquals("/privacy/blocklist", server.last().rawPath());
        assertEquals("Bearer test-token", server.last().authorization());
        assertEquals(
                List.of("069a79f4-44e9-4726-a5be-fca90e38aaf5", "853c80ef-3c37-49fd-aa49-938b674adae6"),
                blocklist.blockedProfiles());
        assertTrue(blocklist.blocks("069a79f444e94726a5befca90e38aaf5"), "either form of an id is recognised");
        assertTrue(blocklist.blocks("069A79F4-44E9-4726-A5BE-FCA90E38AAF5"));
        assertFalse(blocklist.blocks("00000000-0000-0000-0000-000000000000"));
        assertFalse(blocklist.blocks(null));
        assertFalse(blocklist.isEmpty());
    }

    @Test
    void anAbsentOrEmptyBlocklistIsEmpty() throws Exception {
        server.canned(200, "{\"blockedProfiles\":[]}");
        assertTrue(server.services().blocklist().fetch().isEmpty());

        server.canned(200, "{}");
        assertTrue(server.services().blocklist().fetch().isEmpty());
    }

    @Test
    void blocklistFailuresCarryTheirStatus() {
        server.canned(401, "{}");
        assertTrue(assertThrows(
                        AccountException.class,
                        () -> server.services().blocklist().fetch())
                .tokenRefused());

        server.rateLimited(2);
        assertTrue(assertThrows(
                        AccountException.class,
                        () -> server.services().blocklist().fetch())
                .rateLimited());
    }
}

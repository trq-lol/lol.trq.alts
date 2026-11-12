package lol.trq.alts.account;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import lol.trq.alts.net.HttpUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The player-attributes read and the profanity-filter write. What these defend is the leniency: the
 * document grows upstream, so a missing block, an unknown field, or a ban scope nobody has heard of must
 * each cost only itself, and "the service did not say" must never read as "allowed".
 */
class PlayerAttributesTest {

    private static final String FULL = "{\"privileges\":{"
            + "\"onlineChat\":{\"enabled\":true},"
            + "\"multiplayerServer\":{\"enabled\":true},"
            + "\"multiplayerRealms\":{\"enabled\":false},"
            + "\"telemetry\":{\"enabled\":true},"
            + "\"optionalTelemetry\":{\"enabled\":false},"
            + "\"somethingNew\":{\"enabled\":true}},"
            + "\"profanityFilterPreferences\":{\"profanityFilterOn\":true},"
            + "\"friendsPreferences\":{\"friendsEnabledPreference\":\"ENABLED\",\"nested\":{\"ignored\":1}},"
            + "\"chatPreferences\":{\"textCommunicationEnabledPreference\":\"DISABLED\"},"
            + "\"banStatus\":{\"bannedScopes\":{}},"
            + "\"aBlockAddedLater\":{\"x\":1}}";

    private LoopbackServices server;

    @BeforeEach
    void setUp() throws IOException {
        HttpUtil.resetForTests();
        server = new LoopbackServices();
    }

    @AfterEach
    void tearDown() {
        server.close();
    }

    @Test
    void readsPrivilegesPreferencesAndAnEmptyBanStatus() throws Exception {
        server.canned(200, FULL);

        PlayerAttributes attributes = server.services().attributes().fetch();

        assertEquals("GET", server.last().method());
        assertEquals("/player/attributes", server.last().rawPath());
        assertEquals("Bearer test-token", server.last().authorization());
        assertTrue(attributes.canChat());
        assertTrue(attributes.canPlayMultiplayer());
        assertFalse(attributes.canPlayRealms());
        assertEquals(Boolean.TRUE, attributes.privileges().telemetry());
        assertEquals(Boolean.FALSE, attributes.privileges().optionalTelemetry());
        assertEquals(Boolean.TRUE, attributes.profanityFilter());
        assertEquals("ENABLED", attributes.friendsPreferences().get("friendsEnabledPreference"));
        assertFalse(attributes.friendsPreferences().containsKey("nested"), "only primitive preferences are kept");
        assertEquals("DISABLED", attributes.chatPreferences().get("textCommunicationEnabledPreference"));
        assertFalse(attributes.banned());
    }

    @Test
    void everyBlockIsOptional() throws Exception {
        server.canned(200, "{}");

        PlayerAttributes attributes = server.services().attributes().fetch();

        assertNotNull(attributes.privileges());
        assertNull(attributes.privileges().onlineChat(), "an unstated privilege is unknown, not false");
        assertNull(attributes.profanityFilter());
        assertTrue(attributes.friendsPreferences().isEmpty());
        assertTrue(attributes.chatPreferences().isEmpty());
        assertFalse(attributes.banned());
        assertFalse(attributes.canChat(), "a privilege the service did not grant is not assumed");
        assertFalse(attributes.canPlayMultiplayer());
    }

    @Test
    void blocksOfTheWrongShapeCostOnlyThemselves() throws Exception {
        server.canned(
                200,
                "{\"privileges\":\"nope\",\"profanityFilterPreferences\":{\"profanityFilterOn\":\"yes\"},"
                        + "\"banStatus\":[],\"chatPreferences\":{\"a\":\"b\"}}");

        PlayerAttributes attributes = server.services().attributes().fetch();

        assertNull(attributes.privileges().multiplayerServer());
        assertNull(attributes.profanityFilter(), "a non-boolean flag is unreadable, not true");
        assertFalse(attributes.banned());
        assertEquals("b", attributes.chatPreferences().get("a"));
    }

    @Test
    void bansAreReadPerScopeAndUnknownScopesAreKept() throws Exception {
        server.canned(
                200,
                "{\"privileges\":{\"multiplayerServer\":{\"enabled\":true},\"onlineChat\":{\"enabled\":true}},"
                        + "\"banStatus\":{\"bannedScopes\":{"
                        + "\"MULTIPLAYER\":{\"banId\":\"ban-1\",\"expires\":\"2030-01-01T00:00:00Z\","
                        + "\"reason\":\"hate_speech\",\"reasonMessage\":\"Message\"},"
                        + "\"A_SCOPE_FROM_THE_FUTURE\":{\"banId\":\"ban-2\",\"expires\":null,\"reason\":\"other\"}}}}");

        PlayerAttributes attributes = server.services().attributes().fetch();

        assertTrue(attributes.banned());
        PlayerAttributes.Ban multiplayer = attributes.ban(PlayerAttributes.SCOPE_MULTIPLAYER);
        assertEquals("ban-1", multiplayer.banId());
        assertEquals(Instant.parse("2030-01-01T00:00:00Z"), multiplayer.expires());
        assertEquals("hate_speech", multiplayer.reason());
        assertEquals("Message", multiplayer.reasonMessage());
        assertFalse(multiplayer.permanent());
        assertTrue(multiplayer.activeAt(Instant.parse("2029-12-31T00:00:00Z")));
        assertFalse(multiplayer.activeAt(Instant.parse("2030-01-02T00:00:00Z")));

        PlayerAttributes.Ban unknown = attributes.ban("A_SCOPE_FROM_THE_FUTURE");
        assertNotNull(unknown, "a scope this release does not know is kept, not dropped");
        assertTrue(unknown.permanent(), "a null expiry is a ban with no stated end");
        assertNull(unknown.reasonMessage());
        assertTrue(attributes.bannedAt(Instant.parse("2040-01-01T00:00:00Z")), "the permanent ban still holds");

        assertFalse(attributes.canPlayMultiplayer(), "an enabled privilege does not outrank a multiplayer ban");
        assertTrue(attributes.canChat());
        assertNull(attributes.ban("NOT_BANNED_HERE"));
    }

    @Test
    void anExpiredBanIsListedButNoLongerActive() throws Exception {
        server.canned(
                200,
                "{\"banStatus\":{\"bannedScopes\":{\"MULTIPLAYER\":{\"banId\":\"b\",\"expires\":1577836800000}}}}");

        PlayerAttributes attributes = server.services().attributes().fetch();

        assertTrue(attributes.banned());
        assertEquals(
                Instant.parse("2020-01-01T00:00:00Z"),
                attributes.ban(PlayerAttributes.SCOPE_MULTIPLAYER).expires(),
                "an expiry given as epoch milliseconds is read too");
        assertFalse(attributes.bannedAt(Instant.parse("2021-01-01T00:00:00Z")));
    }

    @Test
    void settingTheProfanityFilterPostsThePreferenceAndReturnsTheUpdatedAttributes() throws Exception {
        server.canned(200, "{\"profanityFilterPreferences\":{\"profanityFilterOn\":false}}");

        PlayerAttributes attributes = server.services().attributes().setProfanityFilter(false);

        assertEquals("POST", server.last().method());
        assertEquals("/player/attributes", server.last().rawPath());
        assertEquals(
                "{\"profanityFilterPreferences\":{\"profanityFilterOn\":false}}",
                server.last().bodyText());
        assertTrue(server.last().contentType().startsWith("application/json"));
        assertEquals(Boolean.FALSE, attributes.profanityFilter());

        server.services().attributes().setProfanityFilter(true);
        assertEquals(
                "{\"profanityFilterPreferences\":{\"profanityFilterOn\":true}}",
                server.last().bodyText());
    }

    @Test
    void aRefusedTokenIsAnExceptionCarryingItsStatus() {
        server.canned(
                401, "{\"path\":\"/player/attributes\",\"error\":\"UNAUTHORIZED\",\"errorMessage\":\"Bad token\"}");

        AccountException read = assertThrows(
                AccountException.class, () -> server.services().attributes().fetch());
        AccountException write = assertThrows(
                AccountException.class, () -> server.services().attributes().setProfanityFilter(true));

        assertEquals(401, read.status());
        assertTrue(read.tokenRefused());
        assertTrue(read.getMessage().contains("Bad token"));
        assertTrue(write.tokenRefused());
    }

    @Test
    void aRateLimitCarriesTheWaitTheServiceAskedFor() {
        server.rateLimited(7);

        AccountException read = assertThrows(
                AccountException.class, () -> server.services().attributes().fetch());
        AccountException write = assertThrows(
                AccountException.class, () -> server.services().attributes().setProfanityFilter(true));

        assertTrue(read.rateLimited());
        assertEquals(Duration.ofSeconds(7), read.retryAfter());
        assertTrue(write.rateLimited());
    }

    @Test
    void aWriteAnsweredWithNoBodyIsAFailureRatherThanEmptyAttributes() {
        server.canned(204, "");

        assertThrows(
                AccountException.class, () -> server.services().attributes().setProfanityFilter(true));
    }
}

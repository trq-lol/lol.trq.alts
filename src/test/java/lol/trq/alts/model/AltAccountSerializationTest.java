package lol.trq.alts.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.Gson;
import java.util.Map;
import lol.trq.alts.internal.store.AltAccountJson;
import org.junit.jupiter.api.Test;

class AltAccountSerializationTest {

    /** The library's own: an account goes through its record form, never its final fields. */
    private final Gson gson = AltAccountJson.gson();

    /**
     * The record form writes every field under its name, in the order the store file has always had,
     * leaving out the nulls.
     */
    @Test
    void writesTheFieldsInTheStoreFileOrder() {
        AltAccount full = AltAccount.builder("u", "Alex", "a", AccountType.MICROSOFT)
                .lastUsed(1L)
                .lastUsedBy("m")
                .bans(Map.of("example.net", new BanInfo(true, 2L, "kick", "d", "m")))
                .sourceClient("c")
                .sourceUser("s")
                .refreshToken("r")
                .expiresAt(3L)
                .build();

        assertEquals(
                "{\"uuid\":\"u\",\"username\":\"Alex\",\"accessToken\":\"a\",\"type\":\"MICROSOFT\",\"lastUsed\":1,"
                        + "\"lastUsedBy\":\"m\",\"bans\":{\"example.net\":{\"banned\":true,\"observedAt\":2,"
                        + "\"source\":\"kick\",\"detail\":\"d\",\"observedBy\":\"m\"}},\"sourceClient\":\"c\","
                        + "\"sourceUser\":\"s\",\"refreshToken\":\"r\",\"expiresAt\":3}",
                gson.toJson(full));
        assertEquals(
                "{\"uuid\":\"u\",\"lastUsed\":0,\"expiresAt\":0}",
                gson.toJson(AltAccount.builder("u", null, null, null).build()));
        assertEquals("null", gson.toJson(null, AltAccount.class));
        assertNull(gson.fromJson("null", AltAccount.class));
    }

    /**
     * Gate for forward compatibility: a legacy account payload (written by an older {@code @Expose}-based
     * model) must still deserialize into the record. The field names are identical, so the only thing
     * under test is that {@code @SerializedName}-only Gson reads them.
     */
    @Test
    void parsesLegacyJsonShape() {
        String legacy =
                "{\"uuid\":\"00000000-0000-0000-0000-000000000001\",\"username\":\"Steve\",\"accessToken\":\"tok\",\"type\":\"MICROSOFT\",\"lastUsed\":1717000000000}";

        AltAccount account = gson.fromJson(legacy, AltAccount.class);

        assertEquals("00000000-0000-0000-0000-000000000001", account.uuid());
        assertEquals("Steve", account.username());
        assertEquals("tok", account.accessToken());
        assertEquals(AccountType.MICROSOFT, account.type());
        assertEquals(1717000000000L, account.lastUsed());
        assertNull(account.bans(), "legacy files predate the bans field");
        assertNull(account.sourceClient(), "legacy files predate the sourceClient field");
        assertNull(account.sourceUser(), "legacy files predate the sourceUser field");
    }

    /**
     * A payload carrying a per-server {@code bans} map but no provenance must still load: the missing
     * {@code sourceClient}/{@code sourceUser} read as null, and the bans deserialize. (Migrating the
     * older single {@code ban} object is the store's job; see AccountStoreBanMigrationTest.)
     */
    @Test
    void parsesBansWithoutProvenance() {
        String json =
                "{\"uuid\":\"u\",\"username\":\"Steve\",\"accessToken\":\"tok\",\"type\":\"MICROSOFT\",\"lastUsed\":1,\"bans\":{\"example.net\":{\"banned\":true,\"observedAt\":2,\"source\":\"self\",\"detail\":\"d\",\"observedBy\":\"m\"}}}";

        AltAccount account = gson.fromJson(json, AltAccount.class);

        assertTrue(account.banned());
        assertTrue(account.banned("example.net"));
        assertNull(account.sourceClient());
        assertNull(account.sourceUser());
    }

    @Test
    void withSourceSetsProvenanceAndRoundTrips() {
        AltAccount stamped =
                AltAccount.of("u", "Alex", "tok", AccountType.MICROSOFT).withSource("democlient", "user1");
        assertEquals("democlient", stamped.sourceClient());
        assertEquals("user1", stamped.sourceUser());

        AltAccount restored = gson.fromJson(gson.toJson(stamped), AltAccount.class);
        assertEquals(stamped, restored);
        assertEquals("democlient", restored.sourceClient());
        assertEquals("user1", restored.sourceUser());
    }

    @Test
    void roundTripsThroughGson() {
        AltAccount original = AltAccount.of("uuid-1", "Alex", "token-xyz", AccountType.SESSION);
        AltAccount restored = gson.fromJson(gson.toJson(original), AltAccount.class);
        assertEquals(original, restored);
    }

    @Test
    void usedNowKeepsIdentityFieldsAndAdvancesTimestamp() {
        AltAccount base = AltAccount.builder("u", "Steve", "t", AccountType.OFFLINE)
                .lastUsed(1L)
                .sourceClient("democlient")
                .sourceUser("user1")
                .build();
        AltAccount stamped = base.usedNow();

        assertEquals(base.uuid(), stamped.uuid());
        assertEquals(base.username(), stamped.username());
        assertEquals(base.accessToken(), stamped.accessToken());
        assertEquals(base.type(), stamped.type());
        assertEquals(1L, base.lastUsed());
        assertEquals("democlient", stamped.sourceClient(), "usedNow preserves provenance");
        assertEquals("user1", stamped.sourceUser(), "usedNow preserves provenance");
    }

    @Test
    void perServerBanRoundTripsAndFlagsBanned() {
        AltAccount banned = AltAccount.of("u", "Herobrine", "t", AccountType.MICROSOFT)
                .withBan("example.net", BanInfo.observed("self", "cheating"));
        assertTrue(banned.banned(), "banned on any");
        assertTrue(banned.banned("example.net"));
        assertEquals(java.util.Set.of("example.net"), banned.bannedServers());

        AltAccount restored = gson.fromJson(gson.toJson(banned), AltAccount.class);
        assertEquals(banned, restored);
        assertTrue(restored.banned("example.net"));
        assertEquals("self", restored.bans().get("example.net").source());
    }

    @Test
    void bansAreIndependentPerServer() {
        AltAccount alt = AltAccount.of("u", "Alex", "t", AccountType.MICROSOFT)
                .withBan("example.net", BanInfo.observed("self", "x"))
                .withBan("example.org", BanInfo.observed("login", "y"));

        assertTrue(alt.banned("example.net"));
        assertTrue(alt.banned("example.org"));
        assertFalse(alt.banned("unlisted.example"), "not banned on a server with no entry");
        assertEquals(java.util.Set.of("example.net", "example.org"), alt.bannedServers());

        // Clearing one server leaves the other intact.
        AltAccount cleared = alt.withBan("example.net", null);
        assertFalse(cleared.banned("example.net"));
        assertTrue(cleared.banned("example.org"));
        assertTrue(cleared.banned(), "still banned somewhere");
    }

    @Test
    void tokenFieldsDefaultToAbsentOnLegacyPayloads() {
        String legacy =
                "{\"uuid\":\"u\",\"username\":\"Steve\",\"accessToken\":\"tok\",\"type\":\"MICROSOFT\",\"lastUsed\":1}";

        AltAccount account = gson.fromJson(legacy, AltAccount.class);

        assertNull(account.refreshToken(), "legacy files predate the refreshToken field");
        assertEquals(0L, account.expiresAt(), "legacy files predate the expiresAt field");
        assertFalse(account.hasRefreshToken());
    }

    @Test
    void withTokensReplacesCredentialsAndPreservesEverythingElse() {
        AltAccount base = AltAccount.of("u", "Alex", "old-access", AccountType.MICROSOFT)
                .withSource("democlient", "user1")
                .withBan("example.net", BanInfo.observed("self", "x"));

        AltAccount renewed = base.withTokens("new-access", "new-refresh", 1717000000000L);

        assertEquals("new-access", renewed.accessToken());
        assertEquals("new-refresh", renewed.refreshToken());
        assertEquals(1717000000000L, renewed.expiresAt());
        assertTrue(renewed.hasRefreshToken());
        assertEquals("democlient", renewed.sourceClient(), "withTokens preserves provenance");
        assertEquals("user1", renewed.sourceUser(), "withTokens preserves provenance");
        assertTrue(renewed.banned("example.net"), "withTokens preserves bans");
        assertEquals(base.lastUsed(), renewed.lastUsed(), "withTokens does not restamp last-used");
    }

    @Test
    void tokenFieldsRoundTripThroughGson() {
        AltAccount original =
                AltAccount.of("u", "Alex", "access", AccountType.MICROSOFT).withTokens("access", "refresh", 42L);

        AltAccount restored = gson.fromJson(gson.toJson(original), AltAccount.class);

        assertEquals(original, restored);
        assertEquals("refresh", restored.refreshToken());
        assertEquals(42L, restored.expiresAt());
    }

    @Test
    void hasRefreshTokenRejectsBlankValues() {
        AltAccount blank =
                AltAccount.of("u", "Alex", "access", AccountType.MICROSOFT).withTokens("access", "  ", 0L);

        assertFalse(blank.hasRefreshToken(), "a blank token is not usable for renewal");
    }
}

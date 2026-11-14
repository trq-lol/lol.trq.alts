package lol.trq.alts.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.google.gson.Gson;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The records are values: what a caller built one from, and what it reads back out, cannot change it
 * afterwards. A store shares one {@link AltAccount} between threads and between the list a host renders
 * and the file it writes, so a ban map someone else still holds a reference to must not reach in.
 */
class DefensiveCopyTest {

    private static final String UUID = "00000000-0000-4000-8000-0000000000d1";

    private static AltAccount withBans(Map<String, BanInfo> bans) {
        return AltAccount.builder(UUID, "Alex", "t", AccountType.MICROSOFT)
                .lastUsed(1L)
                .bans(bans)
                .build();
    }

    @Test
    void anAccountKeepsItsOwnCopyOfTheBansItWasBuiltWith() {
        Map<String, BanInfo> bans = new LinkedHashMap<>();
        bans.put("example.net", BanInfo.observed("kick", "banned"));
        AltAccount account = withBans(bans);

        bans.clear();

        assertEquals(1, account.bans().size(), "clearing the caller's map changes nothing");
        assertThrows(UnsupportedOperationException.class, () -> account.bans().put("x", null));
    }

    @Test
    void aBuilderHandsTheAccountACopyOfItsBans() {
        Map<String, BanInfo> bans = new LinkedHashMap<>();
        bans.put("example.net", BanInfo.observed("kick", "banned"));
        AltAccount.Builder builder =
                AltAccount.builder(UUID, "Alex", "t", AccountType.MICROSOFT).bans(bans);
        AltAccount account = builder.build();

        bans.put("example.org", BanInfo.observed("kick", "banned"));

        assertEquals(1, account.bans().size(), "the map handed to the builder does not reach the account");
        assertEquals(2, builder.build().bans().size(), "a later build takes the map as it is then");
        assertThrows(
                UnsupportedOperationException.class,
                () -> account.withBan("x", null).bans().clear());
    }

    @Test
    void anAccountGsonReadKeepsItsBansReadOnly() {
        AltAccount read =
                new Gson().fromJson("{\"uuid\":\"u\",\"bans\":{\"example.net\":{\"banned\":true}}}", AltAccount.class);

        assertEquals(1, read.bans().size());
        assertThrows(UnsupportedOperationException.class, () -> read.bans().clear());
    }

    @Test
    void anAccountIsAValueOverEveryField() {
        AltAccount full = AltAccount.builder(UUID, "Alex", "t", AccountType.MICROSOFT)
                .lastUsed(1L)
                .lastUsedBy("m")
                .bans(Map.of("example.net", BanInfo.observed("kick", "banned")))
                .sourceClient("c")
                .sourceUser("u")
                .refreshToken("r")
                .expiresAt(2L)
                .build();

        assertEquals(full, full.toBuilder().build());
        assertEquals(full.hashCode(), full.toBuilder().build().hashCode());
        assertNotEquals(full, full.toBuilder().expiresAt(3L).build());
        assertNotEquals(full, full.toBuilder().lastUsedBy(null).build());
        assertNotEquals(full, full.toBuilder().bans(null).build());
        assertEquals(
                "AltAccount[uuid=" + UUID + ", username=Alex, accessToken=<redacted>, type=MICROSOFT, lastUsed=1,"
                        + " lastUsedBy=m, bans=" + full.bans() + ", sourceClient=c, sourceUser=u,"
                        + " refreshToken=<redacted>, expiresAt=2]",
                full.toString(),
                "the record's description, credentials redacted");
    }

    @Test
    void anAccountWithNoBansStillSaysSo() {
        assertNull(withBans(null).bans(), "null still means never observed banned");
    }

    @Test
    void statsKeepTheirOwnCopyOfTheChips() {
        List<GameStats.Stat> chips = new ArrayList<>(List.of(new GameStats.Stat("rank", "Veteran")));
        GameStats stats = new GameStats("example.net", "uuid-1", chips, 1L);

        chips.add(new GameStats.Stat("wins", "128"));

        assertEquals(1, stats.stats().size());
        assertThrows(UnsupportedOperationException.class, () -> stats.stats().clear());
        assertNull(new GameStats("s", "u", null, 0L).stats());
    }
}

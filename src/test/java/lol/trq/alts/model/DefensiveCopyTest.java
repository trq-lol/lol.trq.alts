package lol.trq.alts.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

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
        return new AltAccount(UUID, "Alex", "t", AccountType.MICROSOFT, 1L, null, bans, null, null, null, 0L);
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

package lol.trq.alts.store;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import lol.trq.alts.internal.store.EncryptionUtil;
import lol.trq.alts.model.AccountType;
import lol.trq.alts.model.AltAccount;
import lol.trq.alts.model.BanInfo;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The account file is the only copy of every credential the user saved, and 1.0 must read what 0.12 wrote
 * and write it back the same way. The fixture ({@code src/test/resources/store-0.12}) is the plaintext the
 * 0.12.0 {@code AltStore} wrote, captured once from the v0.12.0 sources; this test seals it as the store
 * does, loads it, and saves it again: every field must arrive, and the plaintext written back must be the
 * same bytes. A renamed field, a changed order or a different null handling fails it.
 */
class StoreFormatCompatTest {

    private static final String BINDING = "lol.trq.alts";

    @TempDir
    Path storeDir;

    @Test
    void aStoreWrittenByZeroTwelveLoadsAndSavesBackTheSameBytes() throws Exception {
        String written = fixture();
        Files.writeString(
                storeDir.resolve("accounts.dat"),
                EncryptionUtil.encrypt(written, EncryptionUtil.getHardwareKey(BINDING)));

        AccountStore store = AccountStore.open(storeDir);
        try {
            store.load();
            assertEquals(java.util.Optional.empty(), store.loadError());
            assertEquals(java.util.Optional.empty(), store.loadWarning());
            List<AltAccount> accounts = store.accounts();
            assertEquals(3, accounts.size());
            assertFull(accounts.get(0));
            assertMinimal(accounts.get(1));
            assertCookie(accounts.get(2));

            store.save();
            assertEquals(java.util.Optional.empty(), store.saveError());
            String rewritten = EncryptionUtil.decrypt(
                    Files.readString(storeDir.resolve("accounts.dat")).strip(), EncryptionUtil.getHardwareKey(BINDING));
            assertEquals(written, rewritten, "the file 1.0 writes back is the file 0.12 wrote");
        } finally {
            store.close();
        }
    }

    private static void assertFull(AltAccount a) {
        assertEquals("00000000-0000-4000-8000-000000000c01", a.uuid());
        assertEquals("FullRecord", a.username());
        assertEquals("access-token-c01", a.accessToken());
        assertEquals(AccountType.MICROSOFT, a.type());
        assertEquals(1731000000000L, a.lastUsed());
        assertEquals("member-ed25519-c01", a.lastUsedBy());
        assertEquals("democlient", a.sourceClient());
        assertEquals("user1", a.sourceUser());
        assertEquals("refresh-token-c01", a.refreshToken());
        assertEquals(1731003600000L, a.expiresAt());
        Map<String, BanInfo> bans = a.bans();
        assertEquals(List.of("example.net", "example.org"), List.copyOf(bans.keySet()));
        assertEquals(new BanInfo(true, 1731000001000L, "kick", "banned: \"x\" <&>", "m1"), bans.get("example.net"));
        assertEquals(new BanInfo(false, 1731000002000L, "self", null, null), bans.get("example.org"));
        assertTrue(a.banned("example.net"));
        assertEquals(java.util.Set.of("example.net"), a.bannedServers());
        assertThrows(UnsupportedOperationException.class, () -> a.bans().clear(), "a loaded account is a value");
    }

    private static void assertMinimal(AltAccount a) {
        assertEquals("00000000-0000-4000-8000-000000000c02", a.uuid());
        assertEquals("Offline_Name", a.username());
        assertEquals("offline", a.accessToken());
        assertEquals(AccountType.OFFLINE, a.type());
        assertEquals(1L, a.lastUsed());
        assertNull(a.lastUsedBy());
        assertNull(a.bans(), "an absent map stays absent, so it is left out again on save");
        assertNull(a.sourceClient());
        assertNull(a.sourceUser());
        assertNull(a.refreshToken());
        assertEquals(0L, a.expiresAt());
    }

    private static void assertCookie(AltAccount a) {
        assertEquals("00000000-0000-4000-8000-000000000c03", a.uuid());
        assertEquals("Ünïcødé", a.username());
        assertEquals(AccountType.COOKIE, a.type());
        assertEquals(Long.MAX_VALUE, a.lastUsed());
        assertNotNull(a.bans(), "an empty map stays an empty map, not an absent one");
        assertTrue(a.bans().isEmpty());
        assertNull(a.sourceClient());
        assertEquals("only-user", a.sourceUser());
        assertEquals(-5L, a.expiresAt());
    }

    private static String fixture() throws IOException {
        try (InputStream in = StoreFormatCompatTest.class.getResourceAsStream("/store-0.12/accounts-plaintext.json")) {
            assertNotNull(in, "the 0.12 store fixture is on the test class path");
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}

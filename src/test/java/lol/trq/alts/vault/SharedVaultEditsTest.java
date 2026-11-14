package lol.trq.alts.vault;

import static lol.trq.alts.vault.VaultWorld.await;
import static lol.trq.alts.vault.VaultWorld.failure;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.internal.avp.Payload;
import lol.trq.alts.model.AccountType;
import lol.trq.alts.model.AltAccount;
import lol.trq.alts.model.BanInfo;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Editing accounts without reverting a remote edit (AVP SPEC 5): {@link SharedVault#update}, {@link
 * SharedVault#put(AltAccount, AltAccount)}, the mapped-space comparison of {@link SharedVault#put(AltAccount)},
 * a write that changes nothing sending nothing, and the tolerant read of what another member wrote.
 */
class SharedVaultEditsTest {

    private static final String X = "00000000-0000-0000-0000-00000000000a";

    @TempDir
    Path dir;

    private record Pair(SharedVault owner, VaultIdentity bobId, SharedVault bob) {}

    private static Pair pair(VaultWorld w) throws Exception {
        OwnerIdentity ownerId = OwnerIdentity.generate();
        SharedVault owner = await(SharedVault.create(w.home(), ownerId));
        assertEquals(1, owner.snapshot().pinnedSeq(), "the genesis state is seq 1");
        VaultIdentity bobId = VaultIdentity.create("pw".toCharArray());
        RepoLocator locator = owner.locator();
        VaultHost home = await(w.alts.vault().connect(locator));
        await(owner.invite(await(SharedVault.prepareJoin(home, bobId, locator))));
        SharedVault bob = await(SharedVault.join(home, bobId, locator));
        assertEquals(2, bob.snapshot().pinnedSeq(), "the pin is the tip's manifestSeq");
        assertEquals(2, owner.snapshot().pinnedSeq());
        return new Pair(owner, bobId, bob);
    }

    private static AltAccount alpha() {
        return AltAccount.builder(X, "alpha", "tok1", AccountType.MICROSOFT)
                .lastUsed(1000L)
                .sourceClient("src")
                .sourceUser("user")
                .build();
    }

    /** The probe's scenario: Bob reads, the owner renames, Bob syncs, Bob writes new tokens on what he read. */
    private static void staleScenario(VaultWorld w, Pair p, boolean useUpdate) {
        await(p.owner().put(alpha()));
        await(p.bob().sync());
        AltAccount read = p.bob().account(X).orElseThrow();
        await(p.owner()
                .put(
                        p.owner().account(X).orElseThrow(),
                        p.owner().account(X).orElseThrow().withUsername("renamed")));
        await(p.bob().sync());
        if (useUpdate) {
            AltAccount stored = await(p.bob().update(X, a -> a.withTokens("tok2", null, 0L)));
            assertEquals("renamed", stored.username(), "update edits the account as the copy holds it");
            assertEquals("tok2", stored.accessToken());
        } else {
            await(p.bob().put(read, read.withTokens("tok2", null, 0L)));
        }
        await(p.owner().sync());
        AltAccount merged = p.owner().account(X).orElseThrow();
        assertEquals("renamed", merged.username(), "the owner's rename survives the member's edit");
        assertEquals("tok2", merged.accessToken(), "the member's edit lands");
    }

    @Test
    void anEditOfAStaleReadThroughPutKeepsTheRemoteRename() throws Exception {
        try (VaultWorld w = new VaultWorld(dir)) {
            staleScenario(w, pair(w), false);
        }
    }

    @Test
    void anUpdateKeepsTheRemoteRename() throws Exception {
        try (VaultWorld w = new VaultWorld(dir)) {
            staleScenario(w, pair(w), true);
        }
    }

    @Test
    void updateRefusesAMissingAccountAndABadResult() throws Exception {
        try (VaultWorld w = new VaultWorld(dir)) {
            Pair p = pair(w);
            assertEquals(Kind.NOT_FOUND, failure(p.owner().update(X, a -> a)).kind());
            await(p.owner().put(alpha()));
            assertEquals(
                    Kind.INVALID_INPUT, failure(p.owner().update(X, a -> null)).kind());
            AltAccount other = AltAccount.builder("00000000-0000-0000-0000-00000000000b", "b", "t", AccountType.OFFLINE)
                    .build();
            assertEquals(
                    Kind.INVALID_INPUT, failure(p.owner().update(X, a -> other)).kind());
            assertEquals(
                    Kind.INVALID_INPUT, failure(p.owner().put(alpha(), other)).kind());
            await(p.owner().remove(X));
            assertEquals(Kind.NOT_FOUND, failure(p.owner().update(X, a -> a)).kind(), "a deleted account");
        }
    }

    @Test
    void aWriteThatChangesNothingSendsNoCommit() throws Exception {
        try (VaultWorld w = new VaultWorld(dir)) {
            Pair p = pair(w);
            await(p.owner().put(alpha()));
            long pushes = w.host.count("/push");
            await(p.owner().put(alpha()));
            await(p.owner().put(alpha(), alpha()));
            assertEquals("alpha", await(p.owner().update(X, a -> a)).username());
            // Withheld, a refresh token is not a change either.
            await(p.owner().put(alpha().withTokens("tok1", "refresh", 123L)));
            assertEquals(pushes, w.host.count("/push"), "no commit for an edit that changes nothing");
            await(p.owner().update(X, a -> a.withUsername("beta")));
            assertEquals(pushes + 1, w.host.count("/push"));
        }
    }

    @Test
    void aFreshPutNeverReStampsAFieldThatReadsAsItsDefault() throws Exception {
        try (VaultWorld w = new VaultWorld(dir)) {
            Pair p = pair(w);
            // Another implementation wrote an account with no lastUsed and a type this library does not know.
            await(p.owner().engineForTests().write(e -> {
                e.setField(X, "username", new JsonPrimitive("alpha"));
                e.setField(X, "type", new JsonPrimitive("FUTURE_KIND"));
            }));
            await(p.bob().sync());
            AltAccount read = p.bob().account(X).orElseThrow();
            assertNull(read.type());
            assertEquals(0L, read.lastUsed());
            long pushes = w.host.count("/push");
            await(p.bob().put(read));
            assertEquals(pushes, w.host.count("/push"), "nothing differs in the account the copy reads as");
            await(p.bob().put(read.withUsername("beta")));
            Payload.Account stored =
                    p.bob().engineForTests().payload().accounts().get(X);
            assertEquals("FUTURE_KIND", stored.fields().get("type").value().getAsString(), "the type is kept");
            assertFalse(stored.fields().containsKey("lastUsed"), "an absent lastUsed stays absent");
        }
    }

    @Test
    void aRevivedAccountTakesTheBansItCarries() throws Exception {
        try (VaultWorld w = new VaultWorld(dir)) {
            Pair p = pair(w);
            BanInfo first = new BanInfo(true, 1L, "self", "first", null);
            BanInfo second = new BanInfo(true, 2L, "login", "second", null);
            await(p.owner().put(alpha().withBan("one.example", first)));
            await(p.owner().remove(X));
            await(p.owner().put(alpha().withBan("one.example", second)));
            await(p.bob().sync());
            assertEquals(
                    Map.of("one.example", second),
                    p.bob().account(X).orElseThrow().bans());
        }
    }

    @Test
    void anEditThatDropsABanServerClearsIt() throws Exception {
        try (VaultWorld w = new VaultWorld(dir)) {
            Pair p = pair(w);
            BanInfo ban = new BanInfo(true, 1L, "self", null, null);
            await(p.owner().put(alpha().withBan("one.example", ban).withBan("two.example", ban)));
            await(p.owner().update(X, a -> a.withBan("one.example", null)));
            await(p.bob().sync());
            assertEquals(
                    Map.of("two.example", ban), p.bob().account(X).orElseThrow().bans());
        }
    }

    @Test
    void mergeHeadsReportsWhetherItMerged() throws Exception {
        try (VaultWorld w = new VaultWorld(dir)) {
            Pair p = pair(w);
            await(p.owner().put(alpha()));
            await(p.bob().put(alpha().withUsername("bob's")));
            SyncReport report = await(p.owner().sync());
            assertTrue(report.merged(), "two heads were merged");
            assertFalse(await(p.owner().mergeHeads()), "one head: nothing to merge");
        }
    }

    @Test
    void aChangedBanOnAServerSyncsAsTheNewValue() throws Exception {
        try (VaultWorld w = new VaultWorld(dir)) {
            Pair p = pair(w);
            BanInfo first = new BanInfo(true, 1L, "self", "first", null);
            BanInfo second = new BanInfo(true, 2L, "login", "second", null);
            BanInfo third = new BanInfo(false, 3L, "login", "lifted", null);
            await(p.owner().put(alpha().withBan("one.example", first)));
            await(p.owner().update(X, a -> a.withBan("one.example", second)));
            await(p.bob().sync());
            assertEquals(
                    Map.of("one.example", second),
                    p.bob().account(X).orElseThrow().bans(),
                    "through update");
            AltAccount read = p.bob().account(X).orElseThrow();
            await(p.bob().put(read, read.withBan("one.example", third)));
            await(p.owner().sync());
            assertEquals(
                    Map.of("one.example", third),
                    p.owner().account(X).orElseThrow().bans(),
                    "through put");
        }
    }

    @Test
    void puttingBackTheReadOfARemovedAccountRevivesIt() throws Exception {
        try (VaultWorld w = new VaultWorld(dir)) {
            Pair p = pair(w);
            await(p.owner().put(alpha()));
            AltAccount read = p.owner().account(X).orElseThrow();
            await(p.owner().remove(X));
            long pushes = w.host.count("/push");
            await(p.owner().put(read, read));
            assertEquals(pushes + 1, w.host.count("/push"), "a revival is a commit, though base equals edited");
            await(p.bob().sync());
            assertEquals(read, p.bob().account(X).orElseThrow());
        }
    }

    @Test
    void aRevivalIsWrittenWholeAndDropsTheBansItDoesNotCarry() throws Exception {
        try (VaultWorld w = new VaultWorld(dir)) {
            Pair p = pair(w);
            BanInfo ban = new BanInfo(true, 1L, "self", null, null);
            AltAccount banned = alpha().withBan("one.example", ban).withBan("two.example", ban);
            // Through put(base, edited): edited carries only the second server.
            await(p.owner().put(banned));
            await(p.owner().remove(X));
            await(p.owner().put(banned, banned.withBan("one.example", null)));
            await(p.bob().sync());
            assertEquals(
                    Map.of("two.example", ban), p.bob().account(X).orElseThrow().bans());
            // Through put(account): the same, from an account carrying no ban at all.
            await(p.owner().put(banned));
            await(p.owner().remove(X));
            await(p.owner().put(alpha()));
            await(p.bob().sync());
            assertNull(p.bob().account(X).orElseThrow().bans(), "no pre-deletion ban comes back");
        }
    }

    @Test
    void aLocatorWithAPathUserinfoOrQueryIsRefused() throws Exception {
        try (VaultWorld w = new VaultWorld(dir)) {
            for (String bad : List.of(
                    // Loopback names, so a locator check that let one through would fail fast, not reach out.
                    "127.0.0.1/path",
                    "user@127.0.0.1",
                    "127.0.0.1?x=1",
                    "127.0.0.1#f",
                    "127.0.0.1:",
                    "http://127.0.0.1",
                    "-localhost")) {
                AltsException e = failure(w.alts.vault().connectFirstContact(bad));
                assertEquals(Kind.INVALID_INPUT, e.kind(), bad);
            }
        }
    }

    @Test
    void aSnapshotWithANegativeEpochIsRefused() throws Exception {
        try (VaultWorld w = new VaultWorld(dir)) {
            Pair p = pair(w);
            JsonObject o = JsonParser.parseString(p.bob().snapshot().toJson()).getAsJsonObject();
            JsonObject keys = o.getAsJsonObject("epochKeys");
            keys.add("-1", keys.get("0"));
            keys.remove("0");
            AltsException e = assertThrows(AltsException.class, () -> VaultSnapshot.fromJson(o.toString()));
            assertEquals(Kind.INVALID_INPUT, e.kind());
        }
    }

    @Test
    void anOutOfRangeTimeOrANonBooleanBanReadsAsTheDefault() {
        TreeMap<String, Payload.Field> fields = new TreeMap<>();
        Payload.Stamp s = new Payload.Stamp(1, 0, "m");
        fields.put("lastUsed", new Payload.Field(JsonParser.parseString("1.5"), s));
        fields.put("expiresAt", new Payload.Field(JsonParser.parseString("1e30"), s));
        TreeMap<String, Payload.Field> bans = new TreeMap<>();
        bans.put("a", new Payload.Field(JsonParser.parseString("{\"banned\":\"yes\",\"observedAt\":2}"), s));
        bans.put("b", new Payload.Field(JsonParser.parseString("{\"banned\":1}"), s));
        bans.put("c", new Payload.Field(JsonParser.parseString("{\"banned\":true}"), s));
        AltAccount a = AccountMapping.toAccount(X, new Payload.Account(Optional.empty(), fields, bans));
        assertEquals(0L, a.lastUsed(), "a fractional time reads 0");
        assertEquals(0L, a.expiresAt(), "an out-of-range time reads 0");
        assertFalse(a.bans().get("a").banned(), "a non-boolean banned reads false");
        assertEquals(2L, a.bans().get("a").observedAt());
        assertFalse(a.bans().get("b").banned());
        assertTrue(a.bans().get("c").banned());
    }
}

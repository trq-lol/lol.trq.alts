package lol.trq.alts.vault;

import static lol.trq.alts.vault.VaultWorld.await;
import static lol.trq.alts.vault.VaultWorld.failure;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.internal.avp.AvpBytes;
import lol.trq.alts.internal.avp.Commits;
import lol.trq.alts.internal.avp.Commits.Commit;
import lol.trq.alts.internal.avp.Payload;
import lol.trq.alts.internal.avp.Tokens;
import lol.trq.alts.internal.vault.TestAvpHost;
import lol.trq.alts.model.AccountType;
import lol.trq.alts.model.AltAccount;
import lol.trq.alts.model.BanInfo;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The public AVP 0.5 vault API against the honest loopback test host: create, invite and join from pasted
 * tokens, the {@link AltAccount} and {@link BanInfo} mapping of payload v2 (AVP SPEC 5) with its per-field
 * merge, the refresh-token policy in both directions (SPEC 5.1), the roster and host views, member removal,
 * leave processing, owner device linking, the expected host key, and the snapshot.
 */
class SharedVaultAvp05Test {

    private static final String UUID_A = "0b5e7f2a-5d1c-4a6e-9c1e-1f0d4a7b3c21";
    private static final String UUID_B = "7c1d2e3f-4a5b-4c6d-8e7f-90a1b2c3d4e5";

    @TempDir
    Path dir;

    /** The owner and one member, Bob, joined through pasted tokens. */
    private record Pair(OwnerIdentity ownerId, SharedVault owner, VaultIdentity bobId, SharedVault bob) {}

    private static VaultIdentity newMember() throws Exception {
        return VaultIdentity.create("correct horse".toCharArray());
    }

    /** The whole join, every token pasted as text with whitespace around it and a line break inside. */
    private static SharedVault join(VaultWorld w, SharedVault owner, VaultIdentity member) {
        RepoLocator locator = RepoLocator.parse(pasted(owner.locator().text()));
        VaultHost home = await(w.alts.vault().connect(locator));
        InviteToken token = await(SharedVault.prepareJoin(home, member, locator));
        await(owner.invite(InviteToken.parse(pasted(token.text()))));
        return await(SharedVault.join(home, member, locator));
    }

    private static String pasted(String text) {
        int half = text.length() / 2;
        return "  \n\t" + text.substring(0, half) + "\r\n" + text.substring(half) + " \n";
    }

    private Pair pair(VaultWorld w) throws Exception {
        OwnerIdentity ownerId = OwnerIdentity.generate();
        SharedVault owner = await(SharedVault.create(w.home(), ownerId));
        VaultIdentity bobId = newMember();
        return new Pair(ownerId, owner, bobId, join(w, owner, bobId));
    }

    private static AltAccount full(String uuid) {
        Map<String, BanInfo> bans = new LinkedHashMap<>();
        bans.put("one.example", new BanInfo(true, 1_700_000_000_111L, "self", "cheating", "observer-1"));
        bans.put("two.example", new BanInfo(false, 1_700_000_000_222L, "login", null, null));
        return new AltAccount(
                uuid,
                "Steve",
                "access-token-value",
                AccountType.MICROSOFT,
                1_700_000_000_333L,
                "member-who-used-it",
                bans,
                "client-name",
                "client-user",
                "refresh-token-value",
                1_700_000_000_444L);
    }

    // --- Create, join, resume ------------------------------------------------------------------------

    @Test
    void createJoinFromPastedTokensAndResumeFromASnapshot() throws Exception {
        try (VaultWorld w = new VaultWorld(dir)) {
            Pair p = pair(w);
            assertTrue(p.owner().isOwner());
            assertFalse(p.bob().isOwner());
            assertEquals(p.owner().repoId(), p.bob().repoId());
            assertEquals(p.bobId().identityId(), p.bob().memberId(), "the 0.4 identity is the 0.5 member key");
            assertEquals(p.ownerId().memberId(), p.owner().memberId());
            SyncReport joined = p.bob().openReport();
            assertEquals(2, joined.newStates(), "a join learns the whole chain: genesis and the invite");
            assertFalse(joined.policyTurnedOn());

            await(p.owner().put(full(UUID_A)));
            await(p.bob().sync());
            assertEquals(
                    List.of(UUID_A),
                    p.bob().accounts().stream().map(AltAccount::uuid).toList());

            // The owner moves on while Bob is away; Bob resumes from the JSON he persisted.
            VaultSnapshot saved = VaultSnapshot.fromJson(p.bob().snapshot().toJson());
            assertEquals(p.bob().snapshot().pinnedSeq(), saved.pinnedSeq());
            assertEquals(p.bobId().identityId(), saved.memberId());
            await(p.owner().setShareRefreshTokens(true));
            await(p.owner().put(full(UUID_B)));

            VaultHost home = await(w.alts.vault().connect(saved));
            SharedVault resumed = await(SharedVault.resume(home, p.bobId(), saved));
            assertEquals(saved.pinnedSeq() + 1, resumed.snapshot().pinnedSeq(), "the pin moved past the saved one");
            SyncReport report = resumed.openReport();
            assertEquals(1, report.newStates(), "only the state past the pin is new");
            assertTrue(report.policyTurnedOn(), "the policy flip that happened while away is reported");
            assertEquals(
                    List.of(UUID_A, UUID_B),
                    resumed.accounts().stream().map(AltAccount::uuid).toList());

            // The owner resumes too, and its accounts are intact.
            VaultSnapshot ownerSaved =
                    VaultSnapshot.fromJson(p.owner().snapshot().toJson());
            SharedVault ownerAgain =
                    await(SharedVault.resume(await(w.alts.vault().connect(ownerSaved)), p.ownerId(), ownerSaved));
            assertTrue(ownerAgain.isOwner());
            assertEquals(p.owner().accounts(), ownerAgain.accounts());
            assertEquals(p.owner().locator(), ownerAgain.locator());
        }
    }

    @Test
    void aSnapshotResumesOnlyForItsOwnMember() throws Exception {
        try (VaultWorld w = new VaultWorld(dir)) {
            Pair p = pair(w);
            VaultSnapshot bobs = p.bob().snapshot();
            AltsException other = failure(SharedVault.resume(p.bob().host(), newMember(), bobs));
            assertEquals(Kind.INVALID_INPUT, other.kind());
            assertEquals(
                    Kind.INVALID_INPUT,
                    failure(SharedVault.resume(p.bob().host(), p.ownerId(), bobs))
                            .kind());
        }
    }

    @Test
    void aRolledBackChainIsRefusedOnResume() throws Exception {
        try (VaultWorld w = new VaultWorld(dir)) {
            Pair p = pair(w);
            await(p.owner().setShareRefreshTokens(true));
            await(p.bob().sync());
            VaultSnapshot pinned = p.bob().snapshot();
            // The host now serves the chain without its last state.
            w.host.interceptor = (r, honest) -> {
                TestAvpHost.Response answer = honest.apply(r);
                if (!r.path().endsWith("/pull") || answer.status() != 200) {
                    return answer;
                }
                JsonObject o = answer.json();
                com.google.gson.JsonArray states = o.getAsJsonArray("manifests");
                if (states.size() > 0) {
                    states.remove(states.size() - 1);
                }
                return TestAvpHost.Response.json(200, o);
            };
            AltsException rollback = failure(SharedVault.resume(p.bob().host(), p.bobId(), pinned));
            assertEquals(Kind.PROTOCOL, rollback.kind());
        }
    }

    // --- The AltAccount mapping ------------------------------------------------------------------------

    @Test
    void anAccountRoundTripsFieldForFieldThroughAnotherDevice() throws Exception {
        try (VaultWorld w = new VaultWorld(dir)) {
            Pair p = pair(w);
            await(p.owner().setShareRefreshTokens(true));
            AltAccount steve = full(UUID_A);
            await(p.owner().put(steve));
            await(p.bob().sync());
            AltAccount read = p.bob().account(UUID_A).orElseThrow();
            assertEquals(steve, read, "every SPEC 5 field and every ban survives the trip");
            assertEquals("member-who-used-it", read.lastUsedBy());
            assertEquals(1_700_000_000_333L, read.lastUsed());
            assertEquals(
                    new BanInfo(true, 1_700_000_000_111L, "self", "cheating", "observer-1"),
                    read.bans().get("one.example"));
            assertTrue(read.banned("one.example"));
            assertFalse(read.banned("two.example"));
        }
    }

    @Test
    void thePayloadUsesTheSpecFieldNames() throws Exception {
        try (VaultWorld w = new VaultWorld(dir)) {
            Pair p = pair(w);
            await(p.owner().setShareRefreshTokens(true));
            await(p.owner().put(full(UUID_A)));
            Payload.Account a = hostPayload(w, p.owner()).accounts().get(UUID_A);
            assertEquals(
                    List.of(
                            "accessToken",
                            "expiresAt",
                            "lastUsed",
                            "lastUsedBy",
                            "refreshToken",
                            "sourceClient",
                            "sourceUser",
                            "type",
                            "username"),
                    new ArrayList<>(a.fields().keySet()));
            assertEquals("Steve", a.fields().get("username").value().getAsString());
            assertEquals("MICROSOFT", a.fields().get("type").value().getAsString());
            assertEquals(1_700_000_000_333L, a.fields().get("lastUsed").value().getAsLong());
            assertEquals(
                    "member-who-used-it", a.fields().get("lastUsedBy").value().getAsString());
            assertEquals(1_700_000_000_444L, a.fields().get("expiresAt").value().getAsLong());
            assertEquals(
                    List.of("one.example", "two.example"),
                    new ArrayList<>(a.bans().keySet()));
            JsonObject ban = a.bans().get("one.example").value().getAsJsonObject();
            assertEquals(
                    JsonParser.parseString("{\"banned\":true,\"observedAt\":1700000000111,\"source\":\"self\","
                            + "\"detail\":\"cheating\",\"observedBy\":\"observer-1\"}"),
                    ban);
            // Every field of one write carries a stamp by this device's member id.
            a.fields()
                    .values()
                    .forEach(f -> assertEquals(p.owner().memberId(), f.stamp().by()));
        }
    }

    @Test
    void twoDevicesEditingDifferentFieldsOfOneAccountKeepBothEdits() throws Exception {
        try (VaultWorld w = new VaultWorld(dir)) {
            Pair p = pair(w);
            AltAccount steve = full(UUID_A);
            await(p.owner().put(steve));
            await(p.bob().sync());
            // Apart: the owner renames, Bob records that he used it.
            await(p.owner().put(steve.withUsername("Alex")));
            await(p.bob()
                    .put(p.bob().account(UUID_A).orElseThrow().usedNow(p.bob().memberId())));
            await(p.owner().sync());
            await(p.bob().sync());
            for (SharedVault v : List.of(p.owner(), p.bob())) {
                AltAccount merged = v.account(UUID_A).orElseThrow();
                assertEquals("Alex", merged.username(), "the owner's edit survives on " + v.memberId());
                assertEquals(p.bob().memberId(), merged.lastUsedBy(), "Bob's edit survives on " + v.memberId());
                assertNotEquals(steve.lastUsed(), merged.lastUsed());
            }
            assertEquals(p.owner().accounts(), p.bob().accounts());
        }
    }

    @Test
    void bansAreKeptPerServerIdAcrossDevices() throws Exception {
        try (VaultWorld w = new VaultWorld(dir)) {
            Pair p = pair(w);
            await(p.owner().put(AltAccount.of(UUID_A, "Steve", "t", AccountType.OFFLINE)));
            await(p.bob().sync());
            BanInfo seenByBob = new BanInfo(true, 10L, "self", "x", p.bob().memberId());
            BanInfo seenByOwner =
                    new BanInfo(true, 20L, "login", null, p.owner().memberId());
            await(p.bob().markBanned(UUID_A, "one.example", seenByBob));
            await(p.owner().markBanned(UUID_A, "two.example", seenByOwner));
            await(p.owner().sync());
            await(p.bob().sync());
            for (SharedVault v : List.of(p.owner(), p.bob())) {
                Map<String, BanInfo> bans = v.account(UUID_A).orElseThrow().bans();
                assertEquals(seenByBob, bans.get("one.example"));
                assertEquals(seenByOwner, bans.get("two.example"));
                assertEquals(2, bans.size());
            }
            await(p.owner().markBanned(UUID_A, "one.example", null));
            await(p.bob().sync());
            Map<String, BanInfo> after = p.bob().account(UUID_A).orElseThrow().bans();
            assertEquals(Map.of("two.example", seenByOwner), after, "a null ban clears that server only");
        }
    }

    @Test
    void aRemovedAccountIsHiddenUntilItIsPutAgain() throws Exception {
        try (VaultWorld w = new VaultWorld(dir)) {
            Pair p = pair(w);
            AltAccount steve = full(UUID_A);
            await(p.owner().put(steve));
            await(p.owner().put(AltAccount.of(UUID_B, "Alex", "t", AccountType.OFFLINE)));
            await(p.owner().remove(UUID_A));
            await(p.bob().sync());
            assertEquals(Optional.empty(), p.bob().account(UUID_A));
            assertEquals(
                    List.of(UUID_B),
                    p.bob().accounts().stream().map(AltAccount::uuid).toList());
            // The same record again brings it back, though no field changed.
            await(p.bob().put(steve));
            await(p.owner().sync());
            assertTrue(p.owner().account(UUID_A).isPresent());
            assertEquals(2, p.owner().accounts().size());
        }
    }

    // --- The refresh-token policy (SPEC 5.1) ---------------------------------------------------------

    @Test
    void whileThePolicyWithholdsNoRefreshTokenIsSentOrRead() throws Exception {
        try (VaultWorld w = new VaultWorld(dir)) {
            Pair p = pair(w);
            assertFalse(p.owner().sharesRefreshTokens());
            await(p.owner().put(full(UUID_A)));
            await(p.bob().sync());
            for (SharedVault v : List.of(p.owner(), p.bob())) {
                AltAccount a = v.account(UUID_A).orElseThrow();
                assertNull(a.refreshToken(), "withheld on " + v.memberId());
                assertEquals(0L, a.expiresAt(), "withheld on " + v.memberId());
                assertEquals("access-token-value", a.accessToken());
            }
            Payload.Account sent = hostPayload(w, p.owner()).accounts().get(UUID_A);
            assertFalse(sent.fields().containsKey("refreshToken"), "put() never sends a withheld field");
            assertFalse(sent.fields().containsKey("expiresAt"), "put() never sends a withheld field");

            // Sharing on: the same put now carries both, and Bob sees the flip once.
            await(p.owner().setShareRefreshTokens(true));
            SyncReport flip = await(p.bob().sync());
            assertTrue(flip.policyTurnedOn());
            assertFalse(await(p.bob().sync()).policyTurnedOn(), "a flip is reported once");
            await(p.bob().put(full(UUID_A)));
            await(p.owner().sync());
            assertEquals(
                    "refresh-token-value",
                    p.owner().account(UUID_A).orElseThrow().refreshToken());
            assertEquals(
                    1_700_000_000_444L, p.owner().account(UUID_A).orElseThrow().expiresAt());

            // Sharing off again: what a member holds is stripped on read, and nothing new is sent.
            await(p.owner().setShareRefreshTokens(false));
            await(p.bob().sync());
            assertNull(p.bob().account(UUID_A).orElseThrow().refreshToken());
            assertEquals(0L, p.bob().account(UUID_A).orElseThrow().expiresAt());
            await(p.bob().put(full(UUID_A).withUsername("Again")));
            Payload.Account later = hostPayload(w, p.bob()).accounts().get(UUID_A);
            assertFalse(later.fields().containsKey("refreshToken"));
            assertFalse(later.fields().containsKey("expiresAt"));
        }
    }

    /** Decrypts the head the host holds now with the device's current data key, from its snapshot. */
    private static Payload hostPayload(VaultWorld w, SharedVault v) {
        List<byte[]> heads = w.host.heads(v.repoId());
        assertEquals(1, heads.size(), "one head");
        Commit c = w.host.commit(v.repoId(), heads.get(0));
        JsonObject keys =
                JsonParser.parseString(v.snapshot().toJson()).getAsJsonObject().getAsJsonObject("epochKeys");
        byte[] key = AvpBytes.fromBase64(keys.get(Long.toString(c.keyEpoch())).getAsString(), "key");
        return Payload.parse(Commits.open(c, key));
    }

    // --- Roster, hosts, removal, leave -----------------------------------------------------------------

    @Test
    void theRosterAndTheHostsAreViewsOfTheVerifiedState() throws Exception {
        try (VaultWorld w = new VaultWorld(dir)) {
            Pair p = pair(w);
            InviteToken carol = inviteOf(w, p.owner());
            await(p.bob().sync());
            String bobId = p.bobId().identityId();
            for (SharedVault v : List.of(p.owner(), p.bob())) {
                List<VaultMember> roster = v.roster();
                assertEquals(3, roster.size());
                VaultMember owner = roster.get(0);
                assertTrue(owner.owner());
                assertEquals(p.ownerId().memberId(), owner.memberId());
                VaultMember bob = roster.stream()
                        .filter(m -> m.memberId().equals(bobId))
                        .findFirst()
                        .orElseThrow();
                assertFalse(bob.owner());
                assertEquals(p.bobId().fingerprint(), bob.fingerprint());
                assertEquals(1, roster.stream().filter(VaultMember::owner).count(), "one owner");
                assertEquals(carol.fingerprint(), roster.get(2).fingerprint());
                assertEquals(carol.memberId(), roster.get(2).memberId());
                assertEquals(w.host.key().length, AvpBytes.fromBase64(bob.homeHostKey(), "k").length);
                assertArrayEquals(w.host.key(), AvpBytes.fromBase64(bob.homeHostKey(), "k"));
                assertEquals(
                        List.of(new HostRef(AvpBytes.base64(w.host.key()), VaultWorld.locator(w.host))), v.hosts());
            }
        }
    }

    /** Invites a third member, so a roster has someone besides the pair. */
    private InviteToken inviteOf(VaultWorld w, SharedVault owner) throws Exception {
        VaultIdentity carol = newMember();
        RepoLocator locator = owner.locator();
        VaultHost home = await(w.alts.vault().connect(locator));
        InviteToken token = await(SharedVault.prepareJoin(home, carol, locator));
        assertEquals(carol.fingerprint(), token.fingerprint(), "the owner compares this fingerprint");
        assertEquals(carol.identityId(), token.memberId());
        await(owner.invite(token));
        return token;
    }

    @Test
    void theOwnerRemovesAMemberByItsRosterEntry() throws Exception {
        try (VaultWorld w = new VaultWorld(dir)) {
            Pair p = pair(w);
            await(p.owner().put(full(UUID_A)));
            VaultMember bob = p.owner().roster().stream()
                    .filter(m -> !m.owner())
                    .findFirst()
                    .orElseThrow();
            await(p.owner().remove(bob));
            assertEquals(1, p.owner().roster().size());
            assertTrue(p.owner().roster().get(0).owner());
            assertTrue(p.owner().accounts().size() == 1, "the accounts are carried forward under the new key");
            // Bob is out: his next sync is refused.
            failure(p.bob().sync());
            VaultMember owner = p.owner().roster().get(0);
            assertEquals(Kind.INVALID_INPUT, failure(p.owner().remove(owner)).kind(), "the owner is never removed");
            assertEquals(Kind.INVALID_INPUT, failure(p.bob().remove(owner)).kind(), "only the owner removes");
        }
    }

    @Test
    void aMemberLeavesAndTheOwnerProcessesIt() throws Exception {
        try (VaultWorld w = new VaultWorld(dir)) {
            Pair p = pair(w);
            await(p.bob().leave());
            assertTrue(p.bob().left());
            assertEquals(Kind.INVALID_INPUT, failure(p.bob().sync()).kind(), "a leaving member stops syncing");
            VaultSnapshot gone = VaultSnapshot.fromJson(p.bob().snapshot().toJson());
            assertTrue(gone.left());
            assertEquals(
                    Kind.INVALID_INPUT,
                    failure(SharedVault.resume(p.bob().host(), p.bobId(), gone)).kind());

            SyncReport seen = await(p.owner().sync());
            assertEquals(1, seen.pendingLeaves().size());
            assertEquals(p.bobId().identityId(), seen.pendingLeaves().get(0).memberId());
            assertEquals(seen.pendingLeaves(), p.owner().pendingLeaves());
            List<VaultMember> removed = await(p.owner().processLeaves());
            assertEquals(seen.pendingLeaves(), removed);
            assertEquals(1, p.owner().roster().size());
            assertEquals(List.of(), p.owner().pendingLeaves());
            assertEquals(Kind.INVALID_INPUT, failure(p.owner().leave()).kind(), "the owner cannot leave");
        }
    }

    @Test
    void onlyTheOwnerChangesMembersOrThePolicy() throws Exception {
        try (VaultWorld w = new VaultWorld(dir)) {
            Pair p = pair(w);
            assertEquals(
                    Kind.INVALID_INPUT,
                    failure(p.bob().setShareRefreshTokens(true)).kind());
            assertEquals(Kind.INVALID_INPUT, failure(p.bob().processLeaves()).kind());
            AltsException locator =
                    assertThrows(AltsException.class, () -> p.bob().locator());
            assertEquals(Kind.INVALID_INPUT, locator.kind());
        }
    }

    // --- Owner device linking ----------------------------------------------------------------------------

    @Test
    void aSecondOwnerDeviceLinksWithTheConfirmationCode() throws Exception {
        try (VaultWorld w = new VaultWorld(dir)) {
            Pair p = pair(w);
            await(p.owner().put(full(UUID_A)));

            LinkSession fresh = LinkSession.start();
            LinkRequest request = LinkRequest.parse(pasted(fresh.request().text()));
            assertEquals(fresh.confirmationCode(), request.confirmationCode());
            assertTrue(fresh.confirmationCode().matches("[0-9]{6}"));
            List<String> shown = new ArrayList<>();
            LinkGrant grant = LinkSession.approve(p.ownerId(), request, code -> {
                shown.add(code);
                return code.equals(fresh.confirmationCode());
            });
            assertEquals(List.of(fresh.confirmationCode()), shown, "the existing device shows the code");
            OwnerIdentity linked = fresh.finish(LinkGrant.parse(pasted(grant.text())));
            assertEquals(p.ownerId().phrase(), linked.phrase());
            assertArrayEquals(p.ownerId().entropy(), linked.entropy());

            SharedVault second =
                    await(SharedVault.open(p.owner().host(), linked, p.owner().repoId()));
            assertTrue(second.isOwner());
            assertEquals(p.owner().accounts(), second.accounts());
            assertEquals(
                    Kind.INVALID_INPUT,
                    assertThrows(AltsException.class, () -> fresh.finish(grant)).kind());
        }
    }

    @Test
    void anUnconfirmedOrForeignGrantLinksNothing() {
        OwnerIdentity owner = OwnerIdentity.generate();
        LinkSession mine = LinkSession.start();
        AltsException declined =
                assertThrows(AltsException.class, () -> LinkSession.approve(owner, mine.request(), code -> false));
        assertEquals(Kind.DECLINED, declined.kind());
        LinkSession other = LinkSession.start();
        LinkGrant forOther = LinkSession.approve(owner, other.request(), code -> true);
        assertEquals(
                Kind.CRYPTO,
                assertThrows(AltsException.class, () -> mine.finish(forOther)).kind());
        assertEquals("LinkGrant[redacted]", forOther.toString());
    }

    // --- The expected host key ---------------------------------------------------------------------------

    @Test
    void aHostReachedFromALocatorMustServeTheLocatorsKey() throws Exception {
        try (VaultWorld w = new VaultWorld(dir);
                TestAvpHost impostor = new TestAvpHost()) {
            Pair p = pair(w);
            RepoLocator real = p.owner().locator();
            // A locator that names the impostor's address with the real host's key: the impostor's discovery
            // serves its own key, and the connection is refused.
            RepoLocator lured = new RepoLocator(new Tokens.RepoLocator(
                    real.repoId(), w.host.key(), VaultWorld.locator(impostor), real.ownerFingerprint()));
            assertEquals(Kind.PROTOCOL, failure(w.alts.vault().connect(lured)).kind());
            assertEquals(0, impostor.count("/pull"), "nothing but discovery reached the impostor");
            assertEquals(0, impostor.count("/challenge"), "no sign-in reached the impostor");

            // The same for a snapshot's home host, and for a key given outright.
            VaultSnapshot s = p.bob().snapshot();
            w.host.rekey();
            assertEquals(Kind.PROTOCOL, failure(w.alts.vault().connect(s)).kind());
            assertEquals(
                    Kind.PROTOCOL,
                    failure(w.alts.vault().connect(VaultWorld.locator(impostor), real.hostKey()))
                            .kind());
        }
    }

    @Test
    void aHostFirstReachedByLocatorAloneMustStillBeListed() throws Exception {
        try (VaultWorld w = new VaultWorld(dir);
                TestAvpHost other = new TestAvpHost()) {
            Pair p = pair(w);
            VaultHost unlisted = await(w.alts.vault().connect(VaultWorld.locator(other)));
            assertEquals(AvpBytes.base64(other.key()), unlisted.hostKey());
            failure(SharedVault.open(unlisted, p.bobId(), p.owner().repoId()));
        }
    }

    @Test
    void aLocatorIsReachedOverHttpsByDefault(@TempDir Path other) throws Exception {
        assertEquals(java.net.URI.create("https://vault.example:8443"), VaultHosts.https("vault.example:8443"));
        try (TestAvpHost plain = new TestAvpHost();
                lol.trq.alts.AltsRuntime<Object> alts = new lol.trq.alts.AltsRuntime.Builder<Object>()
                        .sessionInjector(session -> {})
                        .vaultDirectory(() -> other)
                        .mainThread(Runnable::run)
                        .toastSink((level, title, description, durationMs) -> {})
                        .build()) {
            // The test host speaks plain http, so a TLS handshake with it fails before any request is read.
            assertEquals(
                    Kind.NETWORK,
                    failure(alts.vault().connect(VaultWorld.locator(plain))).kind());
            assertEquals(List.of(), plain.requests());
        }
    }

    // --- Identities, tokens, snapshot -------------------------------------------------------------------

    @Test
    void anOwnerPhraseRoundTripsAndABadOneIsInvalidInput() {
        OwnerIdentity owner = OwnerIdentity.generate();
        String phrase = owner.phrase();
        assertEquals(24, phrase.split(" ").length);
        OwnerIdentity typed =
                OwnerIdentity.fromPhrase("  " + phrase.toUpperCase().replace(" ", "  \n ") + "\t");
        assertArrayEquals(owner.entropy(), typed.entropy());
        assertEquals(owner.memberId(), typed.memberId());
        assertEquals(
                owner.fingerprint(), OwnerIdentity.fromEntropy(owner.entropy()).fingerprint());

        String[] words = phrase.split(" ");
        String badChecksum = ("abandon ".repeat(24)).strip();
        for (String bad :
                List.of("", "abandon", phrase + " abandon", phrase.replace(words[3], "notaword"), badChecksum)) {
            AltsException e = assertThrows(AltsException.class, () -> OwnerIdentity.fromPhrase(bad), bad);
            assertEquals(Kind.INVALID_INPUT, e.kind());
        }
        assertEquals(
                Kind.INVALID_INPUT,
                assertThrows(AltsException.class, () -> OwnerIdentity.fromEntropy(new byte[31]))
                        .kind());

        String shown = owner.toString();
        assertFalse(shown.contains(words[0] + " " + words[1]), "no phrase in toString");
        assertFalse(shown.contains(AvpBytes.base64(owner.entropy())));
        assertFalse(shown.contains(AvpBytes.hex(owner.entropy())));
        assertTrue(shown.contains(owner.fingerprint()));
    }

    @Test
    void tokensParseFromPastedTextAndRefuseGarbage() throws Exception {
        try (VaultWorld w = new VaultWorld(dir)) {
            Pair p = pair(w);
            RepoLocator locator = p.owner().locator();
            assertEquals(locator, RepoLocator.parse(pasted(locator.text())));
            assertEquals(locator.text(), RepoLocator.parse(locator.text()).text());
            assertEquals(p.owner().repoId(), locator.repoId());
            assertEquals(p.ownerId().fingerprint(), locator.ownerFingerprint());
            assertEquals(AvpBytes.base64(w.host.key()), locator.hostKey());
            assertEquals("avp://" + VaultWorld.locator(w.host) + "/" + locator.repoId(), locator.avpUri());

            LinkRequest request = LinkSession.start().request();
            String otherKind = request.text();
            for (String garbage : List.of("", "   ", "not a token", otherKind + "x", "eyJ2IjozfQ")) {
                assertEquals(Kind.INVALID_INPUT, invalid(() -> RepoLocator.parse(garbage)), garbage);
                assertEquals(Kind.INVALID_INPUT, invalid(() -> InviteToken.parse(garbage)), garbage);
                assertEquals(Kind.INVALID_INPUT, invalid(() -> LinkGrant.parse(garbage)), garbage);
            }
            assertEquals(Kind.INVALID_INPUT, invalid(() -> LinkRequest.parse(locator.text())));
            assertEquals(Kind.INVALID_INPUT, invalid(() -> RepoLocator.parse(otherKind)));
        }
    }

    private static Kind invalid(org.junit.jupiter.api.function.Executable parse) {
        return assertThrows(AltsException.class, parse).kind();
    }

    @Test
    void aSnapshotIsRedactedAndRoundTripsThroughJson() throws Exception {
        try (VaultWorld w = new VaultWorld(dir)) {
            Pair p = pair(w);
            await(p.owner().setShareRefreshTokens(true));
            await(p.owner().put(full(UUID_A)));
            // A removal raises the epoch, so the snapshot retains two data keys.
            inviteOf(w, p.owner());
            VaultMember carol = p.owner().roster().get(2);
            await(p.owner().remove(carol));
            await(p.bob().sync());

            VaultSnapshot s = p.bob().snapshot();
            String json = s.toJson();
            JsonObject keys = JsonParser.parseString(json).getAsJsonObject().getAsJsonObject("epochKeys");
            assertEquals(List.of("0", "1"), new ArrayList<>(keys.keySet()));
            VaultSnapshot back = VaultSnapshot.fromJson(json);
            assertEquals(json, back.toJson(), "the JSON form round-trips byte for byte");

            // Resumed past both epochs, the snapshot still holds the old key it could not learn again.
            SharedVault resumed = await(SharedVault.resume(await(w.alts.vault().connect(back)), p.bobId(), back));
            JsonObject again = JsonParser.parseString(resumed.snapshot().toJson())
                    .getAsJsonObject()
                    .getAsJsonObject("epochKeys");
            assertEquals(keys, again);
            assertEquals(p.bob().accounts(), resumed.accounts());

            String shown = s.toString() + back;
            for (String k : keys.keySet()) {
                String b64 = keys.get(k).getAsString();
                assertFalse(shown.contains(b64), "no data key in toString");
                assertFalse(shown.contains(AvpBytes.hex(AvpBytes.fromBase64(b64, "k"))), "no data key in toString");
            }
            for (String secret : List.of("access-token-value", "refresh-token-value", "Steve")) {
                assertTrue(json.contains(secret), "the JSON holds the payload");
                assertFalse(shown.contains(secret), "no account field in toString");
            }
            assertTrue(shown.contains(s.repoId()));

            for (String bad : List.of("", "{}", "[]", json.replace("\"v\":1", "\"v\":2"), json.substring(1))) {
                assertEquals(Kind.INVALID_INPUT, invalid(() -> VaultSnapshot.fromJson(bad)), bad);
            }
        }
    }

    // --- Failures, zero knowledge, the account store -------------------------------------------------------

    @Test
    void everyPublicFutureFailsOnlyWithAltsException() throws Exception {
        try (VaultWorld w = new VaultWorld(dir)) {
            Pair p = pair(w);
            assertEquals(
                    Kind.INVALID_INPUT,
                    failure(w.alts.vault().connect("not a/locator")).kind());
            assertEquals(
                    Kind.INVALID_INPUT,
                    failure(w.alts.vault().connect("example.net", "AAAA")).kind());
            assertEquals(
                    Kind.INVALID_INPUT,
                    failure(p.owner()
                                    .put(new AltAccount(
                                            " ", "x", "t", AccountType.OFFLINE, 0, null, null, null, null, null, 0)))
                            .kind());
            assertEquals(Kind.INVALID_INPUT, failure(p.bob().remove(" ")).kind());
            // A host that answers with garbage.
            w.host.interceptor = (r, honest) -> r.path().endsWith("/pull")
                    ? new TestAvpHost.Response(200, "{\"manifests\":".getBytes(StandardCharsets.UTF_8), Map.of())
                    : honest.apply(r);
            assertEquals(Kind.PROTOCOL, failure(p.bob().sync()).kind());
            // A host that refuses with a bare 500.
            w.host.interceptor = (r, honest) -> new TestAvpHost.Response(500, new byte[0], Map.of());
            failure(p.bob().sync());
            failure(p.owner().put(full(UUID_B)));
            w.host.interceptor = (r, honest) -> honest.apply(r);

            // After the runtime closes, every operation fails as cancelled.
            w.alts.close();
            assertEquals(Kind.CANCELLED, failure(p.owner().sync()).kind());
            assertEquals(Kind.CANCELLED, failure(p.bob().put(full(UUID_B))).kind());
            assertEquals(
                    Kind.CANCELLED,
                    failure(w.alts.vault().connect(VaultWorld.locator(w.host))).kind());
        }
    }

    @Test
    void noRequestOnThePublicPathCarriesASecretOrAPlaintext() throws Exception {
        try (VaultWorld w = new VaultWorld(dir)) {
            Pair p = pair(w);
            await(p.owner().put(full(UUID_A)));
            await(p.owner().setShareRefreshTokens(true));
            await(p.bob().put(full(UUID_B)));
            await(p.owner().sync());
            LinkSession fresh = LinkSession.start();
            OwnerIdentity linked = fresh.finish(LinkSession.approve(p.ownerId(), fresh.request(), code -> true));
            await(SharedVault.open(p.owner().host(), linked, p.owner().repoId()));
            await(p.bob().leave());
            await(p.owner().processLeaves());

            Map<String, byte[]> secrets = new LinkedHashMap<>();
            String phrase = p.ownerId().phrase();
            secrets.put("entropy", p.ownerId().entropy());
            secrets.put("phrase", phrase.getBytes(StandardCharsets.UTF_8));
            secrets.put("seed", lol.trq.alts.internal.avp.Bip39.mnemonicToSeed(phrase, ""));
            secrets.put("owner seed", p.ownerId().ownerKeys().ed25519Seed());
            secrets.put("owner x25519", p.ownerId().ownerKeys().x25519Private());
            secrets.put("bob seed", p.bobId().memberKeys().ed25519Seed());
            secrets.put("bob x25519", p.bobId().memberKeys().x25519Private());
            JsonObject keys = JsonParser.parseString(p.owner().snapshot().toJson())
                    .getAsJsonObject()
                    .getAsJsonObject("epochKeys");
            for (String k : keys.keySet()) {
                secrets.put("data key " + k, AvpBytes.fromBase64(keys.get(k).getAsString(), "k"));
            }
            for (String plain :
                    List.of("access-token-value", "refresh-token-value", "member-who-used-it", "client-name")) {
                secrets.put(plain, plain.getBytes(StandardCharsets.UTF_8));
            }
            List<TestAvpHost.Request> requests = w.host.requests();
            assertTrue(requests.size() > 20, "the whole flow was recorded");
            for (TestAvpHost.Request r : requests) {
                byte[] wire = wire(r);
                for (Map.Entry<String, byte[]> s : secrets.entrySet()) {
                    for (byte[] form : forms(s.getValue())) {
                        assertFalse(contains(wire, form), s.getKey() + " sent in " + r.method() + " " + r.path());
                    }
                }
            }
        }
    }

    @Test
    void theVaultNeverWritesIntoTheAccountStore() throws Exception {
        try (VaultWorld w = new VaultWorld(dir)) {
            w.alts.store().flush();
            Map<Path, byte[]> before = files(dir);
            Pair p = pair(w);
            await(p.owner().put(full(UUID_A)));
            await(p.bob().sync());
            await(p.bob().put(full(UUID_B)));
            await(p.owner().sync());
            assertEquals(2, p.owner().accounts().size());
            assertEquals(List.of(), w.alts.store().accounts(), "no shared account is saved");
            w.alts.store().flush();
            Map<Path, byte[]> after = files(dir);
            assertEquals(before.keySet(), after.keySet());
            before.forEach((f, bytes) -> assertArrayEquals(bytes, after.get(f), f + " unchanged"));
        }
    }

    @Test
    void aZeroAndAnAbsentFieldReadAsTheAccountDefaults() {
        Payload.Account bare =
                new Payload.Account(Optional.empty(), new java.util.TreeMap<>(), new java.util.TreeMap<>());
        AltAccount a = AccountMapping.toAccount(UUID_A, bare);
        assertEquals(new AltAccount(UUID_A, null, null, null, 0L, null, null, null, null, null, 0L), a);
    }

    private static Map<Path, byte[]> files(Path root) throws Exception {
        Map<Path, byte[]> out = new LinkedHashMap<>();
        try (var walk = Files.walk(root)) {
            for (Path f : walk.filter(Files::isRegularFile).sorted().toList()) {
                if (!f.getFileName().toString().endsWith(".lock")) {
                    out.put(root.relativize(f), Files.readAllBytes(f));
                }
            }
        }
        return out;
    }

    private static byte[] wire(TestAvpHost.Request r) throws Exception {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        out.write((r.method() + " " + r.path() + "\n").getBytes(StandardCharsets.UTF_8));
        for (Map.Entry<String, List<String>> h : r.headers().entrySet()) {
            out.write((h.getKey() + ": " + String.join(",", h.getValue()) + "\n").getBytes(StandardCharsets.UTF_8));
        }
        out.write(r.body());
        return out.toByteArray();
    }

    private static List<byte[]> forms(byte[] secret) {
        return List.of(
                secret,
                AvpBytes.base64(secret).replace("=", "").getBytes(StandardCharsets.UTF_8),
                AvpBytes.base64Url(secret).getBytes(StandardCharsets.UTF_8),
                AvpBytes.hex(secret).getBytes(StandardCharsets.UTF_8),
                AvpBytes.hex(secret).toUpperCase(java.util.Locale.ROOT).getBytes(StandardCharsets.UTF_8));
    }

    private static boolean contains(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }
}

package lol.trq.alts.internal.vault;

import static lol.trq.alts.internal.vault.VaultFixture.ACCOUNT;
import static lol.trq.alts.internal.vault.VaultFixture.await;
import static lol.trq.alts.internal.vault.VaultFixture.failure;
import static lol.trq.alts.internal.vault.VaultFixture.field;
import static lol.trq.alts.internal.vault.VaultFixture.newOwner;
import static lol.trq.alts.internal.vault.VaultFixture.set;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonPrimitive;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.internal.avp.AvpBytes;
import lol.trq.alts.internal.avp.AvpCrypto;
import lol.trq.alts.internal.avp.AvpCrypto.WrapLabel;
import lol.trq.alts.internal.avp.Commits;
import lol.trq.alts.internal.avp.Commits.Commit;
import lol.trq.alts.internal.avp.Manifest;
import lol.trq.alts.internal.avp.Manifest.ManifestState;
import lol.trq.alts.internal.avp.Manifest.MemberEntry;
import lol.trq.alts.internal.avp.Manifest.Removal;
import lol.trq.alts.internal.avp.OwnerKeys;
import lol.trq.alts.internal.avp.Payload;
import lol.trq.alts.internal.avp.Payload.Account;
import lol.trq.alts.internal.avp.Payload.Field;
import lol.trq.alts.internal.avp.Payload.Stamp;
import lol.trq.alts.internal.avp.Tokens;
import lol.trq.alts.internal.avp.Tokens.InviteToken;
import lol.trq.alts.internal.avp.Tokens.LinkGrant;
import lol.trq.alts.net.NetworkScope;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** The engine's happy paths against an honest host (AVP SPEC 5, 6, 7, 8, 11). */
class VaultEngineFlowTest {

    private VaultFixture fx;

    @BeforeEach
    void start() throws Exception {
        fx = new VaultFixture();
    }

    @AfterEach
    void stop() {
        fx.close();
    }

    /** Seals a payload as {@code author} under a retained key of {@code keys}, the way a modified build could. */
    static Commit sealAs(
            MemberKeys author,
            VaultEngine keys,
            long epoch,
            Payload payload,
            List<byte[]> parents,
            long seq,
            byte[] manifestHash) {
        return Commits.seal(
                keys.retainedEpochKeys().get(epoch),
                new Commits.Header(keys.repoId(), parents, seq, manifestHash, epoch),
                payload.encode(),
                author.ed25519Seed());
    }

    static Payload oneField(String name, String value, Stamp stamp) {
        TreeMap<String, Field> fields = new TreeMap<>();
        fields.put(name, new Field(new JsonPrimitive(value), stamp));
        TreeMap<String, Account> accounts = new TreeMap<>();
        accounts.put(ACCOUNT, new Account(Optional.empty(), fields, new TreeMap<>()));
        return new Payload(accounts);
    }

    @Test
    void createWritesAndAnotherDeviceOpensTheSameAccounts() {
        VaultFixture.Owner o = newOwner();
        VaultEngine owner = fx.create(o);
        assertEquals(1, owner.tip().state().manifestSeq());
        assertTrue(owner.isOwner());
        set(owner, "username", "alice-alt");

        VaultEngine again = await(VaultEngine.open(fx.connect(), o.member(), owner.repoId(), fx.clock));
        assertEquals("alice-alt", field(again.payload(), "username"));
        assertArrayEquals(owner.tipHash(), again.tipHash());
        assertEquals(1, again.heads().size());
    }

    @Test
    void inviteWrapsTheDataKeyToTheTokenKeyAndTheJoinerReads() {
        VaultEngine owner = fx.create(newOwner());
        set(owner, "username", "alice-alt");
        MemberKeys bob = MemberKeys.generate();
        HostClient home = fx.connect();
        InviteToken token = await(VaultEngine.prepareJoin(home, bob, owner.repoId()));
        assertTrue(Tokens.verifyInvite(token, owner.repoId(), System.currentTimeMillis()));
        await(owner.invite(token));

        ManifestState tip = owner.tip().state();
        assertEquals(2, tip.manifestSeq());
        MemberEntry entry = tip.member(bob.ed25519Public()).orElseThrow();
        assertArrayEquals(token.x25519PublicKey(), entry.x25519PublicKey());
        assertArrayEquals(
                owner.retainedEpochKeys().get(0L),
                AvpCrypto.unwrap(bob.x25519Private(), entry.wrappedDataKey(), WrapLabel.DATA_KEY));

        VaultEngine joined = await(VaultEngine.join(home, bob, owner.locator(), fx.clock));
        assertEquals("alice-alt", field(joined.payload(), "username"));
        assertFalse(joined.isOwner());
        assertThrows(AltsException.class, joined::locator);
    }

    @Test
    void inviteAddsTheJoinersHomeHostWhenItIsNotListed() throws Exception {
        VaultEngine owner = fx.create(newOwner());
        TestAvpHost other = fx.anotherHost();
        MemberKeys bob = MemberKeys.generate();
        InviteToken token = await(VaultEngine.prepareJoin(fx.connect(other), bob, owner.repoId()));
        await(owner.invite(token));
        ManifestState tip = owner.tip().state();
        assertTrue(tip.hasHost(other.key()));
        assertTrue(tip.hasHost(fx.host.key()));
        assertArrayEquals(
                other.key(), tip.member(bob.ed25519Public()).orElseThrow().homeHostKey());
    }

    @Test
    void concurrentEditsMergeWithExactlyTheReadHeadsAsParents() {
        VaultEngine owner = fx.create(newOwner());
        set(owner, "username", "alice-alt");
        VaultEngine bob = fx.invite(owner, MemberKeys.generate());

        set(owner, "username", "alice-renamed");
        set(bob, "lastUsedBy", "bob");
        List<byte[]> hostHeads = fx.host.heads(owner.repoId());
        assertEquals(2, hostHeads.size(), "two concurrent heads");

        PullReport r = await(owner.pull());
        assertEquals(2, r.readableHeads().size());
        byte[] merge = r.mergeCommit().orElseThrow();
        Commit mc = fx.host.commit(owner.repoId(), merge);
        assertEquals(ids(hostHeads), ids(mc.parents()));
        assertEquals("alice-renamed", field(owner.payload(), "username"));
        assertEquals("bob", field(owner.payload(), "lastUsedBy"));

        await(bob.pull());
        assertEquals(owner.payload(), bob.payload());
        assertEquals(1, fx.host.heads(owner.repoId()).size());
    }

    @Test
    void removeRotatesRewrapsSetsTheFrontierAndCarriesTheRotationCommit() {
        VaultEngine owner = fx.create(newOwner());
        MemberKeys bobKeys = MemberKeys.generate();
        VaultEngine bob = fx.invite(owner, bobKeys);
        VaultEngine carol = fx.invite(owner, MemberKeys.generate());
        set(bob, "note", "from bob");
        await(owner.pull());
        List<byte[]> merged = owner.heads();

        await(owner.remove(bobKeys.ed25519Public()));
        ManifestState tip = owner.tip().state();
        assertEquals(1, tip.keyEpoch());
        assertFalse(tip.hasMember(bobKeys.ed25519Public()));
        Removal removal = tip.removalOf(bobKeys.ed25519Public()).orElseThrow();
        assertEquals(tip.manifestSeq(), removal.removedAtSeq());
        assertEquals(ids(merged), ids(removal.frontier()));
        for (MemberEntry m : tip.members()) {
            assertEquals(1, m.keyEpoch());
        }

        List<byte[]> heads = fx.host.heads(owner.repoId());
        assertEquals(1, heads.size());
        Commit rotation = fx.host.commit(owner.repoId(), heads.get(0));
        assertEquals(1, rotation.keyEpoch());
        assertEquals(tip.manifestSeq(), rotation.manifestSeq());
        assertArrayEquals(Manifest.hash(owner.tip()), rotation.manifestHash());
        assertArrayEquals(tip.ownerKey(), rotation.author());
        assertEquals(ids(merged), ids(rotation.parents()));

        await(carol.pull());
        assertEquals("from bob", field(carol.payload(), "note"));
        assertTrue(carol.retainedEpochKeys().containsKey(1L));
        set(carol, "note", "from carol");
        assertEquals(Kind.UNAUTHORIZED, failure(bob.pull()).kind());
    }

    @Test
    void aPolicyChangeIsReportedAndTheRefreshTokenOnlyTravelsWhileShared() {
        VaultEngine owner = fx.create(newOwner());
        VaultEngine bob = fx.invite(owner, MemberKeys.generate());
        await(owner.write(e -> {
            e.setField(ACCOUNT, "username", new JsonPrimitive("alice-alt"));
            e.setField(ACCOUNT, "refreshToken", new JsonPrimitive("refresh-withheld"));
        }));
        assertNull(field(owner.payload(), "refreshToken"), "stripped on write while the policy is false");

        await(owner.setShareRefreshTokens(true));
        assertTrue(owner.tip().state().shareRefreshTokens());
        PullReport flipped = await(bob.pull());
        assertTrue(flipped.policyTurnedOn());
        assertFalse(await(bob.pull()).policyTurnedOn(), "reported once");
        set(owner, "refreshToken", "refresh-shared");
        await(bob.pull());
        assertEquals("refresh-shared", field(bob.payload(), "refreshToken"));

        await(owner.setShareRefreshTokens(false));
        await(bob.pull());
        assertNull(field(bob.payload(), "refreshToken"), "stripped on read once the policy is false again");
        assertEquals("alice-alt", field(bob.payload(), "username"));
    }

    @Test
    void aLeavingMemberStopsSyncingAndTheOwnerProcessesTheLeave() {
        VaultEngine owner = fx.create(newOwner());
        MemberKeys bobKeys = MemberKeys.generate();
        VaultEngine bob = fx.invite(owner, bobKeys);
        await(bob.leave());
        assertTrue(bob.left());
        assertEquals(Kind.INVALID_INPUT, failure(bob.pull()).kind());
        assertEquals(Kind.INVALID_INPUT, failure(bob.write(e -> {})).kind());

        PullReport r = await(owner.pull());
        assertEquals(1, r.leaves().size());
        List<byte[]> removed = await(owner.processLeaves());
        assertEquals(1, removed.size());
        assertArrayEquals(bobKeys.ed25519Public(), removed.get(0));
        assertFalse(owner.tip().state().hasMember(bobKeys.ed25519Public()));
        assertEquals(1, owner.tip().state().keyEpoch());
        assertTrue(owner.pendingLeaves().isEmpty());
        assertEquals(Kind.INVALID_INPUT, failure(owner.leave()).kind(), "the owner cannot leave");
    }

    @Test
    void anOwnerDeviceLinksAndReadsTheVault() {
        VaultFixture.Owner o = newOwner();
        VaultEngine owner = fx.create(o);
        set(owner, "username", "alice-alt");

        DeviceLink session = DeviceLink.start();
        String code = session.confirmationCode();
        List<String> shown = new ArrayList<>();
        LinkGrant grant = DeviceLink.approve(o.entropy(), session.request(), c -> shown.add(c) && c.equals(code));
        assertEquals(List.of(code), shown);
        byte[] entropy = session.finish(grant);
        assertArrayEquals(o.entropy(), entropy);
        assertEquals(
                Kind.INVALID_INPUT,
                assertThrows(AltsException.class, () -> session.finish(grant)).kind());

        VaultEngine linked = await(VaultEngine.open(
                fx.connect(), MemberKeys.ofOwner(OwnerKeys.fromEntropy(entropy)), owner.repoId(), fx.clock));
        assertTrue(linked.isOwner());
        assertEquals("alice-alt", field(linked.payload(), "username"));

        DeviceLink other = DeviceLink.start();
        assertEquals(
                Kind.CRYPTO,
                assertThrows(AltsException.class, () -> other.finish(grant)).kind());
        assertEquals(
                Kind.DECLINED,
                assertThrows(AltsException.class, () -> DeviceLink.approve(o.entropy(), other.request(), c -> false))
                        .kind());
    }

    @Test
    void theStateRoundTripsAndAResumedVaultKeepsItsPin() {
        VaultEngine owner = fx.create(newOwner());
        MemberKeys bobKeys = MemberKeys.generate();
        VaultEngine bob = fx.invite(owner, bobKeys);
        set(owner, "username", "alice-alt");
        await(bob.pull());
        EngineState state = bob.state();
        assertFalse(
                state.toString().contains(AvpBytes.base64(state.retainedKeys().get(0L))));

        VaultEngine resumed = await(VaultEngine.resume(fx.connect(), bobKeys, state, fx.clock));
        assertEquals(bob.payload(), resumed.payload());
        assertArrayEquals(bob.tipHash(), resumed.tipHash());
        assertArrayEquals(
                state.retainedKeys().get(0L), resumed.retainedEpochKeys().get(0L));
        set(resumed, "lastUsedBy", "bob");
        await(owner.pull());
        assertEquals("bob", field(owner.payload(), "lastUsedBy"));

        // A host that later serves the genesis alone rolls the resumed device back: refused.
        fx.host.interceptor = (req, honest) -> {
            TestAvpHost.Response r = honest.apply(req);
            if (req.path().endsWith("/pull")) {
                var o = r.json();
                var ms = o.getAsJsonArray("manifests");
                var keep = new com.google.gson.JsonArray();
                if (req.json().get("sinceManifestSeq").getAsLong() == 0) {
                    keep.add(ms.get(0));
                }
                o.add("manifests", keep);
                return TestAvpHost.Response.json(200, o);
            }
            return r;
        };
        AltsException e = failure(VaultEngine.resume(fx.connect(), bobKeys, state, fx.clock));
        assertEquals(Kind.PROTOCOL, e.kind());
    }

    @Test
    void everyRequestGoesOutUnderTheVaultPurpose() {
        VaultEngine owner = fx.create(newOwner());
        fx.invite(owner, MemberKeys.generate());
        set(owner, "username", "x");
        await(owner.pull());
        assertFalse(fx.scopes.isEmpty());
        Set<NetworkScope.Purpose> purposes =
                fx.scopes.stream().map(NetworkScope::purpose).collect(Collectors.toSet());
        assertEquals(Set.of(NetworkScope.Purpose.VAULT), purposes);
        assertEquals(fx.host.requests().size(), fx.scopes.size(), "one scope per request, none skipped");
    }

    @Test
    void theClockObservesEveryMergedStampBeforeItTicks() {
        VaultEngine owner = fx.create(newOwner());
        MemberKeys bobKeys = MemberKeys.generate();
        VaultEngine bob = fx.invite(owner, bobKeys);
        // Bob's clock runs an hour fast: his stamp is later than anything the owner's wall clock gives.
        long ahead = System.currentTimeMillis() + 3_600_000L;
        Commit c = sealAs(
                bobKeys,
                bob,
                0,
                oneField("username", "bob-version", new Stamp(ahead, 0, bobKeys.id())),
                bob.heads(),
                bob.tip().state().manifestSeq(),
                bob.tipHash());
        bob.host().push(bobKeys, bob.repoId(), c);
        await(owner.pull());
        assertEquals("bob-version", field(owner.payload(), "username"));
        set(owner, "username", "owner-version");
        Stamp stamp =
                owner.payload().accounts().get(ACCOUNT).fields().get("username").stamp();
        assertTrue(stamp.compareTo(new Stamp(ahead, 0, bobKeys.id())) > 0);
        await(bob.pull());
        assertEquals("owner-version", field(bob.payload(), "username"), "the later write wins everywhere");
    }

    @Test
    void anImpossibleMemberTimestampRefusesWritesWithAClearMessage() {
        VaultEngine owner = fx.create(newOwner());
        MemberKeys bobKeys = MemberKeys.generate();
        VaultEngine bob = fx.invite(owner, bobKeys);
        Commit c = sealAs(
                bobKeys,
                bob,
                0,
                oneField("username", "max", new Stamp(Long.MAX_VALUE, Long.MAX_VALUE, bobKeys.id())),
                bob.heads(),
                bob.tip().state().manifestSeq(),
                bob.tipHash());
        bob.host().push(bobKeys, bob.repoId(), c);
        await(owner.pull());
        AltsException e = failure(owner.write(w -> w.setField(ACCOUNT, "username", new JsonPrimitive("y"))));
        assertEquals(Kind.PROTOCOL, e.kind());
        assertEquals(VaultFailures.IMPOSSIBLE_TIMESTAMP, e.failure().message());
    }

    @Test
    void anOldEpochHeadIsMergedForwardWithTheRetainedKey() {
        VaultEngine owner = fx.create(newOwner());
        VaultEngine bob = fx.invite(owner, MemberKeys.generate());
        MemberKeys carolKeys = MemberKeys.generate();
        fx.invite(owner, carolKeys);
        await(bob.pull());
        await(owner.remove(carolKeys.ed25519Public()));
        // Bob has not pulled the rotation: his write is under epoch 0, citing the state before it.
        set(bob, "note", "written under epoch 0");
        PullReport r = await(owner.pull());
        assertTrue(r.unreadableHeads().isEmpty());
        assertEquals("written under epoch 0", field(owner.payload(), "note"));
        Commit merge = fx.host.commit(owner.repoId(), r.mergeCommit().orElseThrow());
        assertEquals(1, merge.keyEpoch(), "merged forward under the current epoch");
    }

    @Test
    void anUnreadableHeadIsSkippedAndNeverAParent() {
        VaultEngine owner = fx.create(newOwner());
        VaultEngine bob = fx.invite(owner, MemberKeys.generate());
        MemberKeys carolKeys = MemberKeys.generate();
        fx.invite(owner, carolKeys);
        await(bob.pull());
        await(owner.remove(carolKeys.ed25519Public()));
        VaultEngine dave = fx.invite(owner, MemberKeys.generate());
        VaultEngine erin = fx.invite(owner, MemberKeys.generate());
        await(dave.pull());
        await(erin.pull());
        set(bob, "note", "epoch 0, which dave never held");
        set(owner, "username", "owner under epoch 1");
        set(erin, "lastUsedBy", "erin");
        assertEquals(3, fx.host.heads(owner.repoId()).size());

        PullReport r = await(dave.pull());
        assertEquals(1, r.unreadableHeads().size());
        assertEquals(2, r.readableHeads().size());
        Commit merge = fx.host.commit(dave.repoId(), r.mergeCommit().orElseThrow());
        assertEquals(ids(r.readableHeads()), ids(merge.parents()));
        assertNull(field(dave.payload(), "note"));
        assertEquals("erin", field(dave.payload(), "lastUsedBy"));
    }

    @Test
    void ownerOperationsAreRefusedOnAMembersDevice() {
        VaultEngine owner = fx.create(newOwner());
        MemberKeys bobKeys = MemberKeys.generate();
        VaultEngine bob = fx.invite(owner, bobKeys);
        assertEquals(
                Kind.INVALID_INPUT, failure(bob.setShareRefreshTokens(true)).kind());
        assertEquals(
                Kind.INVALID_INPUT,
                failure(bob.remove(owner.member().ed25519Public())).kind());
        assertEquals(Kind.INVALID_INPUT, failure(bob.processLeaves()).kind());
        assertEquals(
                Kind.INVALID_INPUT,
                failure(owner.remove(owner.member().ed25519Public())).kind());
        HostClient home = fx.connect();
        InviteToken again = await(VaultEngine.prepareJoin(home, bobKeys, owner.repoId()));
        assertEquals(Kind.INVALID_INPUT, failure(owner.invite(again)).kind(), "already a member");
    }

    @Test
    void anInviteTokenWhoseAcceptanceDoesNotCheckIsRefused() {
        VaultEngine owner = fx.create(newOwner());
        MemberKeys bob = MemberKeys.generate();
        InviteToken token = await(VaultEngine.prepareJoin(fx.connect(), bob, owner.repoId()));
        InviteToken otherKey = new InviteToken(
                MemberKeys.generate().ed25519Public(),
                token.x25519PublicKey(),
                token.homeHostKey(),
                token.homeHostLocator(),
                token.acceptance());
        assertEquals(Kind.PROTOCOL, failure(owner.invite(otherKey)).kind());
        fx.skew.set(16 * 60_000L);
        assertEquals(Kind.PROTOCOL, failure(owner.invite(token)).kind(), "expired");
        assertEquals(1, owner.tip().state().manifestSeq());
    }

    @Test
    void afterTheRuntimeClosesAnOperationFailsAsCancelled() {
        VaultEngine owner = fx.create(newOwner());
        fx.transport.close();
        assertEquals(Kind.CANCELLED, failure(owner.pull()).kind());
        fx.executor.shutdownNow();
        assertEquals(Kind.CANCELLED, failure(owner.pull()).kind());
        assertEquals(
                Kind.CANCELLED,
                failure(VaultEngine.open(owner.host(), owner.member(), owner.repoId(), fx.clock))
                        .kind());
    }

    static List<String> ids(List<byte[]> ids) {
        return ids.stream()
                .map(AvpBytes::base64)
                .sorted(Comparator.naturalOrder())
                .toList();
    }

    static void assertHasMerge(PullReport r) {
        assertNotNull(r.mergeCommit().orElse(null));
    }
}

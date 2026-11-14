package lol.trq.alts.internal.vault;

import static lol.trq.alts.internal.vault.VaultEngineFlowTest.ids;
import static lol.trq.alts.internal.vault.VaultEngineFlowTest.oneField;
import static lol.trq.alts.internal.vault.VaultEngineFlowTest.sealAs;
import static lol.trq.alts.internal.vault.VaultFixture.ACCOUNT;
import static lol.trq.alts.internal.vault.VaultFixture.await;
import static lol.trq.alts.internal.vault.VaultFixture.failure;
import static lol.trq.alts.internal.vault.VaultFixture.field;
import static lol.trq.alts.internal.vault.VaultFixture.newOwner;
import static lol.trq.alts.internal.vault.VaultFixture.set;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.UnaryOperator;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.internal.avp.AvpBytes;
import lol.trq.alts.internal.avp.AvpCrypto;
import lol.trq.alts.internal.avp.AvpCrypto.WrapLabel;
import lol.trq.alts.internal.avp.AvpJson;
import lol.trq.alts.internal.avp.Challenge;
import lol.trq.alts.internal.avp.Commits;
import lol.trq.alts.internal.avp.Commits.Commit;
import lol.trq.alts.internal.avp.Ed25519Strict;
import lol.trq.alts.internal.avp.Manifest;
import lol.trq.alts.internal.avp.Manifest.ManifestState;
import lol.trq.alts.internal.avp.Manifest.MemberEntry;
import lol.trq.alts.internal.avp.Manifest.Removal;
import lol.trq.alts.internal.avp.Manifest.SignedManifest;
import lol.trq.alts.internal.avp.Payload;
import lol.trq.alts.internal.avp.Payload.Stamp;
import lol.trq.alts.internal.avp.Tokens;
import lol.trq.alts.internal.avp.Tokens.RepoLocator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A host that lies (AVP SPEC 6.4, 6.5, 7.5, 8, 10.4; the four attacks of the 1.0 freeze record, section 4).
 * The hostile layer rewrites what an honest host answers; the client must refuse, discard or ignore it.
 */
class VaultHostileHostTest {

    private VaultFixture fx;

    @BeforeEach
    void start() throws Exception {
        fx = new VaultFixture();
    }

    @AfterEach
    void stop() {
        fx.close();
    }

    // --- Helpers ---------------------------------------------------------------------------------

    /** Rewrites every successful pull answer. */
    private void onPull(UnaryOperator<JsonObject> rewrite) {
        fx.host.interceptor = (req, honest) -> {
            TestAvpHost.Response r = honest.apply(req);
            if (req.path().endsWith("/pull") && r.status() == 200) {
                return TestAvpHost.Response.json(200, rewrite.apply(r.json()));
            }
            return r;
        };
    }

    /** Rewrites the states of every pull answer, keeping each owner signature as it was. */
    private void onServedStates(UnaryOperator<ManifestState> change) {
        onPull(answer -> {
            JsonArray out = new JsonArray();
            for (JsonElement e : answer.getAsJsonArray("manifests")) {
                SignedManifest m = Manifest.signedFromJson(e);
                out.add(Manifest.toJson(new SignedManifest(change.apply(m.state()), m.ownerSignature())));
            }
            answer.add("manifests", out);
            return answer;
        });
    }

    static ManifestState with(ManifestState s, boolean share, List<MemberEntry> members) {
        return new ManifestState(
                s.repoId(),
                s.manifestSeq(),
                s.prevManifestHash(),
                s.ownerKey(),
                s.genesisNonce(),
                s.schemeId(),
                s.keyEpoch(),
                share,
                s.hosts(),
                members,
                s.removals());
    }

    static List<MemberEntry> replace(List<MemberEntry> members, byte[] who, UnaryOperator<MemberEntry> change) {
        List<MemberEntry> out = new ArrayList<>();
        for (MemberEntry m : members) {
            out.add(AvpBytes.same(m.ed25519PublicKey(), who) ? change.apply(m) : m);
        }
        return out;
    }

    private static void addHeads(JsonObject answer, Commit... extra) {
        JsonArray heads = new JsonArray();
        for (Commit c : extra) {
            heads.add(Commits.toJson(c));
        }
        heads.addAll(answer.getAsJsonArray("heads"));
        answer.add("heads", heads);
    }

    /** The owner's epoch-raising next state removing {@code removed}, with its rotation commit. */
    record Rotation(SignedManifest state, Commit commit) {}

    static Rotation removal(VaultFixture.Owner o, SignedManifest prev, byte[] removed, List<byte[]> heads) {
        ManifestState p = prev.state();
        long seq = p.manifestSeq() + 1;
        long epoch = p.keyEpoch() + 1;
        byte[] key = AvpCrypto.randomBytes(32);
        List<MemberEntry> members = new ArrayList<>();
        for (MemberEntry m : p.members()) {
            if (!AvpBytes.same(m.ed25519PublicKey(), removed)) {
                members.add(new MemberEntry(
                        m.ed25519PublicKey(),
                        m.x25519PublicKey(),
                        AvpCrypto.wrap(m.x25519PublicKey(), key, WrapLabel.DATA_KEY),
                        epoch,
                        m.homeHostKey()));
            }
        }
        List<Removal> removals = new ArrayList<>(p.removals());
        removals.add(new Removal(removed, seq, heads));
        SignedManifest s = Manifest.sign(
                new ManifestState(
                        p.repoId(),
                        seq,
                        Manifest.hash(prev),
                        p.ownerKey(),
                        new byte[0],
                        p.schemeId(),
                        epoch,
                        p.shareRefreshTokens(),
                        p.hosts(),
                        members,
                        removals),
                o.keys().ed25519Seed());
        Commit rotation = Commits.seal(
                key,
                new Commits.Header(p.repoId(), heads, seq, Manifest.hash(s), epoch),
                Payload.EMPTY.encode(),
                o.keys().ed25519Seed());
        return new Rotation(s, rotation);
    }

    /** A rotation at the seq after {@code prev} whose hash is on the wanted side of {@code other}. */
    static Rotation removalBeating(
            VaultFixture.Owner o,
            SignedManifest prev,
            byte[] removed,
            List<byte[]> heads,
            byte[] other,
            boolean lower) {
        while (true) {
            Rotation r = removal(o, prev, removed, heads);
            int cmp = AvpBytes.compare(Manifest.hash(r.state()), other);
            if (lower ? cmp < 0 : cmp > 0) {
                return r;
            }
        }
    }

    /** The owner's next state with only the policy changed. */
    static SignedManifest policy(VaultFixture.Owner o, SignedManifest prev, boolean share) {
        ManifestState p = prev.state();
        return Manifest.sign(
                new ManifestState(
                        p.repoId(),
                        p.manifestSeq() + 1,
                        Manifest.hash(prev),
                        p.ownerKey(),
                        new byte[0],
                        p.schemeId(),
                        p.keyEpoch(),
                        share,
                        p.hosts(),
                        p.members(),
                        p.removals()),
                o.keys().ed25519Seed());
    }

    private static Payload openWith(Commit c, byte[] key) {
        return Payload.parse(Commits.open(c, key));
    }

    // --- The four attacks of the freeze record ---------------------------------------------------

    @Test
    void keySubstitutionOnJoinIsRefused() {
        VaultEngine owner = fx.create(newOwner());
        MemberKeys bob = MemberKeys.generate();
        HostClient home = fx.connect();
        await(owner.invite(await(VaultEngine.prepareJoin(home, bob, owner.repoId()))));
        byte[] hostChosen = AvpCrypto.randomBytes(32);
        onServedStates(s -> with(
                s,
                s.shareRefreshTokens(),
                replace(
                        s.members(),
                        bob.ed25519Public(),
                        m -> new MemberEntry(
                                m.ed25519PublicKey(),
                                m.x25519PublicKey(),
                                AvpCrypto.wrap(m.x25519PublicKey(), hostChosen, WrapLabel.DATA_KEY),
                                m.keyEpoch(),
                                m.homeHostKey()))));
        AltsException e = failure(VaultEngine.join(home, bob, owner.locator(), fx.clock));
        assertEquals(Kind.PROTOCOL, e.kind());
    }

    @Test
    void aRepositoryOfAnotherOwnerIsRefusedOnJoin() {
        VaultFixture.Owner real = newOwner();
        VaultEngine owner = fx.create(real);
        VaultEngine attacker = fx.create(newOwner());
        MemberKeys bob = MemberKeys.generate();
        HostClient home = fx.connect();
        await(attacker.invite(await(VaultEngine.prepareJoin(home, bob, attacker.repoId()))));
        RepoLocator tampered = new RepoLocator(
                attacker.repoId(),
                fx.host.key(),
                home.locator(),
                Tokens.ownerFingerprint(owner.tip().state().ownerKey()));
        assertEquals(
                Kind.PROTOCOL,
                failure(VaultEngine.join(home, bob, tampered, fx.clock)).kind());
        // The same join with the attacker's own fingerprint is a valid join of the attacker's repository.
        await(VaultEngine.join(home, bob, attacker.locator(), fx.clock));
    }

    @Test
    void memberKeySubstitutionOnRotationIsRefusedAndNothingIsPublished() {
        VaultEngine owner = fx.create(newOwner());
        MemberKeys bob = MemberKeys.generate();
        fx.invite(owner, bob);
        MemberKeys carol = MemberKeys.generate();
        fx.invite(owner, carol);
        byte[] tipBefore = owner.tipHash();
        byte[] hostKey = AvpCrypto.x25519Public(AvpCrypto.randomBytes(32));
        // The host serves a "new" state whose bob entry carries the host's X25519 key.
        onPull(answer -> {
            if (answer.getAsJsonArray("manifests").isEmpty()) {
                SignedManifest tip = fx.host.tip(owner.repoId());
                ManifestState s = policy(newOwner(), tip, false).state();
                ManifestState forged = with(
                        s,
                        false,
                        replace(
                                s.members(),
                                bob.ed25519Public(),
                                m -> new MemberEntry(
                                        m.ed25519PublicKey(),
                                        hostKey,
                                        m.wrappedDataKey(),
                                        m.keyEpoch(),
                                        m.homeHostKey())));
                JsonArray ms = new JsonArray();
                ms.add(Manifest.toJson(new SignedManifest(forged, tip.ownerSignature())));
                answer.add("manifests", ms);
            }
            return answer;
        });
        long published = fx.host.count("/manifest");
        assertEquals(Kind.PROTOCOL, failure(owner.remove(carol.ed25519Public())).kind());
        assertEquals(
                Kind.PROTOCOL,
                failure(owner.invite(
                                await(VaultEngine.prepareJoin(fx.connect(), MemberKeys.generate(), owner.repoId()))))
                        .kind());
        assertEquals(published, fx.host.count("/manifest"), "nothing published");
        assertArrayEquals(tipBefore, owner.tipHash());
    }

    @Test
    void aSharingFlagFlipIsRefusedAndTheMemberKeepsWithholding() {
        VaultEngine owner = fx.create(newOwner());
        MemberKeys bobKeys = MemberKeys.generate();
        VaultEngine bob = fx.invite(owner, bobKeys);
        fx.invite(owner, MemberKeys.generate());
        onServedStates(s -> with(s, true, s.members()));
        assertEquals(Kind.PROTOCOL, failure(bob.pull()).kind());
        assertFalse(bob.tip().state().shareRefreshTokens());
        assertEquals(2, bob.tip().state().manifestSeq(), "the pin did not move");

        fx.host.interceptor = (r, honest) -> honest.apply(r);
        await(bob.write(e -> e.setField(ACCOUNT, "refreshToken", new com.google.gson.JsonPrimitive("withheld"))));
        Commit written = fx.host.commit(bob.repoId(), bob.heads().get(0));
        Payload plain = openWith(written, owner.retainedEpochKeys().get(0L));
        assertTrue(plain.accounts().isEmpty()
                || !plain.accounts().get(ACCOUNT).fields().containsKey("refreshToken"));
    }

    @Test
    void aRollbackIsRefusedAndThePinStays() {
        VaultEngine owner = fx.create(newOwner());
        VaultEngine bob = fx.invite(owner, MemberKeys.generate());
        fx.invite(owner, MemberKeys.generate());
        await(bob.pull());
        assertEquals(3, bob.tip().state().manifestSeq());
        byte[] pin = bob.tipHash();
        // The host serves the chain as it was at seq 2: the pinned state is missing.
        List<SignedManifest> old = chainOf(bob).subList(0, 2);
        onPull(answer -> {
            JsonArray ms = new JsonArray();
            if (answer.getAsJsonArray("manifests").isEmpty()) {
                ms.add(Manifest.toJson(old.get(1)));
            } else {
                old.forEach(m -> ms.add(Manifest.toJson(m)));
            }
            answer.add("manifests", ms);
            return answer;
        });
        fx.host.clearLog();
        assertEquals(Kind.PROTOCOL, failure(bob.pull()).kind());
        assertArrayEquals(pin, bob.tipHash());
        assertEquals(2, fx.host.count("/pull"), "the pin's seq, then one re-pull from seq 0");
    }

    private List<SignedManifest> chainOf(VaultEngine v) {
        TestAvpHost.Interceptor saved = fx.host.interceptor;
        fx.host.interceptor = (r, honest) -> honest.apply(r);
        try {
            return v.host().pull(v.member(), v.repoId(), 0).manifests();
        } finally {
            fx.host.interceptor = saved;
        }
    }

    // --- More hostile cases ----------------------------------------------------------------------

    @Test
    void forgedCommitsAreDiscardedAndNeverShadowARealHead() {
        VaultEngine owner = fx.create(newOwner());
        MemberKeys bobKeys = MemberKeys.generate();
        VaultEngine bob = fx.invite(owner, bobKeys);
        set(bob, "username", "bob-real");
        Commit real = fx.host.commit(bob.repoId(), bob.heads().get(0));
        byte[] tampered = real.ciphertext().clone();
        tampered[0] ^= 1;
        Commit sameIdOtherBody = new Commit(
                real.repoId(),
                real.commitId(),
                real.parents(),
                real.manifestSeq(),
                real.manifestHash(),
                real.keyEpoch(),
                real.author(),
                real.iv(),
                tampered,
                real.authorSignature());
        MemberKeys mallory = MemberKeys.generate();
        Commit signedByOther = sealAs(
                mallory,
                bob,
                0,
                oneField("username", "forged", new Stamp(Long.MAX_VALUE - 1, 0, "x")),
                List.of(),
                bob.tip().state().manifestSeq(),
                bob.tipHash());
        Commit claimingBob = new Commit(
                signedByOther.repoId(),
                signedByOther.commitId(),
                signedByOther.parents(),
                signedByOther.manifestSeq(),
                signedByOther.manifestHash(),
                signedByOther.keyEpoch(),
                bobKeys.ed25519Public(),
                signedByOther.iv(),
                signedByOther.ciphertext(),
                signedByOther.authorSignature());
        onPull(answer -> {
            addHeads(answer, sameIdOtherBody, signedByOther, claimingBob);
            return answer;
        });
        PullReport r = await(owner.pull());
        assertEquals(ids(List.of(real.commitId())), ids(r.readableHeads()));
        assertEquals(3, r.discardedCommits().size());
        assertEquals("bob-real", field(owner.payload(), "username"));
        assertTrue(r.mergeCommit().isEmpty());
    }

    @Test
    void aRemovedMembersLateCommitsAreDiscardedButAnAncestorOfTheFrontierIsKept() {
        VaultEngine owner = fx.create(newOwner());
        MemberKeys bobKeys = MemberKeys.generate();
        VaultEngine bob = fx.invite(owner, bobKeys);
        set(bob, "note", "b0");
        byte[] b0 = bob.heads().get(0);
        set(bob, "note", "b1");
        byte[] b1 = bob.heads().get(0);
        await(owner.pull());
        long seqBefore = bob.tip().state().manifestSeq();
        byte[] hashBefore = bob.tipHash();
        await(owner.remove(bobKeys.ed25519Public()));
        assertEquals(
                ids(List.of(b1)),
                ids(owner.tip()
                        .state()
                        .removalOf(bobKeys.ed25519Public())
                        .orElseThrow()
                        .frontier()));

        Commit afterCutoff = sealAs(
                bobKeys,
                bob,
                0,
                oneField("note", "after cutoff", new Stamp(1, 0, "b")),
                List.of(),
                seqBefore,
                hashBefore);
        Commit childOfFrontier = sealAs(
                bobKeys,
                bob,
                0,
                oneField("note", "backdated", new Stamp(2, 0, "b")),
                List.of(b1),
                seqBefore,
                hashBefore);
        Commit ancestor = fx.host.commit(owner.repoId(), b0);
        onPull(answer -> {
            addHeads(answer, afterCutoff, childOfFrontier, ancestor);
            return answer;
        });
        PullReport r = await(owner.pull());
        assertEquals(ids(List.of(afterCutoff.commitId(), childOfFrontier.commitId())), ids(r.discardedCommits()));
        assertTrue(ids(r.readableHeads()).contains(AvpBytes.base64(b0)), "an ancestor of a frontier id passes");
        assertEquals("b1", field(owner.payload(), "note"));
    }

    @Test
    void aStalePinIsRecoveredWithOneRepullAndOneRetry() {
        VaultFixture.Owner o = newOwner();
        VaultEngine owner = fx.create(o);
        MemberKeys bobKeys = MemberKeys.generate();
        VaultEngine bob = fx.invite(owner, bobKeys);
        MemberKeys carol = MemberKeys.generate();
        fx.invite(owner, carol);
        SignedManifest m3 = fx.host.tip(owner.repoId());
        List<byte[]> heads = fx.host.heads(owner.repoId());
        await(owner.setShareRefreshTokens(true));
        await(bob.pull());
        byte[] losing = bob.tipHash();
        // A second owner device, apart from the first, removed carol at the same seq; it wins the tie rule,
        // and the host switches to it by replication.
        Rotation w4 = removalBeating(o, m3, carol.ed25519Public(), heads, losing, true);
        assertTrue(fx.host.offer(w4.state(), w4.commit()));
        fx.host.clearLog();

        byte[] id = await(bob.write(e -> e.setField(ACCOUNT, "note", new com.google.gson.JsonPrimitive("after"))));
        assertEquals(2, fx.host.count("/push"), "the refused push, then one retry");
        assertEquals(
                1,
                fx.host.requests().stream()
                        .filter(r -> r.path().endsWith("/pull")
                                && r.json().get("sinceManifestSeq").getAsLong() == 0)
                        .count());
        assertArrayEquals(Manifest.hash(w4.state()), bob.tipHash());
        assertEquals(4, bob.lastDivergence().orElseThrow());
        Commit written = fx.host.commit(bob.repoId(), id);
        assertEquals(1, written.keyEpoch());
        assertArrayEquals(Manifest.hash(w4.state()), written.manifestHash());

        // An unchanged pin leaves a 403 terminal: no second retry.
        fx.host.interceptor = (req, honest) ->
                req.path().endsWith("/push") ? TestAvpHost.Response.error(403, "forbidden", "no") : honest.apply(req);
        fx.host.clearLog();
        assertEquals(
                Kind.UNAUTHORIZED,
                failure(bob.write(e -> e.setField(ACCOUNT, "note", new com.google.gson.JsonPrimitive("x"))))
                        .kind());
        assertEquals(1, fx.host.count("/push"));
        assertEquals(1, fx.host.count("/pull"));
    }

    @Test
    void aForbiddenWithoutItsCodeIsTreatedAsForbidden() {
        VaultEngine owner = fx.create(newOwner());
        fx.host.interceptor = (req, honest) ->
                req.path().endsWith("/push") ? new TestAvpHost.Response(403, new byte[0], Map.of()) : honest.apply(req);
        fx.host.clearLog();
        assertEquals(
                Kind.UNAUTHORIZED,
                failure(owner.write(e -> e.setField(ACCOUNT, "a", new com.google.gson.JsonPrimitive("b"))))
                        .kind());
        assertEquals(
                1,
                fx.host.requests().stream()
                        .filter(r -> r.path().endsWith("/pull")
                                && r.json().get("sinceManifestSeq").getAsLong() == 0)
                        .count(),
                "the stale-pin re-pull ran for a bare 403 too");
        assertEquals(1, fx.host.count("/push"), "and, the pin unchanged, no retry");
    }

    @Test
    void ofTwoDivergedOwnerStatesTheLowerHashWinsAndAHigherOneIsARollback() {
        VaultFixture.Owner o = newOwner();
        VaultEngine owner = fx.create(o);
        VaultEngine bob = fx.invite(owner, MemberKeys.generate());
        MemberKeys carol = MemberKeys.generate();
        fx.invite(owner, carol);
        SignedManifest m3 = fx.host.tip(owner.repoId());
        List<byte[]> heads = fx.host.heads(owner.repoId());
        await(owner.setShareRefreshTokens(true));
        await(bob.pull());
        byte[] l4 = bob.tipHash();
        List<SignedManifest> base = chainOf(bob).subList(0, 3);

        // Higher: the host serves a diverged chain whose state at the fork has the higher hash.
        Rotation hi = removalBeating(o, m3, carol.ed25519Public(), heads, l4, false);
        SignedManifest hi5 = policy(o, hi.state(), true);
        fx.host.interceptor = (req, honest) -> {
            TestAvpHost.Response r = honest.apply(req);
            if (!req.path().endsWith("/pull")) {
                return r;
            }
            JsonObject a = r.json();
            JsonArray ms = new JsonArray();
            if (req.json().get("sinceManifestSeq").getAsLong() == 0) {
                base.forEach(m -> ms.add(Manifest.toJson(m)));
                ms.add(Manifest.toJson(hi.state()));
            }
            ms.add(Manifest.toJson(hi5));
            a.add("manifests", ms);
            return TestAvpHost.Response.json(200, a);
        };
        assertEquals(Kind.PROTOCOL, failure(bob.pull()).kind());
        assertArrayEquals(l4, bob.tipHash());

        // Lower: the host switches to it by replication, and the next pull adopts it.
        fx.host.interceptor = (req, honest) -> honest.apply(req);
        Rotation lo = removalBeating(o, m3, carol.ed25519Public(), heads, l4, true);
        assertTrue(fx.host.offer(lo.state(), lo.commit()));
        SignedManifest lo5 = policy(o, lo.state(), false);
        assertTrue(fx.host.offer(lo5, null));
        PullReport r = await(bob.pull());
        assertEquals(4, r.divergedAt().orElseThrow());
        assertArrayEquals(Manifest.hash(lo5), bob.tipHash());
        assertEquals(1, bob.tip().state().keyEpoch());
        assertTrue(bob.retainedEpochKeys().containsKey(1L));
    }

    @Test
    void aCommitCitingAStateOffTheChainNeedsMembershipAtOrAfterTheCitedSeq() {
        VaultEngine owner = fx.create(newOwner());
        MemberKeys bobKeys = MemberKeys.generate();
        VaultEngine bob = fx.invite(owner, bobKeys);
        MemberKeys carol = MemberKeys.generate();
        fx.invite(owner, carol);
        await(bob.pull());
        await(owner.remove(carol.ed25519Public()));
        assertEquals(4, owner.tip().state().manifestSeq());
        // Bob is a member at epoch 0 in states 2 and 3, and at epoch 1 in state 4.
        Commit cites3 = sealAs(
                bobKeys, bob, 0, oneField("a", "x", new Stamp(1, 0, "b")), List.of(), 3, AvpCrypto.randomBytes(32));
        Commit cites4 = sealAs(
                bobKeys, bob, 0, oneField("b", "y", new Stamp(1, 0, "b")), List.of(), 4, AvpCrypto.randomBytes(32));
        fx.host.interceptor = (req, honest) -> {
            if (req.path().endsWith("/push")) {
                // The merge names the injected head, which this host never held: accept it unseen.
                return TestAvpHost.Response.json(200, new JsonObject());
            }
            TestAvpHost.Response r = honest.apply(req);
            if (req.path().endsWith("/pull")) {
                JsonObject a = r.json();
                addHeads(a, cites3, cites4);
                return TestAvpHost.Response.json(200, a);
            }
            return r;
        };
        PullReport r = await(owner.pull());
        assertTrue(ids(r.readableHeads()).contains(AvpBytes.base64(cites3.commitId())));
        assertEquals(ids(List.of(cites4.commitId())), ids(r.discardedCommits()));
    }

    @Test
    void aRemovedMembersVerifiedButUnreadableHeadIsInTheFrontier() {
        VaultEngine owner = fx.create(newOwner());
        MemberKeys bobKeys = MemberKeys.generate();
        VaultEngine bob = fx.invite(owner, bobKeys);
        set(bob, "note", "b1");
        await(owner.pull());
        // A head the owner verifies but cannot read: sealed under a key nobody was given.
        Commit garbled = Commits.seal(
                AvpCrypto.randomBytes(32),
                new Commits.Header(bob.repoId(), bob.heads(), bob.tip().state().manifestSeq(), bob.tipHash(), 0),
                Payload.EMPTY.encode(),
                bobKeys.ed25519Seed());
        bob.host().push(bobKeys, bob.repoId(), garbled);
        PullReport r = await(owner.pull());
        assertEquals(ids(List.of(garbled.commitId())), ids(r.unreadableHeads()));
        await(owner.remove(bobKeys.ed25519Public()));
        List<byte[]> frontier = owner.tip()
                .state()
                .removalOf(bobKeys.ed25519Public())
                .orElseThrow()
                .frontier();
        assertTrue(ids(frontier).contains(AvpBytes.base64(garbled.commitId())), "every verified commit is covered");
    }

    @Test
    void anotherRepositoryServedInPlaceOfTheOneAskedForIsRefused() {
        VaultFixture.Owner o = newOwner();
        VaultEngine first = fx.create(o);
        VaultEngine second = fx.create(o);
        MemberKeys bob = MemberKeys.generate();
        fx.invite(first, bob);
        VaultEngine inSecond = fx.invite(second, bob);
        String asked = first.repoId();
        String served = second.repoId();
        fx.host.interceptor = (req, honest) -> honest.apply(
                new TestAvpHost.Request(req.method(), req.path().replace(asked, served), req.headers(), req.body()));
        assertEquals(
                Kind.PROTOCOL,
                failure(VaultEngine.open(fx.connect(), bob, asked, fx.clock)).kind());
        EngineState wrong = new EngineState(
                asked, inSecond.state().chainHashes(), new java.util.TreeMap<>(), 0, 0, Payload.EMPTY, false);
        assertEquals(
                Kind.PROTOCOL,
                failure(VaultEngine.resume(fx.connect(), bob, wrong, fx.clock)).kind());
    }

    @Test
    void anAcceptanceThatDoesNotCheckIsRefusedOnPrepareJoin() {
        VaultEngine owner = fx.create(newOwner());
        MemberKeys bob = MemberKeys.generate();
        String repoId = owner.repoId();
        long expires = System.currentTimeMillis() + 600_000;
        byte[] hostSeed = fx.host.seed();
        byte[] other = AvpCrypto.randomBytes(32);
        Tokens.Acceptance otherSigner =
                Tokens.signAcceptance(repoId, bob.ed25519Public(), expires, AvpCrypto.randomBytes(32));
        Tokens.Acceptance forgedSig = new Tokens.Acceptance(
                repoId,
                bob.ed25519Public(),
                fx.host.key(),
                expires,
                Tokens.signAcceptance(repoId, bob.ed25519Public(), expires, other)
                        .signature());
        Tokens.Acceptance otherRepo =
                Tokens.signAcceptance("AAAAAAAAAAAAAAAAAAAAAA", bob.ed25519Public(), expires, hostSeed);
        Tokens.Acceptance otherMember =
                Tokens.signAcceptance(repoId, MemberKeys.generate().ed25519Public(), expires, hostSeed);
        for (Tokens.Acceptance bad : List.of(otherSigner, forgedSig, otherRepo, otherMember)) {
            fx.host.interceptor = (req, honest) -> req.path().equals("/v1/prepare-join")
                    ? TestAvpHost.Response.json(200, Tokens.toJson(bad))
                    : honest.apply(req);
            assertEquals(
                    Kind.PROTOCOL,
                    failure(VaultEngine.prepareJoin(fx.connect(), bob, repoId)).kind());
        }
    }

    @Test
    void twoLeaveRequestsOfOneMemberRemoveItOnce() {
        VaultEngine owner = fx.create(newOwner());
        MemberKeys bobKeys = MemberKeys.generate();
        VaultEngine bob = fx.invite(owner, bobKeys);
        await(bob.leave());
        Tokens.LeaveRequest again =
                Tokens.signLeave(owner.repoId(), System.currentTimeMillis() + 1, bobKeys.ed25519Seed());
        onPull(answer -> {
            answer.getAsJsonArray("leaves").add(Tokens.toJson(again));
            return answer;
        });
        List<byte[]> removed = await(owner.processLeaves());
        assertEquals(1, removed.size());
        assertFalse(owner.tip().state().hasMember(bobKeys.ed25519Public()));
        assertEquals(3, owner.tip().state().manifestSeq(), "one removal, not two");
    }

    @Test
    void aBareBadRequestIsReportedByItsStatus() {
        VaultEngine owner = fx.create(newOwner());
        fx.host.interceptor = (req, honest) -> req.path().endsWith("/push")
                ? new TestAvpHost.Response(400, "Bad Request".getBytes(), Map.of("Content-Type", "text/plain"))
                : honest.apply(req);
        AltsException e = failure(owner.write(w -> w.setField(ACCOUNT, "a", new com.google.gson.JsonPrimitive("b"))));
        assertEquals(Kind.PROTOCOL, e.kind());
        assertTrue(e.getMessage().contains("400"));
        assertFalse(e.getMessage().contains("Bad Request"));
    }

    @Test
    void theHostsErrorTextIsNeverShown() {
        VaultEngine owner = fx.create(newOwner());
        String said = "HOST-TEXT-" + AvpBytes.hex(AvpCrypto.randomBytes(8));
        String code = "made-up-" + AvpBytes.hex(AvpCrypto.randomBytes(8));
        AtomicInteger n = new AtomicInteger();
        fx.host.interceptor = (req, honest) -> {
            if (!req.path().endsWith("/push")) {
                return honest.apply(req);
            }
            JsonObject err = new JsonObject();
            err.addProperty("error", said);
            err.addProperty("code", n.getAndIncrement() == 0 ? code : "forbidden");
            err.addProperty("detail", said);
            return TestAvpHost.Response.json(n.get() == 1 ? 409 : 403, err);
        };
        AltsException conflict =
                failure(owner.write(w -> w.setField(ACCOUNT, "a", new com.google.gson.JsonPrimitive("b"))));
        assertEquals(Kind.CONFLICT, conflict.kind());
        AltsException refused =
                failure(owner.write(w -> w.setField(ACCOUNT, "a", new com.google.gson.JsonPrimitive("c"))));
        assertEquals(Kind.UNAUTHORIZED, refused.kind());
        for (AltsException e : List.of(conflict, refused)) {
            assertFalse(e.getMessage().contains(said), e.getMessage());
            assertFalse(e.getMessage().contains(code), e.getMessage());
            assertFalse(String.valueOf(e.getCause()).contains(said));
            assertFalse(String.valueOf(e.getCause()).contains(code));
        }
    }

    @Test
    void aRateLimitCarriesTheStatedWait() {
        VaultEngine owner = fx.create(newOwner());
        fx.host.interceptor = (req, honest) -> req.path().endsWith("/pull")
                ? new TestAvpHost.Response(
                        429,
                        AvpJson.write(new JsonObject()),
                        Map.of("Retry-After", "7", "Content-Type", "application/json"))
                : honest.apply(req);
        AltsException e = failure(owner.pull());
        assertEquals(Kind.RATE_LIMITED, e.kind());
        assertEquals(Duration.ofSeconds(7), e.failure().retryAfter().orElseThrow());
    }

    @Test
    void aManifestConflictIsRetriedOnceAfterAFullRepullAndNeverMore() {
        VaultEngine owner = fx.create(newOwner());
        AtomicInteger publishes = new AtomicInteger();
        fx.host.interceptor = (req, honest) -> req.path().endsWith("/manifest") && publishes.getAndIncrement() == 0
                ? TestAvpHost.Response.error(409, "manifest_conflict", "stale")
                : honest.apply(req);
        await(owner.setShareRefreshTokens(true));
        assertEquals(2, publishes.get());
        assertTrue(owner.tip().state().shareRefreshTokens());

        fx.host.interceptor = (req, honest) -> req.path().endsWith("/manifest")
                ? TestAvpHost.Response.error(409, "manifest_conflict", "stale")
                : honest.apply(req);
        fx.host.clearLog();
        assertEquals(Kind.CONFLICT, failure(owner.setShareRefreshTokens(false)).kind());
        assertEquals(2, fx.host.count("/manifest"), "one publication and one retry");
        assertEquals(
                1,
                fx.host.requests().stream()
                        .filter(r -> r.path().endsWith("/pull")
                                && r.json().get("sinceManifestSeq").getAsLong() == 0)
                        .count(),
                "one re-pull from seq 0");
    }

    /** The host commits the request and then the answer is lost, or replaced by the answer to a retry. */
    private static TestAvpHost.Interceptor afterCommit(String path, TestAvpHost.Response instead) {
        return (req, honest) -> {
            TestAvpHost.Response r = honest.apply(req);
            return req.path().equals(path) || req.path().endsWith(path) ? instead : r;
        };
    }

    @Test
    void aPublicationWhoseAnswerWasLostIsDoneWhenTheStateLanded() {
        VaultEngine owner = fx.create(newOwner());
        fx.host.interceptor = afterCommit("/manifest", TestAvpHost.Response.error(502, "bad_gateway", "lost"));
        fx.host.clearLog();
        await(owner.setShareRefreshTokens(true));
        assertTrue(owner.tip().state().shareRefreshTokens());
        assertArrayEquals(Manifest.hash(fx.host.tip(owner.repoId())), owner.tipHash());
        assertEquals(1, fx.host.count("/manifest"), "never published twice");

        fx.host.interceptor = afterCommit("/manifest", TestAvpHost.Response.error(409, "manifest_conflict", "again"));
        MemberKeys bob = MemberKeys.generate();
        await(owner.invite(await(VaultEngine.prepareJoin(fx.connect(), bob, owner.repoId()))));
        assertTrue(owner.tip().state().hasMember(bob.ed25519Public()));

        // An answer lost before the host committed anything is the failure it was.
        fx.host.interceptor = (req, honest) -> req.path().endsWith("/manifest")
                ? TestAvpHost.Response.error(502, "bad_gateway", "lost")
                : honest.apply(req);
        assertEquals(Kind.NETWORK, failure(owner.setShareRefreshTokens(false)).kind());
        assertTrue(fx.host.tip(owner.repoId()).state().shareRefreshTokens());
    }

    @Test
    void aBareConflictOnAPublicationIsTerminal() {
        VaultEngine owner = fx.create(newOwner());
        fx.host.interceptor = (req, honest) -> req.path().endsWith("/manifest")
                ? new TestAvpHost.Response(409, new byte[0], Map.of())
                : honest.apply(req);
        fx.host.clearLog();
        assertEquals(Kind.CONFLICT, failure(owner.setShareRefreshTokens(true)).kind());
        assertEquals(1, fx.host.count("/manifest"), "no retry: a 409 without its code is not a manifest_conflict");
        assertEquals(1, fx.host.count("/pull"), "only the pull before publishing: no check and no re-pull");
    }

    @Test
    void aHostThatForgesTheStateOnTheCheckAfterALostPublicationFailsItWithProtocol() {
        VaultEngine owner = fx.create(newOwner());
        java.util.concurrent.atomic.AtomicBoolean published = new java.util.concurrent.atomic.AtomicBoolean();
        fx.host.interceptor = (req, honest) -> {
            TestAvpHost.Response r = honest.apply(req);
            if (req.path().endsWith("/manifest")) {
                published.set(true);
                return TestAvpHost.Response.error(502, "bad_gateway", "lost");
            }
            if (published.get() && req.path().endsWith("/pull")) {
                JsonObject a = r.json();
                JsonArray out = new JsonArray();
                for (JsonElement e : a.getAsJsonArray("manifests")) {
                    SignedManifest m = Manifest.signedFromJson(e);
                    ManifestState flipped = with(
                            m.state(),
                            !m.state().shareRefreshTokens(),
                            m.state().members());
                    out.add(Manifest.toJson(new SignedManifest(flipped, m.ownerSignature())));
                }
                a.add("manifests", out);
                return TestAvpHost.Response.json(200, a);
            }
            return r;
        };
        assertEquals(Kind.PROTOCOL, failure(owner.setShareRefreshTokens(true)).kind());
    }

    @Test
    void aCreationWhoseAnswerWasLostIsDoneWhenTheHostServesItsGenesis() {
        fx.host.interceptor = afterCommit("/v1/repos", TestAvpHost.Response.error(502, "bad_gateway", "lost"));
        VaultEngine owner = fx.create(newOwner());
        assertArrayEquals(Manifest.hash(fx.host.tip(owner.repoId())), owner.tipHash());
        set(owner, "username", "x");

        fx.host.interceptor = afterCommit("/v1/repos", TestAvpHost.Response.error(409, "duplicate_repo", "exists"));
        fx.create(newOwner());

        fx.host.interceptor = (req, honest) -> req.path().equals("/v1/repos")
                ? TestAvpHost.Response.error(502, "bad_gateway", "lost")
                : honest.apply(req);
        assertEquals(
                Kind.NETWORK,
                failure(VaultEngine.create(fx.connect(), newOwner().keys(), fx.clock))
                        .kind());
    }

    @Test
    void aLostCreationIsNotTakenForAnotherRepositorysGenesis() {
        VaultEngine foreign = fx.create(newOwner());
        SignedManifest foreignGenesis = fx.host.tip(foreign.repoId());
        fx.host.interceptor = (req, honest) -> {
            if (req.path().equals("/v1/repos")) {
                return TestAvpHost.Response.error(502, "bad_gateway", "lost before the host stored it");
            }
            if (req.path().endsWith("/pull")) {
                JsonObject a = new JsonObject();
                JsonArray ms = new JsonArray();
                ms.add(Manifest.toJson(foreignGenesis));
                a.add("manifests", ms);
                a.add("heads", new JsonArray());
                a.add("leaves", new JsonArray());
                return TestAvpHost.Response.json(200, a);
            }
            return honest.apply(req);
        };
        assertEquals(
                Kind.NETWORK,
                failure(VaultEngine.create(fx.connect(), newOwner().keys(), fx.clock))
                        .kind());
    }

    @Test
    void aHostThatLiesOnTheCheckAfterALostCreationFailsItWithProtocol() {
        fx.host.interceptor = (req, honest) -> {
            if (req.path().equals("/v1/repos")) {
                return TestAvpHost.Response.error(502, "bad_gateway", "lost");
            }
            if (req.path().endsWith("/pull")) {
                return new TestAvpHost.Response(200, "{\"manifests\":".getBytes(), Map.of());
            }
            return honest.apply(req);
        };
        assertEquals(
                Kind.PROTOCOL,
                failure(VaultEngine.create(fx.connect(), newOwner().keys(), fx.clock))
                        .kind());
    }

    @Test
    void missingParentsAreRetriedWhileTheHostFetchesThem() {
        VaultEngine owner = fx.create(newOwner());
        AtomicInteger pushes = new AtomicInteger();
        fx.host.interceptor = (req, honest) -> req.path().endsWith("/push") && pushes.getAndIncrement() < 2
                ? TestAvpHost.Response.error(422, "missing_parents", "fetching")
                : honest.apply(req);
        set(owner, "username", "x");
        assertEquals(3, pushes.get());
        assertEquals("x", field(owner.payload(), "username"));
    }

    @Test
    void aLeaveRequestByTheOwnerOrForAnotherRepositoryIsNeverActedOn() {
        VaultFixture.Owner o = newOwner();
        VaultEngine owner = fx.create(o);
        VaultEngine bob = fx.invite(owner, MemberKeys.generate());
        fx.host.addLeave(Tokens.signLeave(
                owner.repoId(), System.currentTimeMillis(), o.keys().ed25519Seed()));
        PullReport r = await(owner.pull());
        assertTrue(r.leaves().isEmpty());
        assertTrue(await(owner.processLeaves()).isEmpty());
        assertEquals(2, owner.tip().state().manifestSeq());
        assertTrue(owner.tip().state().hasMember(bob.member().ed25519Public()));
    }

    @Test
    void theChallengeIsSignedAsTheTranscriptForThisHostsKey() {
        List<JsonObject> redeemed = new ArrayList<>();
        fx.host.interceptor = (req, honest) -> {
            if (req.path().equals("/api/auth/keypair/token")) {
                redeemed.add(req.json());
            }
            return honest.apply(req);
        };
        fx.create(newOwner());
        assertEquals(1, redeemed.size());
        JsonObject t = redeemed.get(0);
        byte[] subject = AvpJson.bytes(t, "ed25519PublicKey", 32);
        byte[] nonce = AvpJson.bytes(t, "nonce");
        byte[] sig = AvpJson.bytes(t, "signature", 64);
        assertTrue(Challenge.verify(fx.host.key(), subject, nonce, sig));
        assertFalse(Ed25519Strict.verify(subject, nonce, sig), "never the raw nonce");
    }

    @Test
    void aTokenIsOnlyEverPresentedToTheHostThatMintedIt() throws Exception {
        TestAvpHost b = fx.anotherHost();
        VaultEngine owner = fx.create(newOwner());
        MemberKeys bob = MemberKeys.generate();
        await(owner.invite(await(VaultEngine.prepareJoin(fx.connect(b), bob, owner.repoId()))));
        set(owner, "username", "x");
        for (TestAvpHost h : List.of(fx.host, b)) {
            for (TestAvpHost.Request r : h.requests()) {
                String auth = r.header("Authorization");
                if (auth != null) {
                    assertTrue(h.tokensMintedUnder(h.key()).contains(auth.substring("Bearer ".length())));
                }
            }
        }

        // The host at the same address becomes another host: a token of the first is never presented to it.
        byte[] first = fx.host.key();
        fx.host.rekey();
        fx.host.clearLog();
        HostClient again = fx.connect();
        assertFalse(AvpBytes.same(first, again.key()));
        // It is not listed in the repository either, so the open is refused once the chain is checked.
        assertEquals(
                Kind.PROTOCOL,
                failure(VaultEngine.open(again, owner.member(), owner.repoId(), fx.clock))
                        .kind());
        for (TestAvpHost.Request r : fx.host.requests()) {
            String auth = r.header("Authorization");
            if (auth != null) {
                assertFalse(fx.host.tokensMintedUnder(first).contains(auth.substring("Bearer ".length())));
            }
        }
    }

    @Test
    void aVaultIsNeverOpenedFromAHostItsVerifiedStateDoesNotList() {
        VaultEngine owner = fx.create(newOwner());
        set(owner, "username", "x");
        fx.host.rekey();
        HostClient unlisted = fx.connect();
        assertEquals(
                Kind.PROTOCOL,
                failure(VaultEngine.open(unlisted, owner.member(), owner.repoId(), fx.clock))
                        .kind());
        assertEquals(
                Kind.PROTOCOL,
                failure(VaultEngine.resume(unlisted, owner.member(), owner.state(), fx.clock))
                        .kind());
    }

    @Test
    void aVaultIsOpenedJoinedAndResumedOnlyFromTheMembersHomeHost() throws Exception {
        VaultEngine owner = fx.create(newOwner());
        TestAvpHost home = fx.anotherHost();
        MemberKeys bobKeys = MemberKeys.generate();
        await(owner.invite(await(VaultEngine.prepareJoin(fx.connect(home), bobKeys, owner.repoId()))));
        // Bob's home host is the other one. The owner's host is listed too, but it is not his to sync through.
        assertEquals(
                Kind.PROTOCOL,
                failure(VaultEngine.open(fx.connect(), bobKeys, owner.repoId(), fx.clock))
                        .kind());
        assertEquals(
                Kind.PROTOCOL,
                failure(VaultEngine.join(fx.connect(), bobKeys, owner.locator(), fx.clock))
                        .kind());
        EngineState state = new EngineState(
                owner.repoId(), owner.state().chainHashes(), new java.util.TreeMap<>(), 0, 0, Payload.EMPTY, false);
        assertEquals(
                Kind.PROTOCOL,
                failure(VaultEngine.resume(fx.connect(), bobKeys, state, fx.clock))
                        .kind());
        await(VaultEngine.open(fx.connect(), owner.member(), owner.repoId(), fx.clock));
        await(VaultEngine.resume(fx.connect(), owner.member(), owner.state(), fx.clock));
    }

    @Test
    void anImpostorThatServesTheHostsKeyNeverReceivesTheHostsToken() throws Exception {
        VaultEngine owner = fx.create(newOwner());
        byte[] realKey = fx.host.key();
        TestAvpHost impostor = fx.anotherHost();
        impostor.interceptor = (req, honest) -> {
            TestAvpHost.Response r = honest.apply(req);
            if (req.path().equals("/.well-known/avp")) {
                JsonObject o = r.json();
                o.addProperty("hostKey", AvpBytes.base64(realKey));
                return TestAvpHost.Response.json(200, o);
            }
            return r;
        };
        // Discovery is unauthenticated: the impostor passes the key check, but the cached token stays put.
        HostClient connected = HostClient.connect(fx.transport, impostor.base(), realKey, fx.tokens, fx.clock);
        failure(VaultEngine.open(connected, owner.member(), owner.repoId(), fx.clock));
        Set<String> minted = fx.host.tokensMintedUnder(realKey);
        assertFalse(minted.isEmpty());
        assertTrue(impostor.count("/api/auth/keypair/challenge") >= 1, "the client signed in afresh there");
        for (TestAvpHost.Request r : impostor.requests()) {
            String auth = r.header("Authorization");
            if (auth != null) {
                assertFalse(minted.contains(auth.substring("Bearer ".length())), "the real host's token leaked");
            }
        }
    }

    @Test
    void aMintedTokenThatIsNotAHeaderValueIsRefusedBeforeItIsSent() {
        fx.host.interceptor = (req, honest) -> {
            TestAvpHost.Response r = honest.apply(req);
            if (req.path().equals("/api/auth/keypair/token") && r.status() == 200) {
                JsonObject o = r.json();
                o.addProperty("token", "abc\r\nX-Injected: 1");
                return TestAvpHost.Response.json(200, o);
            }
            return r;
        };
        AltsException e = failure(VaultEngine.create(fx.connect(), newOwner().keys(), fx.clock));
        assertEquals(Kind.PROTOCOL, e.kind());
        assertEquals(0, fx.host.count("/v1/repos"), "nothing was sent with it");
    }

    @Test
    void aRefusedTokenIsReplacedOnceAndASecondRefusalIsTheFailure() {
        VaultEngine owner = fx.create(newOwner());
        AtomicInteger refusals = new AtomicInteger(1);
        fx.host.interceptor = (req, honest) -> req.path().endsWith("/pull") && refusals.getAndDecrement() > 0
                ? TestAvpHost.Response.error(401, "unauthorized", "expired")
                : honest.apply(req);
        fx.host.clearLog();
        await(owner.pull());
        assertEquals(1, fx.host.count("/api/auth/keypair/token"), "one fresh token after the refusal");
        assertEquals(2, fx.host.count("/pull"));

        fx.host.interceptor = (req, honest) -> req.path().endsWith("/pull")
                ? TestAvpHost.Response.error(401, "unauthorized", "expired")
                : honest.apply(req);
        fx.host.clearLog();
        assertEquals(Kind.UNAUTHORIZED, failure(owner.pull()).kind());
        assertEquals(2, fx.host.count("/pull"), "one retry, never a loop");
    }

    @Test
    void anAnswerUpToSixteenMebibytesIsReadAndALargerOneIsRefused() {
        VaultEngine owner = fx.create(newOwner());
        String pad = "p".repeat(3 << 19);
        onPull(answer -> {
            answer.addProperty("pad", pad);
            return answer;
        });
        await(owner.pull());
        String huge = "p".repeat((16 << 20) + 1);
        onPull(answer -> {
            answer.addProperty("pad", huge);
            return answer;
        });
        assertEquals(Kind.NETWORK, failure(owner.pull()).kind());
    }

    @Test
    void aHostKeyOtherThanTheExpectedOneIsRefusedAtConnect() {
        AltsException e = org.junit.jupiter.api.Assertions.assertThrows(
                AltsException.class,
                () -> HostClient.connect(fx.transport, fx.host.base(), AvpCrypto.randomBytes(32), fx.tokens, fx.clock));
        assertEquals(Kind.PROTOCOL, e.kind());
        HostClient.connect(fx.transport, fx.host.base(), fx.host.key(), fx.tokens, fx.clock);
    }

    @Test
    void aRepositoryIdIsPercentEncodedAsOnePathSegment() {
        assertEquals("/v1/repos/abc_-AZ09/pull", HostClient.repoPath("abc_-AZ09", "pull"));
        assertEquals("/v1/repos/a%2Fb%25c%20%C3%A9/push", HostClient.repoPath("a/b%c é", "push"));
    }
}

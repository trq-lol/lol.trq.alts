package lol.trq.alts.internal.avp;

import static lol.trq.alts.internal.avp.Vectors.hex;
import static lol.trq.alts.internal.avp.Vectors.obj;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonObject;
import java.util.ArrayList;
import java.util.List;
import lol.trq.alts.internal.avp.AvpCrypto.WrapLabel;
import lol.trq.alts.internal.avp.Manifest.ManifestState;
import lol.trq.alts.internal.avp.Manifest.MemberEntry;
import lol.trq.alts.internal.avp.Manifest.Removal;
import lol.trq.alts.internal.avp.Manifest.SignedManifest;
import lol.trq.alts.internal.avp.ManifestRules.Verdict;
import org.junit.jupiter.api.Test;

/**
 * SPEC 6.1 rules the acceptance scenarios leave unpinned, each on a state owner-signed here from the
 * {@code manifest.json} seeds. Every refusal comes with the same state, the one change undone, accepted,
 * so the change is shown to be the cause; and each verdict is the first rule the SPEC orders.
 */
class ManifestRulesTest {

    private static final JsonObject ROOT = Vectors.load("manifest.json");
    private static final byte[] OWNER_SEED = hex(obj(ROOT.getAsJsonObject("seeds"), "owner"), "ed25519SeedHex");
    private static final byte[] DATA_KEY_0 = hex("4242424242424242424242424242424242424242424242424242424242424242");

    private static SignedManifest state(int index) {
        return Manifest.signedFromJson(
                Vectors.cases(ROOT, "cases", 4).get(index).get("signedManifest"));
    }

    private static ManifestState copy(
            ManifestState s, long seq, byte[] prevHash, long epoch, List<MemberEntry> members, List<Removal> removals) {
        return new ManifestState(
                s.repoId(),
                seq,
                prevHash,
                s.ownerKey(),
                s.genesisNonce(),
                s.schemeId(),
                epoch,
                s.shareRefreshTokens(),
                s.hosts(),
                members,
                removals);
    }

    /** SPEC 6.1 rule 5: a new removal names this state's seq; here it names seq 2 in the seq 3 state. */
    @Test
    void aNewRemovalMustNameThisStatesSeq() {
        SignedManifest prev = state(1);
        ManifestState s = state(2).state();
        assertEquals(3, s.manifestSeq());
        Removal bob = s.removals().get(0);
        assertEquals(3, bob.removedAtSeq());
        ManifestState backdated = copy(
                s,
                3,
                s.prevManifestHash(),
                s.keyEpoch(),
                s.members(),
                List.of(new Removal(bob.memberKey(), 2, bob.frontier())));
        assertEquals(Verdict.BAD_CONTENT, ManifestRules.check(Manifest.sign(backdated, OWNER_SEED), prev));
        assertEquals(Verdict.OK, ManifestRules.check(Manifest.sign(s, OWNER_SEED), prev), "undone");
    }

    /** SPEC 6.1 rule 5: the epoch stays or rises by one; one below the previous epoch is refused. */
    @Test
    void theKeyEpochNeverDecreases() {
        SignedManifest prev = state(3);
        ManifestState p = prev.state();
        assertEquals(1, p.keyEpoch());
        byte[] prevHash = Manifest.hash(prev);
        assertEquals(Verdict.BAD_CONTENT, ManifestRules.check(next(p, prevHash, 0), prev), "epoch 0 after epoch 1");
        assertEquals(Verdict.OK, ManifestRules.check(next(p, prevHash, 1), prev), "undone: the same epoch");
    }

    private static SignedManifest next(ManifestState p, byte[] prevHash, long epoch) {
        List<MemberEntry> members = new ArrayList<>();
        for (MemberEntry m : p.members()) {
            WrappedKey wrap = epoch == p.keyEpoch()
                    ? m.wrappedDataKey()
                    : AvpCrypto.wrap(m.x25519PublicKey(), DATA_KEY_0, WrapLabel.DATA_KEY);
            members.add(new MemberEntry(m.ed25519PublicKey(), m.x25519PublicKey(), wrap, epoch, m.homeHostKey()));
        }
        return Manifest.sign(copy(p, p.manifestSeq() + 1, prevHash, epoch, members, p.removals()), OWNER_SEED);
    }

    /** SPEC 6.1 rule 1 before rule 2: a member listed twice is malformed, whatever the signature. */
    @Test
    void aDuplicateMemberIsMalformed() {
        SignedManifest m = state(1);
        List<MemberEntry> members = new ArrayList<>(m.state().members());
        members.add(members.get(0));
        ManifestState s = m.state();
        SignedManifest twice = new SignedManifest(
                copy(s, s.manifestSeq(), s.prevManifestHash(), s.keyEpoch(), members, s.removals()),
                m.ownerSignature());
        assertEquals(Verdict.MALFORMED, ManifestRules.check(twice, state(0)));
        assertEquals(Verdict.OK, ManifestRules.check(m, state(0)), "undone");
    }

    /** SPEC 6.1 rule 1: a frontier listing one commit id twice is malformed. */
    @Test
    void aDuplicateFrontierIdIsMalformed() {
        SignedManifest m = state(2);
        ManifestState s = m.state();
        Removal r = s.removals().get(0);
        Removal doubled = new Removal(
                r.memberKey(),
                r.removedAtSeq(),
                List.of(r.frontier().get(0), r.frontier().get(0)));
        SignedManifest bad = new SignedManifest(
                copy(s, s.manifestSeq(), s.prevManifestHash(), s.keyEpoch(), s.members(), List.of(doubled)),
                m.ownerSignature());
        assertEquals(Verdict.MALFORMED, ManifestRules.check(bad, state(1)));
        assertEquals(Verdict.OK, ManifestRules.check(m, state(1)), "undone");
    }

    /** SPEC 6.2 (rule 3) before the content rules: a genesis whose sole member is not the owner. */
    @Test
    void aGenesisWhoseSoleMemberIsNotTheOwnerIsABadGenesis() {
        ManifestState g = state(0).state();
        MemberEntry alice = state(1).state().members().stream()
                .filter(x -> !AvpBytes.same(x.ed25519PublicKey(), g.ownerKey()))
                .findFirst()
                .orElseThrow();
        MemberEntry asGenesis = new MemberEntry(
                alice.ed25519PublicKey(), alice.x25519PublicKey(), alice.wrappedDataKey(), 0, alice.homeHostKey());
        ManifestState other = copy(g, 1, g.prevManifestHash(), 0, List.of(asGenesis), List.of());
        assertEquals(Verdict.BAD_GENESIS, ManifestRules.check(Manifest.sign(other, OWNER_SEED), null));
        assertEquals(Verdict.OK, ManifestRules.check(Manifest.sign(g, OWNER_SEED), null), "undone");
    }

    /** SPEC 5.1: on the wire, an absent shareRefreshTokens means false, and the signature still holds. */
    @Test
    void anAbsentSharingFlagReadsFalse() {
        JsonObject wire = Vectors.cases(ROOT, "cases", 4)
                .get(0)
                .getAsJsonObject("signedManifest")
                .deepCopy();
        JsonObject state = wire.getAsJsonObject("state");
        assertFalse(state.get("shareRefreshTokens").getAsBoolean());
        state.remove("shareRefreshTokens");
        SignedManifest m = Manifest.signedFromJson(wire);
        assertFalse(m.state().shareRefreshTokens());
        assertTrue(Manifest.verify(m));
    }

    /** SPEC 4.2: removals are encoded sorted by memberKey, as unsigned bytes, whatever the wire order. */
    @Test
    void removalsAreSortedByMemberKey() {
        ManifestState s = state(2).state();
        List<byte[]> keys = new ArrayList<>();
        for (MemberEntry m : state(1).state().members()) {
            if (!AvpBytes.same(m.ed25519PublicKey(), s.ownerKey())) {
                keys.add(m.ed25519PublicKey());
            }
        }
        List<Removal> removals = new ArrayList<>();
        for (byte[] k : keys) {
            removals.add(new Removal(k, 3, List.of()));
        }
        List<Removal> reversed = new ArrayList<>(removals);
        java.util.Collections.reverse(reversed);
        byte[] a = Manifest.encode(copy(s, 3, s.prevManifestHash(), 1, s.members(), removals));
        byte[] b = Manifest.encode(copy(s, 3, s.prevManifestHash(), 1, s.members(), reversed));
        assertArrayEquals(a, b);

        List<byte[]> sorted = AvpBytes.sortedUnique(keys, "key");
        int last = -1;
        for (byte[] k : sorted) {
            int at = indexOf(a, k, last + 1);
            assertTrue(at > last, "removed keys appear in unsigned order");
            last = at;
        }
        assertTrue(keys.size() >= 2 && AvpBytes.compare(sorted.get(0), sorted.get(1)) < 0);
    }

    private static int indexOf(byte[] haystack, byte[] needle, int from) {
        // The removals follow the members, so search from the last occurrence of each key.
        int found = -1;
        for (int i = from; i <= haystack.length - needle.length; i++) {
            boolean match = true;
            for (int j = 0; j < needle.length && match; j++) {
                match = haystack[i + j] == needle[j];
            }
            if (match) {
                found = i;
            }
        }
        return found;
    }
}

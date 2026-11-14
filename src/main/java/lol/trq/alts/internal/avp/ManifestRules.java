package lol.trq.alts.internal.avp;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import lol.trq.alts.internal.avp.Manifest.ManifestState;
import lol.trq.alts.internal.avp.Manifest.MemberEntry;
import lol.trq.alts.internal.avp.Manifest.Removal;
import lol.trq.alts.internal.avp.Manifest.SignedManifest;

/**
 * The client's check of one manifest state (AVP SPEC 6.1 rules 1 to 5, and 6.2 at genesis), evaluated in
 * the order the SPEC gives, first failure wins.
 *
 * <p>Rule 6 (hosted) is a host's rule and is not here. So is everything a host does with a state that
 * does not extend its tip (SPEC 6.5 losing states); a client only ever extends the chain it verified, and
 * a state that does not link to the client's state at the previous seq is {@link Verdict#NOT_LINKED}.
 *
 * <p>Ported from the Alt Vault Protocol reference implementation (MIT).
 *
 * @author trq
 * @since 1.0.0
 */
public final class ManifestRules {

    private ManifestRules() {}

    /** The outcome of a check, with the SPEC 10.4 code a host would answer for it. */
    public enum Verdict {
        /** The state passes every rule. */
        OK(null),
        /** Rule 1: a binary field of the wrong length, a counter out of range, or a repeated list key. */
        MALFORMED("bad_request"),
        /** Rule 2: the owner signature does not verify under {@code ownerKey}. */
        BAD_SIGNATURE("bad_request"),
        /** Rule 3 (SPEC 6.2): not a valid genesis, a recomputed repository id included. */
        BAD_GENESIS("bad_request"),
        /** Rule 4 (SPEC 6.3): not the next seq after, or not hash-linked to, the previous state. */
        NOT_LINKED("manifest_conflict"),
        /** Rule 5: a content rule fails, on its own or against the previous state. */
        BAD_CONTENT("bad_request");

        private final String code;

        Verdict(String code) {
            this.code = code;
        }

        /**
         * The SPEC 10.4 code of this verdict.
         *
         * @return the code, or empty for {@link #OK}
         */
        public Optional<String> code() {
            return Optional.ofNullable(code);
        }
    }

    /**
     * Checks a state against the previous one.
     *
     * @param next the state to check
     * @param prev the verified state it should extend, or {@code null} when {@code next} should be the
     *     genesis
     * @return the first rule that fails, or {@link Verdict#OK}
     * @throws NullPointerException if an argument or one of its fields is null
     */
    public static Verdict check(SignedManifest next, SignedManifest prev) {
        if (!shapeOk(next)) {
            return Verdict.MALFORMED;
        }
        if (!Manifest.verify(next)) {
            return Verdict.BAD_SIGNATURE;
        }
        ManifestState s = next.state();
        if (s.manifestSeq() == 1) {
            if (!genesisOk(s)) {
                return Verdict.BAD_GENESIS;
            }
            if (prev != null) {
                return Verdict.NOT_LINKED;
            }
            return contentOk(s, null) ? Verdict.OK : Verdict.BAD_CONTENT;
        }
        if (prev == null || !Manifest.linksTo(next, prev)) {
            return Verdict.NOT_LINKED;
        }
        return contentOk(s, prev.state()) ? Verdict.OK : Verdict.BAD_CONTENT;
    }

    /**
     * Rule 1: every binary field has its length, the counters are in range, no list repeats a key, and
     * the state encodes.
     */
    static boolean shapeOk(SignedManifest m) {
        ManifestState s = m.state();
        if (s.manifestSeq() < 1 || s.keyEpoch() < 0 || s.ownerKey().length != 32 || m.ownerSignature().length != 64) {
            return false;
        }
        boolean genesis = s.manifestSeq() == 1;
        if (s.prevManifestHash().length != (genesis ? 0 : 32) || s.genesisNonce().length != (genesis ? 16 : 0)) {
            return false;
        }
        List<byte[]> hosts = new ArrayList<>();
        for (Manifest.HostRef h : s.hosts()) {
            if (h.hostKey().length != 32) {
                return false;
            }
            hosts.add(h.hostKey());
        }
        List<byte[]> members = new ArrayList<>();
        for (MemberEntry x : s.members()) {
            WrappedKey wk = x.wrappedDataKey();
            boolean ok = x.keyEpoch() >= 0
                    && x.ed25519PublicKey().length == 32
                    && x.x25519PublicKey().length == 32
                    && x.homeHostKey().length == 32
                    && wk.ephemeralPublicKey().length == 32
                    && wk.iv().length == 12
                    && wk.ciphertext().length == 48;
            if (!ok) {
                return false;
            }
            members.add(x.ed25519PublicKey());
        }
        List<byte[]> removed = new ArrayList<>();
        for (Removal r : s.removals()) {
            if (r.memberKey().length != 32 || !distinct(r.frontier())) {
                return false;
            }
            for (byte[] id : r.frontier()) {
                if (id.length != 32) {
                    return false;
                }
            }
            removed.add(r.memberKey());
        }
        return distinct(hosts) && distinct(members) && distinct(removed);
    }

    /** SPEC 6.2: empty previous hash, a 16-byte nonce, epoch 0, no removals, the owner alone, the id. */
    static boolean genesisOk(ManifestState s) {
        if (s.prevManifestHash().length != 0
                || s.genesisNonce().length != 16
                || s.keyEpoch() != 0
                || !s.removals().isEmpty()
                || s.members().size() != 1
                || !AvpBytes.same(s.members().get(0).ed25519PublicKey(), s.ownerKey())) {
            return false;
        }
        return AvpBytes.same(Manifest.deriveRepoId(s.ownerKey(), s.genesisNonce()), s.repoId());
    }

    /** Rule 5: the content rules, and against {@code prev} when there is one. */
    static boolean contentOk(ManifestState s, ManifestState prev) {
        if (s.hosts().isEmpty()) {
            return false;
        }
        long owners = s.members().stream()
                .filter(x -> AvpBytes.same(x.ed25519PublicKey(), s.ownerKey()))
                .count();
        if (owners != 1) {
            return false;
        }
        for (MemberEntry x : s.members()) {
            if (x.keyEpoch() != s.keyEpoch()
                    || !s.hasHost(x.homeHostKey())
                    || s.removalOf(x.ed25519PublicKey()).isPresent()) {
                return false;
            }
        }
        for (Removal r : s.removals()) {
            if (r.removedAtSeq() < 2 || r.removedAtSeq() > s.manifestSeq()) {
                return false;
            }
        }
        if (prev == null) {
            return true;
        }

        if (!AvpBytes.same(s.repoId(), prev.repoId())
                || !AvpBytes.same(s.ownerKey(), prev.ownerKey())
                || !s.schemeId().equals(prev.schemeId())
                || s.genesisNonce().length != 0) {
            return false;
        }
        boolean raised = isNext(prev.keyEpoch(), s.keyEpoch());
        if (s.keyEpoch() != prev.keyEpoch() && !raised) {
            return false;
        }
        for (Removal r : prev.removals()) {
            Optional<Removal> same = s.removalOf(r.memberKey());
            if (same.isEmpty()
                    || same.get().removedAtSeq() != r.removedAtSeq()
                    || !sameIds(same.get().frontier(), r.frontier())) {
                return false;
            }
        }
        Set<String> added = new HashSet<>();
        for (Removal r : s.removals()) {
            if (prev.removalOf(r.memberKey()).isEmpty()) {
                if (r.removedAtSeq() != s.manifestSeq() || !prev.hasMember(r.memberKey())) {
                    return false;
                }
                added.add(AvpBytes.base64(r.memberKey()));
            }
        }
        for (MemberEntry x : prev.members()) {
            if (s.hasMember(x.ed25519PublicKey())) {
                continue;
            }
            if (AvpBytes.same(x.ed25519PublicKey(), s.ownerKey())
                    || !added.contains(AvpBytes.base64(x.ed25519PublicKey()))) {
                return false;
            }
        }
        return added.isEmpty() || raised;
    }

    /** Whether {@code epoch} is {@code prev + 1}, without overflow. */
    static boolean isNext(long prev, long epoch) {
        return prev != Long.MAX_VALUE && prev + 1 == epoch;
    }

    private static boolean distinct(List<byte[]> ids) {
        Set<String> seen = new HashSet<>();
        for (byte[] id : ids) {
            if (!seen.add(AvpBytes.base64(id))) {
                return false;
            }
        }
        return true;
    }

    private static boolean sameIds(List<byte[]> a, List<byte[]> b) {
        if (a.size() != b.size()) {
            return false;
        }
        Set<String> x = new HashSet<>();
        for (byte[] id : a) {
            x.add(AvpBytes.base64(id));
        }
        for (byte[] id : b) {
            if (!x.contains(AvpBytes.base64(id))) {
                return false;
            }
        }
        return true;
    }
}

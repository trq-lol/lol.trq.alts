package lol.trq.alts.internal.vault;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import lol.trq.alts.AltsException;
import lol.trq.alts.internal.avp.AvpBytes;
import lol.trq.alts.internal.avp.Commits;
import lol.trq.alts.internal.avp.Commits.Commit;
import lol.trq.alts.internal.avp.Manifest;
import lol.trq.alts.internal.avp.Manifest.ManifestState;
import lol.trq.alts.internal.avp.Manifest.Removal;
import lol.trq.alts.internal.avp.Manifest.SignedManifest;
import lol.trq.alts.internal.avp.ManifestRules;

/**
 * A client's verified manifest chain, from genesis to the pinned tip (AVP SPEC 6), and the client's checks
 * of a pulled commit against it (SPEC 7.5).
 *
 * <p>Every state on the chain passed {@link ManifestRules#check} against the one before it, so the chain is
 * never empty and its genesis fixes the repository id and the owner key. The pin of SPEC 6.4 is the tip.
 * Not thread safe: the vault that owns a chain serializes its operations.
 *
 * @author trq
 * @since 1.0.0
 */
public final class VerifiedChain {

    private final List<SignedManifest> states;
    private final List<byte[]> hashes;

    private VerifiedChain(List<SignedManifest> states, List<byte[]> hashes) {
        this.states = states;
        this.hashes = hashes;
    }

    /**
     * Checks one state against the state before it, or as a genesis when there is none.
     *
     * @param next the state
     * @param prev the verified state at {@code next}'s seq minus one, or {@code null}
     * @return the state's {@code manifestHash}
     * @throws AltsException of kind {@code PROTOCOL} naming the first rule that fails
     */
    static byte[] validate(SignedManifest next, SignedManifest prev) {
        ManifestRules.Verdict v = ManifestRules.check(next, prev);
        if (v != ManifestRules.Verdict.OK) {
            throw VaultFailures.protocol("the host served a manifest state that does not verify ("
                    + v.name().toLowerCase(java.util.Locale.ROOT) + ")");
        }
        return Manifest.hash(next);
    }

    /**
     * A chain of one genesis state.
     *
     * @param genesis the genesis
     * @return the chain
     * @throws AltsException of kind {@code PROTOCOL} if it is not a valid genesis
     */
    public static VerifiedChain genesis(SignedManifest genesis) {
        byte[] h = validate(genesis, null);
        List<SignedManifest> s = new ArrayList<>();
        s.add(genesis);
        List<byte[]> hs = new ArrayList<>();
        hs.add(h);
        return new VerifiedChain(s, hs);
    }

    /**
     * A whole chain served from seq 0: every state must verify, genesis first.
     *
     * @param served the states in the order served
     * @return the chain
     * @throws AltsException of kind {@code PROTOCOL} if the list is empty or a state fails: a host that
     *     serves a state that does not verify is not following the protocol, so nothing of it is used
     */
    public static VerifiedChain of(List<SignedManifest> served) {
        if (served.isEmpty()) {
            throw VaultFailures.protocol("the host served no manifest state");
        }
        VerifiedChain c = genesis(served.get(0));
        for (SignedManifest m : served.subList(1, served.size())) {
            c.extend(m);
        }
        return c;
    }

    /**
     * Appends a state that extends the tip.
     *
     * @param next the state
     * @throws AltsException of kind {@code PROTOCOL} if it does not verify against the tip
     */
    public void extend(SignedManifest next) {
        byte[] h = validate(next, tip());
        states.add(next);
        hashes.add(h);
    }

    /**
     * An independent copy, to change and then adopt or drop.
     *
     * @return the copy
     */
    public VerifiedChain copy() {
        return new VerifiedChain(new ArrayList<>(states), new ArrayList<>(hashes));
    }

    /**
     * The number of states, which is the tip's seq.
     *
     * @return the size
     */
    public int size() {
        return states.size();
    }

    /**
     * The states, genesis first.
     *
     * @return a read-only copy
     */
    public List<SignedManifest> states() {
        return List.copyOf(states);
    }

    /**
     * The {@code manifestHash} of every state, genesis first: the form the pin is persisted in.
     *
     * @return copies of the hashes
     */
    public List<byte[]> hashes() {
        return HostClient.copyIds(hashes);
    }

    /**
     * The pinned tip.
     *
     * @return the highest verified state
     */
    public SignedManifest tip() {
        return states.get(states.size() - 1);
    }

    /**
     * The {@code manifestHash} of the tip.
     *
     * @return a copy
     */
    public byte[] tipHash() {
        return hashes.get(hashes.size() - 1).clone();
    }

    /**
     * The repository id the genesis fixed.
     *
     * @return the repoId
     */
    public String repoId() {
        return states.get(0).state().repoId();
    }

    /**
     * The owner key the genesis fixed.
     *
     * @return a copy
     */
    public byte[] ownerKey() {
        return states.get(0).state().ownerKey().clone();
    }

    /**
     * The state at a seq, if the chain has one.
     *
     * @param seq the seq
     * @return the state
     */
    public Optional<SignedManifest> at(long seq) {
        return seq >= 1 && seq <= states.size() ? Optional.of(states.get((int) (seq - 1))) : Optional.empty();
    }

    // --- Rollback protection and the tie rule (SPEC 6.4, 6.5) -----------------------------------

    /**
     * The index of the first state at which two chains differ, or {@code -1} when one is a prefix of the
     * other.
     *
     * @param mine one chain's hashes, genesis first
     * @param theirs the other's
     * @return the fork index (seq minus one), or {@code -1}
     */
    static int fork(List<byte[]> mine, List<byte[]> theirs) {
        int n = Math.min(mine.size(), theirs.size());
        for (int i = 0; i < n; i++) {
            if (!AvpBytes.same(mine.get(i), theirs.get(i))) {
                return i;
            }
        }
        return -1;
    }

    /**
     * SPEC 6.4 with its 6.5 exception, over the hashes of the client's verified chain ({@code pinned}, whose
     * last entry is the pin) and a candidate chain: the candidate is adopted when it contains the pinned
     * state, or when it diverges at a fork point at or below the pin, never at genesis (which fixes the
     * repository), and its state there has the bytewise-lower {@code manifestHash}. A winner may end below
     * the pin.
     *
     * @param pinned the client's chain
     * @param candidate the chain a host served
     * @return whether to adopt the candidate
     */
    public static boolean accepts(List<byte[]> pinned, List<byte[]> candidate) {
        int i = fork(pinned, candidate);
        if (i < 0) {
            return candidate.size() >= pinned.size();
        }
        return i > 0 && AvpBytes.compare(candidate.get(i), pinned.get(i)) < 0;
    }

    /**
     * {@link #accepts(List, List)} against this chain.
     *
     * @param candidate the chain a host served
     * @return whether to adopt it
     */
    public boolean accepts(VerifiedChain candidate) {
        return accepts(hashes, candidate.hashes);
    }

    // --- Commit checks (SPEC 7.5) ----------------------------------------------------------------

    /** The outcome of the client checks on one commit, in the SPEC order. */
    public enum CommitVerdict {
        /** The commit passes every check. */
        OK,
        /** Rule 1: another repository, a malformed header, an id that does not recompute, a bad signature. */
        BAD_ID_OR_SIGNATURE,
        /** Rule 2: a removed member's commit that is neither in the removal's frontier nor an ancestor of it. */
        AFTER_REMOVAL_CUTOFF,
        /** Rule 3: the author is not a member at the commit's epoch of the state it cites, or of any later one. */
        NOT_A_MEMBER_AT_EPOCH
    }

    /**
     * The commit graph a client has learned, for the ancestry of the removal cutoff (SPEC 7.3): the parents of
     * every commit header whose id recomputes and whose signature verifies, whether or not it was accepted.
     * Since an id is the hash of a header that names the parents, no forgery can add an edge.
     */
    public static final class Ancestry {

        /**
         * The most headers one vault learns. Every header comes from a host, so the graph is bounded; past the
         * bound new headers are not learned. That fails closed: a missing edge can only make a removed member's
         * ancestor of a frontier commit look like a commit after the cutoff, which is then discarded.
         */
        public static final int MAX_HEADERS = 65_536;

        private final Map<String, List<byte[]>> parents = new HashMap<>();
        private final int cap;

        /** An empty graph, bounded by {@link #MAX_HEADERS}. */
        public Ancestry() {
            this(MAX_HEADERS);
        }

        Ancestry(int cap) {
            this.cap = cap;
        }

        /**
         * A copy of the graph.
         *
         * @return the copy
         */
        public Ancestry copy() {
            Ancestry a = new Ancestry(cap);
            a.parents.putAll(parents);
            return a;
        }

        /**
         * Learns a commit's parents, if its id recomputes, its signature verifies, and the graph is not full.
         *
         * @param c the commit
         */
        public void learn(Commit c) {
            boolean room = parents.size() < cap || parents.containsKey(AvpBytes.base64(c.commitId()));
            if (room && Commits.verify(c)) {
                parents.put(AvpBytes.base64(c.commitId()), c.parents());
            }
        }

        /**
         * Whether the header of a commit was learned.
         *
         * @param id the commit id
         * @return whether its parents are known
         */
        public boolean knows(byte[] id) {
            return parents.containsKey(AvpBytes.base64(id));
        }

        /**
         * The parents learned for an id.
         *
         * @param id the commit id
         * @return its parents, or empty if the commit is unknown
         */
        List<byte[]> parentsOf(byte[] id) {
            return parents.getOrDefault(AvpBytes.base64(id), List.of());
        }

        /**
         * Whether {@code id} is reachable from one of {@code from} by following parents one or more steps.
         *
         * @param id the commit that may be an ancestor
         * @param from the commits to start from
         * @return whether it is an ancestor of one of them
         */
        public boolean isAncestor(byte[] id, List<byte[]> from) {
            String target = AvpBytes.base64(id);
            Set<String> visited = new HashSet<>();
            ArrayDeque<String> stack = new ArrayDeque<>();
            for (byte[] f : from) {
                stack.push(AvpBytes.base64(f));
            }
            while (!stack.isEmpty()) {
                for (byte[] p : parents.getOrDefault(stack.pop(), List.of())) {
                    String pid = AvpBytes.base64(p);
                    if (pid.equals(target)) {
                        return true;
                    }
                    if (visited.add(pid)) {
                        stack.push(pid);
                    }
                }
            }
            return false;
        }
    }

    /**
     * The client checks of SPEC 7.5 on one pulled commit, against this chain.
     *
     * <ol>
     *   <li>The commit is for this repository, its header is well formed, {@code commitId} recomputes and
     *       {@code authorSignature} verifies.
     *   <li>Removal cutoff: a commit by a member that the tip's removals name passes only if its id is in the
     *       removal's frontier or is an ancestor of a frontier id (removals are cumulative, so the tip holds
     *       them all). A child of a frontier commit does not pass.
     *   <li>Membership: when {@code (manifestSeq, manifestHash)} is the state on this chain at that seq, the
     *       author is a member of it and {@code keyEpoch} is its epoch; otherwise the author is a member, at
     *       the commit's epoch, of a state of this chain at or after the cited seq.
     * </ol>
     *
     * @param c the commit
     * @param ancestry the commit graph learned so far, the commit itself included or not
     * @return the first check that fails, or {@link CommitVerdict#OK}
     */
    public CommitVerdict verifyCommit(Commit c, Ancestry ancestry) {
        if (!AvpBytes.same(c.repoId(), repoId()) || !Commits.verify(c)) {
            return CommitVerdict.BAD_ID_OR_SIGNATURE;
        }
        Optional<Removal> removal = tip().state().removalOf(c.author());
        if (removal.isPresent()) {
            List<byte[]> frontier = removal.get().frontier();
            boolean inFrontier = frontier.stream().anyMatch(id -> AvpBytes.same(id, c.commitId()));
            if (!inFrontier && !ancestry.isAncestor(c.commitId(), frontier)) {
                return CommitVerdict.AFTER_REMOVAL_CUTOFF;
            }
        }
        Optional<SignedManifest> cited = at(c.manifestSeq());
        boolean member;
        if (cited.isPresent() && AvpBytes.same(hashes.get((int) (c.manifestSeq() - 1)), c.manifestHash())) {
            member = memberAt(cited.get().state(), c);
        } else {
            member = false;
            for (SignedManifest m : states) {
                if (m.state().manifestSeq() >= c.manifestSeq() && memberAt(m.state(), c)) {
                    member = true;
                    break;
                }
            }
        }
        return member ? CommitVerdict.OK : CommitVerdict.NOT_A_MEMBER_AT_EPOCH;
    }

    private static boolean memberAt(ManifestState s, Commit c) {
        return s.hasMember(c.author()) && s.keyEpoch() == c.keyEpoch();
    }

    /**
     * Names the repository and the pin only.
     *
     * @return a description
     */
    @Override
    public String toString() {
        return "VerifiedChain[" + repoId() + ", seq " + size() + "]";
    }
}

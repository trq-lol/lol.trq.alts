package lol.trq.alts.internal.vault;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import java.util.function.Consumer;
import java.util.function.LongSupplier;
import java.util.function.Supplier;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.internal.avp.AvpBytes;
import lol.trq.alts.internal.avp.AvpCrypto;
import lol.trq.alts.internal.avp.AvpCrypto.WrapLabel;
import lol.trq.alts.internal.avp.Commits;
import lol.trq.alts.internal.avp.Commits.Commit;
import lol.trq.alts.internal.avp.Hlc;
import lol.trq.alts.internal.avp.Manifest;
import lol.trq.alts.internal.avp.Manifest.HostRef;
import lol.trq.alts.internal.avp.Manifest.ManifestState;
import lol.trq.alts.internal.avp.Manifest.MemberEntry;
import lol.trq.alts.internal.avp.Manifest.Removal;
import lol.trq.alts.internal.avp.Manifest.SignedManifest;
import lol.trq.alts.internal.avp.OwnerKeys;
import lol.trq.alts.internal.avp.Payload;
import lol.trq.alts.internal.avp.Tokens;
import lol.trq.alts.internal.avp.Tokens.InviteToken;
import lol.trq.alts.internal.avp.Tokens.LeaveRequest;
import lol.trq.alts.internal.avp.Tokens.RepoLocator;

/**
 * One member device's copy of one AVP 0.5 repository, synced through its home host (SPEC 5 to 8, 10, 11).
 * Ported from the reference client of the Alt Vault Protocol (MIT).
 *
 * <p>The client never trusts a host's acceptance (SPEC 7.5):
 *
 * <ul>
 *   <li>It keeps its own {@link VerifiedChain}, checked from genesis, and pins its tip. A chain that does
 *       not contain the pin is refused as a rollback unless it diverges at or below the pin and wins the tie
 *       rule there (SPEC 6.4, 6.5). A host that serves a state that fails SPEC 6.1, or a rollback, fails the
 *       operation with {@link Kind#PROTOCOL} and changes nothing.
 *   <li>It checks every pulled commit (SPEC 7.5 rules 1 to 3); a commit that fails is neither merged nor a
 *       parent. A head it cannot read is left alone without failing.
 *   <li>It merges every readable head and pushes the merge with exactly those heads as parents (SPEC 5),
 *       after the clock observed every stamp. It retains every epoch's data key, so old-epoch heads are
 *       merged forward.
 *   <li>It strips {@code refreshToken} and {@code expiresAt} on read and on write unless the latest verified
 *       state shares them (SPEC 5.1).
 *   <li>After {@code 409 manifest_conflict}, or a {@code 403} that may come from a stale pin, it re-pulls the
 *       whole chain once and retries once, never more (SPEC 6.3, 6.4).
 * </ul>
 *
 * <p>The owner operations of SPEC 8 (invite, remove, policy, leave processing) build, check and sign the next
 * state here; the owner wraps the data key only to the X25519 key of a verified invite token. No secret (the
 * phrase, its entropy or seed, a private key, a data key, a plaintext) is ever sent to a host.
 *
 * <p>Every operation that talks to a host runs on the transport's executor and returns a future that fails
 * only with an {@link AltsException}, inside a {@link CompletionException}. Operations on one vault run one
 * at a time, in the order they were started. The accessors read the state the last finished operation left
 * and never wait for a running one.
 *
 * @author trq
 * @since 1.0.0
 */
public final class VaultEngine {

    private final HostClient host;
    private final MemberKeys me;
    private final LongSupplier clock;
    private final Executor executor;

    private VerifiedChain chain;
    private final SortedMap<Long, byte[]> retained = new TreeMap<>();
    private Payload local = Payload.EMPTY;
    private final Hlc hlc;
    private List<byte[]> heads = new ArrayList<>();
    private List<byte[]> unreadable = new ArrayList<>();
    private List<Payload> incoming = new ArrayList<>();
    private final VerifiedChain.Ancestry ancestry = new VerifiedChain.Ancestry();
    /** The author of every commit this device verified, by base64 id, for the removal frontier. */
    private final Map<String, byte[]> authors = new HashMap<>();

    private List<LeaveRequest> leaves = new ArrayList<>();
    private boolean left;
    private OptionalLong lastDivergence = OptionalLong.empty();
    /** What the pull that opened this vault found; an empty report for a vault this device created. */
    private PullReport opening = new PullReport(
            0, OptionalLong.empty(), false, List.of(), List.of(), List.of(), 0, List.of(), Optional.empty());

    private final Object order = new Object();
    private CompletableFuture<?> tail = CompletableFuture.completedFuture(null);
    private volatile View view;

    /** What the accessors read: the state the last finished operation left. */
    private record View(
            String repoId,
            SignedManifest tip,
            List<byte[]> chainHashes,
            Payload payload,
            List<byte[]> heads,
            List<byte[]> unreadable,
            List<LeaveRequest> leaves,
            boolean left,
            OptionalLong lastDivergence,
            SortedMap<Long, byte[]> retained,
            long hlcAt,
            long hlcN) {}

    private VaultEngine(HostClient host, MemberKeys me, VerifiedChain chain, LongSupplier clock, Hlc hlc) {
        this.host = host;
        this.me = me;
        this.chain = chain;
        this.clock = clock;
        this.hlc = hlc;
        this.executor = host.transport().executor();
    }

    // --- Async plumbing --------------------------------------------------------------------------

    /** Maps whatever a future failed with to an {@link AltsException}, so nothing else escapes. */
    private static AltsException classify(Throwable t) {
        Throwable c = t;
        while (c instanceof CompletionException && c.getCause() != null) {
            c = c.getCause();
        }
        if (c instanceof AltsException e) {
            return e;
        }
        if (c instanceof RejectedExecutionException) {
            return VaultFailures.cancelled("the runtime is closed", c);
        }
        return new AltsException(AltsFailure.of(Kind.UNKNOWN, "Vault: the operation failed unexpectedly"), c);
    }

    private static <T> CompletableFuture<T> guard(CompletableFuture<T> f) {
        return f.handle((value, failure) -> {
            if (failure != null) {
                throw new CompletionException(classify(failure));
            }
            return value;
        });
    }

    private static <T> CompletableFuture<T> async(Executor executor, Supplier<T> op) {
        try {
            return guard(CompletableFuture.supplyAsync(op, executor));
        } catch (RejectedExecutionException refused) {
            return CompletableFuture.failedFuture(classify(refused));
        }
    }

    /** Runs {@code op} after every operation started before it, on the executor. */
    private <T> CompletableFuture<T> serial(Supplier<T> op) {
        synchronized (order) {
            CompletableFuture<T> next;
            try {
                next = tail.handle((x, e) -> null)
                        .thenApplyAsync(
                                x -> {
                                    try {
                                        return op.get();
                                    } finally {
                                        publishView();
                                    }
                                },
                                executor);
            } catch (RejectedExecutionException refused) {
                next = CompletableFuture.failedFuture(refused);
            }
            tail = next;
            return guard(next);
        }
    }

    private void publishView() {
        SortedMap<Long, byte[]> keys = new TreeMap<>();
        retained.forEach((k, v) -> keys.put(k, v.clone()));
        view = new View(
                chain.repoId(),
                chain.tip(),
                chain.hashes(),
                local,
                HostClient.copyIds(heads),
                HostClient.copyIds(unreadable),
                List.copyOf(leaves),
                left,
                lastDivergence,
                keys,
                hlc.at(),
                hlc.n());
    }

    // --- Opening a vault -------------------------------------------------------------------------

    /**
     * Creates a repository on the owner's home host (SPEC 8.2, initial host): a random genesis nonce, a fresh
     * epoch-0 data key wrapped to the owner, the owner-signed genesis state listing {@code host}, and an empty
     * first commit, sent together with {@code createRepo}.
     *
     * @param host the owner's home host
     * @param owner the owner keys
     * @param clock epoch milliseconds
     * @return the vault
     */
    public static CompletableFuture<VaultEngine> create(HostClient host, OwnerKeys owner, LongSupplier clock) {
        Objects.requireNonNull(owner, "owner");
        return async(host.transport().executor(), () -> createNow(host, owner, clock));
    }

    private static VaultEngine createNow(HostClient host, OwnerKeys owner, LongSupplier clock) {
        MemberKeys me = MemberKeys.ofOwner(owner);
        byte[] ownerKey = me.ed25519Public();
        byte[] nonce = AvpCrypto.randomBytes(16);
        byte[] dataKey = AvpCrypto.randomBytes(32);
        try {
            String repoId = Manifest.deriveRepoId(ownerKey, nonce);
            ManifestState state = new ManifestState(
                    repoId,
                    1,
                    new byte[0],
                    ownerKey,
                    nonce,
                    AvpCrypto.SCHEME_ID,
                    0,
                    false,
                    List.of(new HostRef(host.key(), host.locator())),
                    List.of(new MemberEntry(
                            ownerKey,
                            me.x25519Public(),
                            AvpCrypto.wrap(me.x25519Public(), dataKey, WrapLabel.DATA_KEY),
                            0,
                            host.key())),
                    List.of());
            SignedManifest genesis = Manifest.sign(state, me.seedRef());
            VerifiedChain chain = VerifiedChain.genesis(genesis);
            Commit first = Commits.seal(
                    dataKey,
                    new Commits.Header(repoId, List.of(), 1, chain.tipHash(), 0),
                    Payload.EMPTY.encode(),
                    me.seedRef());
            try {
                host.createRepo(me, genesis, first);
            } catch (AltsException lost) {
                // SPEC 12.3: an answer that never arrived, or a duplicate_repo for a retry after success. The
                // repository was created iff the host now serves this very genesis.
                boolean retryable = lost.kind() == Kind.NETWORK || VaultFailures.hasCode(lost, "duplicate_repo");
                if (!retryable || !servesGenesis(host, me, repoId, chain.tipHash())) {
                    throw lost;
                }
            }
            VaultEngine v = new VaultEngine(host, me, chain, clock, new Hlc(0, 0));
            v.retained.put(0L, dataKey.clone());
            v.recordOwn(first);
            v.publishView();
            return v;
        } finally {
            Arrays.fill(dataKey, (byte) 0);
        }
    }

    /**
     * Whether the host serves {@code genesisHash} as the repository's first state, after a creation whose
     * answer was lost. A host that answers that pull with something that is not the protocol fails the
     * creation with {@code PROTOCOL}, as {@link #landed} does for a publication; one that cannot be asked
     * leaves the original failure standing.
     */
    private static boolean servesGenesis(HostClient host, MemberKeys me, String repoId, byte[] genesisHash) {
        try {
            List<SignedManifest> served = host.pull(me, repoId, 0).manifests();
            return !served.isEmpty() && AvpBytes.same(Manifest.hash(served.get(0)), genesisHash);
        } catch (AltsException unknown) {
            if (unknown.kind() == Kind.PROTOCOL) {
                throw unknown;
            }
            return false;
        }
    }

    /**
     * Opens a repository this device is a member of, from its home host: pulls the whole chain, verifies it
     * from genesis, unwraps every data key it was given, reads and merges the heads.
     *
     * @param host the member's home host
     * @param me this device's member keys
     * @param repoId the repository
     * @param clock epoch milliseconds
     * @return the vault; fails with {@code PROTOCOL} if the chain does not verify, is another repository, or
     *     does not name {@code host} as this member's home host, and {@code INVALID_INPUT} if its tip does not
     *     list this member
     */
    public static CompletableFuture<VaultEngine> open(
            HostClient host, MemberKeys me, String repoId, LongSupplier clock) {
        Objects.requireNonNull(me, "me");
        Objects.requireNonNull(repoId, "repoId");
        return async(host.transport().executor(), () -> openNow(host, me, repoId, null, clock));
    }

    /**
     * Joins a repository after the owner's invite (SPEC 8.1): {@link #open} from the joiner's home host, plus
     * the SPEC 11.2 check that the genesis owner key matches the locator's owner fingerprint.
     *
     * @param host the joiner's home host
     * @param me the joiner's member keys
     * @param locator the owner's repo locator
     * @param clock epoch milliseconds
     * @return the vault; fails as {@link #open}, and with {@code PROTOCOL} for another owner key
     */
    public static CompletableFuture<VaultEngine> join(
            HostClient host, MemberKeys me, RepoLocator locator, LongSupplier clock) {
        Objects.requireNonNull(me, "me");
        Objects.requireNonNull(locator, "locator");
        String fingerprint = locator.ownerFingerprint();
        return async(host.transport().executor(), () -> openNow(host, me, locator.repoId(), fingerprint, clock));
    }

    private static VaultEngine openNow(
            HostClient host, MemberKeys me, String repoId, String ownerFingerprint, LongSupplier clock) {
        HostClient.PullAnswer answer = host.pull(me, repoId, 0);
        VerifiedChain chain = VerifiedChain.of(answer.manifests());
        if (!AvpBytes.same(chain.repoId(), repoId)) {
            throw VaultFailures.protocol("the host served another repository");
        }
        requireListed(chain, host);
        if (ownerFingerprint != null && !AvpBytes.same(Tokens.ownerFingerprint(chain.ownerKey()), ownerFingerprint)) {
            throw VaultFailures.protocol("the repository's owner key does not match the locator's owner fingerprint");
        }
        requireHome(chain, me, host);
        VaultEngine v = new VaultEngine(host, me, chain, clock, new Hlc(0, 0));
        v.adoptKeys(0);
        // A first open learns the whole chain, and a policy that shares is new to this device.
        PullReport found = v.digest(answer, chain.size(), OptionalLong.empty(), v.share());
        v.opening = found.withMerge(v.mergeHeadsNow());
        v.publishView();
        return v;
    }

    /**
     * Opens a vault from the state a host persisted: pulls the whole chain, verifies it from genesis and
     * requires it to contain the persisted pin, or to win the tie rule at or below it (SPEC 6.4), then takes
     * the retained keys, the clock and the local payload back and reads the heads.
     *
     * @param host the member's home host
     * @param me this device's member keys
     * @param state the persisted state
     * @param clock epoch milliseconds
     * @return the vault; fails with {@code PROTOCOL} for a rollback, another repository, or a host that is not
     *     this member's home host in the verified tip, and with {@code INVALID_INPUT} if this member left or is
     *     no longer a member
     */
    public static CompletableFuture<VaultEngine> resume(
            HostClient host, MemberKeys me, EngineState state, LongSupplier clock) {
        Objects.requireNonNull(me, "me");
        Objects.requireNonNull(state, "state");
        return async(host.transport().executor(), () -> resumeNow(host, me, state, clock));
    }

    private static VaultEngine resumeNow(HostClient host, MemberKeys me, EngineState state, LongSupplier clock) {
        if (state.left()) {
            throw VaultFailures.invalid("this member left the repository and no longer syncs");
        }
        HostClient.PullAnswer answer = host.pull(me, state.repoId(), 0);
        VerifiedChain chain = VerifiedChain.of(answer.manifests());
        if (!AvpBytes.same(chain.repoId(), state.repoId())) {
            throw VaultFailures.protocol("the host served another repository");
        }
        List<byte[]> pinned = state.chainHashes();
        if (!VerifiedChain.accepts(pinned, chain.hashes())) {
            throw rollback();
        }
        requireListed(chain, host);
        requireHome(chain, me, host);
        VaultEngine v = new VaultEngine(host, me, chain, clock, new Hlc(state.hlcAt(), state.hlcN()));
        state.retainedKeys().forEach(v.retained::put);
        int fork = VerifiedChain.fork(pinned, chain.hashes());
        v.lastDivergence = fork < 0 ? OptionalLong.empty() : OptionalLong.of(fork + 1L);
        // The states past what this device had verified: past the pin, or past the fork it lost.
        int known = fork < 0 ? Math.min(pinned.size(), chain.size()) : fork;
        boolean sharedBefore =
                chain.states().get(Math.max(known, 1) - 1).state().shareRefreshTokens();
        v.adoptKeys(known);
        v.local = state.local().underPolicy(v.share());
        PullReport found = v.digest(answer, chain.size() - known, v.lastDivergence, !sharedBefore && v.share());
        v.opening = found.withMerge(v.mergeHeadsNow());
        v.publishView();
        return v;
    }

    /**
     * A host is matched by key (SPEC 3.3, 11.7): the host a vault is opened from must be one the verified tip
     * lists, so a host reached by its locator alone, whose key nobody vouched for, cannot stand in for one.
     */
    private static void requireListed(VerifiedChain chain, HostClient host) {
        if (!chain.tip().state().hasHost(host.key())) {
            throw VaultFailures.protocol("the repository's verified state does not list the host it was opened from");
        }
    }

    /**
     * A member syncs through its home host (SPEC 1, 8.1): the verified tip must list this device, and the
     * host must be the {@code homeHostKey} the owner signed for it, which for a joiner is the home host of its
     * invite token.
     */
    private static void requireHome(VerifiedChain chain, MemberKeys me, HostClient host) {
        Optional<MemberEntry> mine = chain.tip().state().member(me.ed25519Public());
        if (mine.isEmpty()) {
            throw VaultFailures.invalid("this device is not a member of the repository");
        }
        if (!AvpBytes.same(mine.get().homeHostKey(), host.key())) {
            throw VaultFailures.protocol("the host is not this member's home host in the verified state");
        }
    }

    /**
     * The joiner's step 2 of SPEC 8.1: asks its home host to carry the repository ({@code prepareJoin}),
     * checks the acceptance the host signed, and builds the invite token for the owner.
     *
     * @param host the joiner's home host
     * @param me the joiner's member keys
     * @param repoId the repository from the owner's repo locator
     * @return the invite token; fails with {@code PROTOCOL} if the acceptance does not check
     */
    public static CompletableFuture<InviteToken> prepareJoin(HostClient host, MemberKeys me, String repoId) {
        Objects.requireNonNull(me, "me");
        Objects.requireNonNull(repoId, "repoId");
        return async(
                host.transport().executor(),
                () -> new InviteToken(
                        me.ed25519Public(),
                        me.x25519Public(),
                        host.key(),
                        host.locator(),
                        host.prepareJoin(me, repoId)));
    }

    // --- Accessors ---------------------------------------------------------------------------------

    /**
     * The repository id.
     *
     * @return the repoId
     */
    public String repoId() {
        return view.repoId();
    }

    /**
     * What the pull that opened this vault found and did: for {@link #open} and {@link #join} every state of
     * the chain is new and a sharing policy counts as turned on; for {@link #resume}, the states past the
     * persisted pin (or past the fork it lost); for {@link #create}, nothing.
     *
     * @return the report
     */
    public PullReport openReport() {
        return opening;
    }

    /**
     * The pinned tip: the highest verified state.
     *
     * @return the tip
     */
    public SignedManifest tip() {
        return view.tip();
    }

    /**
     * The {@code manifestHash} of the pinned tip.
     *
     * @return a copy
     */
    public byte[] tipHash() {
        List<byte[]> hashes = view.chainHashes();
        return hashes.get(hashes.size() - 1).clone();
    }

    /**
     * The local payload: the merge of every head this device read, under the policy.
     *
     * @return the payload
     */
    public Payload payload() {
        return view.payload();
    }

    /**
     * The readable heads the local payload covers: the parents of the next write.
     *
     * @return copies of the ids
     */
    public List<byte[]> heads() {
        return HostClient.copyIds(view.heads());
    }

    /**
     * The verified heads this device could not read at the last pull.
     *
     * @return copies of the ids
     */
    public List<byte[]> unreadableHeads() {
        return HostClient.copyIds(view.unreadable());
    }

    /**
     * The pending leave requests of the last pull that pass the SPEC 8.4 checks.
     *
     * @return the requests
     */
    public List<LeaveRequest> pendingLeaves() {
        return view.leaves();
    }

    /**
     * The seq of the last diverged chain this vault adopted under the tie rule (SPEC 6.5), on any operation.
     *
     * @return the fork seq, or empty when this vault never switched chains
     */
    public OptionalLong lastDivergence() {
        return view.lastDivergence();
    }

    /**
     * Whether this member left the repository; every later operation that syncs is refused.
     *
     * @return whether it left
     */
    public boolean left() {
        return view.left();
    }

    /**
     * This device's member keys.
     *
     * @return the keys
     */
    public MemberKeys member() {
        return me;
    }

    /**
     * The home host connection.
     *
     * @return the connection
     */
    public HostClient host() {
        return host;
    }

    /**
     * Whether this device is the owner.
     *
     * @return whether its key is the owner key
     */
    public boolean isOwner() {
        return me.is(view.tip().state().ownerKey());
    }

    /**
     * Every data key this device has held, by epoch. Secrets.
     *
     * @return copies, which the caller zeroes
     */
    public SortedMap<Long, byte[]> retainedEpochKeys() {
        SortedMap<Long, byte[]> out = new TreeMap<>();
        view.retained().forEach((k, v) -> out.put(k, v.clone()));
        return out;
    }

    /**
     * The state to persist.
     *
     * @return the state; it holds secrets
     */
    public EngineState state() {
        View v = view;
        return new EngineState(v.repoId(), v.chainHashes(), v.retained(), v.hlcAt(), v.hlcN(), v.payload(), v.left());
    }

    /**
     * A repo locator naming this device's home host as the owner's home host (SPEC 11.2).
     *
     * @return the locator
     * @throws AltsException of kind {@code INVALID_INPUT} unless this device is the owner
     */
    public RepoLocator locator() {
        if (!isOwner()) {
            throw notOwner();
        }
        View v = view;
        return new RepoLocator(
                v.repoId(),
                host.key(),
                host.locator(),
                Tokens.ownerFingerprint(v.tip().state().ownerKey()));
    }

    /**
     * Names the repository and the pin only; never a key or a plaintext.
     *
     * @return a description
     */
    @Override
    public String toString() {
        View v = view;
        return "VaultEngine[" + v.repoId() + ", seq " + v.chainHashes().size() + ", heads "
                + v.heads().size() + ", left=" + v.left() + "]";
    }

    // --- State helpers -----------------------------------------------------------------------------

    private boolean share() {
        // SPEC 5.1, fail closed: on only when the latest verified state says true.
        return chain.tip().state().shareRefreshTokens();
    }

    private boolean owner() {
        return me.is(chain.tip().state().ownerKey());
    }

    private static AltsException notOwner() {
        return VaultFailures.invalid("only the owner changes the members, the policy or the hosts");
    }

    private void requireOwner() {
        if (!owner()) {
            throw notOwner();
        }
    }

    private void requireSyncing() {
        if (left) {
            throw VaultFailures.invalid("this member left the repository and no longer syncs");
        }
    }

    private static AltsException rollback() {
        return VaultFailures.protocol(
                "the host served a chain without the pinned state that does not win the tie rule: a rollback");
    }

    /** Unwraps this member's data key from every chain state from index {@code from} on. */
    private void adoptKeys(int from) {
        List<SignedManifest> states = chain.states();
        for (SignedManifest m : states.subList(Math.min(Math.max(from, 0), states.size()), states.size())) {
            Optional<MemberEntry> mine = m.state().member(me.ed25519Public());
            if (mine.isEmpty()) {
                continue;
            }
            try {
                byte[] key = AvpCrypto.unwrap(me.x25519Ref(), mine.get().wrappedDataKey(), WrapLabel.DATA_KEY);
                if (key.length == 32) {
                    byte[] old = retained.put(m.state().keyEpoch(), key);
                    if (old != null && old != key) {
                        Arrays.fill(old, (byte) 0);
                    }
                } else {
                    Arrays.fill(key, (byte) 0);
                }
            } catch (AltsException unreadable) {
                // A wrap this device cannot open gives no key for that epoch; its heads stay unreadable.
            }
        }
    }

    /**
     * Records who wrote a verified commit, for the removal frontier, up to {@link
     * VerifiedChain.Ancestry#MAX_HEADERS} commits. Past that a removed member's commit may be left out of a
     * frontier, and is then cut off by the removal: a lost write, never an accepted one.
     */
    private void learnAuthor(String id, byte[] author) {
        if (authors.size() < VerifiedChain.Ancestry.MAX_HEADERS || authors.containsKey(id)) {
            authors.put(id, author);
        }
    }

    private void recordOwn(Commit c) {
        ancestry.learn(c);
        learnAuthor(AvpBytes.base64(c.commitId()), c.author());
        heads = new ArrayList<>(List.of(c.commitId()));
        unreadable = new ArrayList<>();
    }

    // --- Pull --------------------------------------------------------------------------------------

    /**
     * Pulls from the home host and merges (SPEC 5, 6.4, 7.5, 10.1): verifies every new state and pins the
     * highest, checks every head, reads the heads it can, and pushes a merge commit when more than one head is
     * readable.
     *
     * @return the report; fails with {@code PROTOCOL} for a state that does not verify or a rollback (and the
     *     vault is unchanged), {@code INVALID_INPUT} after {@link #leave()}, or the host's refusal
     */
    public CompletableFuture<PullReport> pull() {
        return serial(() -> {
            PullReport r = fetch(false);
            return r.withMerge(mergeHeadsNow());
        });
    }

    /**
     * The pull without the merge push: from the pin, or from seq 0 when {@code full}. Nothing changes unless
     * the whole answer verifies.
     */
    private PullReport fetch(boolean full) {
        requireSyncing();
        String repoId = chain.repoId();
        HostClient.PullAnswer answer = host.pull(me, repoId, full ? 0 : chain.size());
        List<SignedManifest> served = answer.manifests();
        boolean linked = !full && (served.isEmpty() || Manifest.linksTo(served.get(0), chain.tip()));
        VerifiedChain next;
        int from;
        OptionalLong diverged = OptionalLong.empty();
        if (linked) {
            next = chain.copy();
            for (SignedManifest m : served) {
                next.extend(m);
            }
            from = chain.size();
        } else {
            // SPEC 6.4: the first state does not link to the pin, or the pin may be stale; pull the whole chain
            // and decide on it.
            if (!full) {
                answer = host.pull(me, repoId, 0);
            }
            next = VerifiedChain.of(answer.manifests());
            if (!AvpBytes.same(next.repoId(), repoId) || !chain.accepts(next)) {
                throw rollback();
            }
            int fork = VerifiedChain.fork(chain.hashes(), next.hashes());
            from = fork < 0 ? chain.size() : fork;
            if (fork >= 0) {
                diverged = OptionalLong.of(fork + 1L);
            }
        }
        int added = Math.max(0, next.size() - from);
        boolean sharedBefore = share();
        chain = next;
        if (diverged.isPresent()) {
            lastDivergence = diverged;
        }
        adoptKeys(from);
        local = local.underPolicy(share());
        return digest(answer, added, diverged, !sharedBefore && share());
    }

    /** Checks the heads and leaves of an answer against the adopted chain and sorts the heads. */
    private PullReport digest(HostClient.PullAnswer answer, int added, OptionalLong diverged, boolean turnedOn) {
        for (Commit c : answer.heads()) {
            ancestry.learn(c);
        }
        heads = new ArrayList<>();
        unreadable = new ArrayList<>();
        incoming = new ArrayList<>();
        List<byte[]> discarded = new ArrayList<>();
        Set<String> once = new HashSet<>();
        for (Commit c : answer.heads()) {
            // Verify before de-duplicating, so a forgery that claims a real head's id cannot shadow it.
            if (chain.verifyCommit(c, ancestry) != VerifiedChain.CommitVerdict.OK) {
                discarded.add(c.commitId());
                continue;
            }
            String id = AvpBytes.base64(c.commitId());
            if (!once.add(id)) {
                continue;
            }
            learnAuthor(id, c.author());
            Payload p = read(c);
            if (p != null) {
                heads.add(c.commitId());
                incoming.add(p);
            } else {
                unreadable.add(c.commitId());
            }
        }
        ManifestState tip = chain.tip().state();
        List<LeaveRequest> keep = new ArrayList<>();
        for (LeaveRequest l : answer.leaves()) {
            if (Tokens.leaveVerdict(l, tip) == Tokens.LeaveVerdict.OK) {
                keep.add(l);
            }
        }
        leaves = keep;
        return new PullReport(
                added, diverged, turnedOn, heads, unreadable, discarded, answer.malformed(), keep, Optional.empty());
    }

    /**
     * Decrypts a verified commit with the retained key of its epoch, stripped by the policy (SPEC 5.1, strip
     * on read); {@code null} if this device cannot read it.
     */
    private Payload read(Commit c) {
        byte[] key = retained.get(c.keyEpoch());
        if (key == null) {
            return null;
        }
        byte[] plain = null;
        try {
            plain = Commits.open(c, key);
            return Payload.parse(plain).underPolicy(share());
        } catch (AltsException unreadableHead) {
            return null;
        } finally {
            if (plain != null) {
                Arrays.fill(plain, (byte) 0);
            }
        }
    }

    /** Merges what the last pull read into the local payload, after the clock observed every stamp. */
    private void absorb() {
        List<Payload> in = incoming;
        incoming = new ArrayList<>();
        for (Payload p : in) {
            hlc.observeAll(p);
        }
        List<Payload> all = new ArrayList<>();
        all.add(local);
        all.addAll(in);
        local = Payload.merge(all).underPolicy(share());
    }

    /**
     * The stale-pin recovery of SPEC 6.3 and 6.4: pulls the whole chain from seq 0, checks it like any pull
     * (a rollback or another genesis is refused), and merges what it read.
     *
     * @return whether the pin moved
     */
    private boolean resync() {
        byte[] before = chain.tipHash();
        fetch(true);
        absorb();
        return !AvpBytes.same(before, chain.tipHash());
    }

    /**
     * Merges every readable head into the local payload and, when more than one head is readable, pushes the
     * merge commit whose parents are exactly those heads (SPEC 5). Unreadable heads are never parents.
     *
     * @return the merge commit id, or empty when there was nothing to merge
     */
    public CompletableFuture<Optional<byte[]>> mergeHeads() {
        return serial(this::mergeHeadsNow);
    }

    private Optional<byte[]> mergeHeadsNow() {
        requireSyncing();
        absorb();
        if (heads.size() < 2) {
            return Optional.empty();
        }
        return Optional.of(pushPayload(local));
    }

    // --- Write -------------------------------------------------------------------------------------

    /**
     * One write (SPEC 5): {@code edit} changes a copy of the local payload through a {@link PayloadEditor},
     * whose stamps come from the clock after it observed every stamp merged so far. The result is stripped by
     * the policy (SPEC 5.1, strip on write), sealed under the tip's epoch with the readable heads as parents,
     * and pushed.
     *
     * @param edit the edits
     * @return the new commit id; fails with {@code PROTOCOL} and the impossible-timestamp message when the
     *     clock cannot advance, {@code CRYPTO} without the current epoch's key, or the host's refusal
     */
    public CompletableFuture<byte[]> write(Consumer<PayloadEditor> edit) {
        Objects.requireNonNull(edit, "edit");
        return serial(() -> {
            requireSyncing();
            absorb();
            hlc.observeAll(local);
            PayloadEditor editor = new PayloadEditor(local, hlc, clock, me.id());
            edit.accept(editor);
            return pushPayload(editor.payload().underPolicy(share()));
        });
    }

    /**
     * Pushes {@code payload} on the readable heads and makes it the local payload. A {@code 403} may come from
     * a stale pin (a commit citing a state that lost the tie rule, whose epoch the winning chain raised), so
     * the client re-pulls from seq 0 and, only if that moved the pin, rebuilds on the new tip and pushes once
     * more. One re-pull and one retry; an unchanged pin leaves the {@code 403} terminal.
     */
    private byte[] pushPayload(Payload payload) {
        byte[] id;
        try {
            id = commitPayload(HostClient.copyIds(heads), payload);
        } catch (AltsException refused) {
            if (!VaultFailures.hasCode(refused, "forbidden")) {
                throw refused;
            }
            boolean moved;
            try {
                moved = resync();
            } catch (AltsException again) {
                if (again.kind() == Kind.PROTOCOL) {
                    throw again;
                }
                moved = false;
            }
            if (!moved) {
                throw refused;
            }
            Payload rebuilt = Payload.merge(List.of(local, payload)).underPolicy(share());
            id = commitPayload(HostClient.copyIds(heads), rebuilt);
            local = rebuilt;
            return id;
        }
        local = payload;
        return id;
    }

    /** Seals {@code payload} under the tip's epoch, citing the tip, and pushes it. */
    private byte[] commitPayload(List<byte[]> parents, Payload payload) {
        ManifestState tip = chain.tip().state();
        long epoch = tip.keyEpoch();
        byte[] key = retained.get(epoch);
        if (key == null) {
            throw VaultFailures.crypto("this device holds no data key for the current epoch");
        }
        byte[] plain = payload.underPolicy(share()).encode();
        Commit c;
        try {
            c = Commits.seal(
                    key,
                    new Commits.Header(tip.repoId(), parents, tip.manifestSeq(), chain.tipHash(), epoch),
                    plain,
                    me.seedRef());
        } finally {
            Arrays.fill(plain, (byte) 0);
        }
        host.push(me, tip.repoId(), c);
        recordOwn(c);
        return c.commitId();
    }

    // --- Owner operations (SPEC 8) -----------------------------------------------------------------

    /** A mutable copy of the tip, the next state an owner operation builds. */
    private static final class Next {
        final ManifestState base;
        final long seq;
        final byte[] prev;
        long keyEpoch;
        boolean share;
        final List<HostRef> hosts;
        List<MemberEntry> members;
        final List<Removal> removals;

        Next(ManifestState base, long seq, byte[] prev) {
            this.base = base;
            this.seq = seq;
            this.prev = prev;
            this.keyEpoch = base.keyEpoch();
            this.share = base.shareRefreshTokens();
            this.hosts = new ArrayList<>(base.hosts());
            this.members = new ArrayList<>(base.members());
            this.removals = new ArrayList<>(base.removals());
        }

        ManifestState build() {
            return new ManifestState(
                    base.repoId(),
                    seq,
                    prev,
                    base.ownerKey(),
                    new byte[0],
                    base.schemeId(),
                    keyEpoch,
                    share,
                    hosts,
                    members,
                    removals);
        }
    }

    /** The next state after the tip, changed by {@code change} and signed by the owner. */
    private SignedManifest signNext(Consumer<Next> change) {
        ManifestState tip = chain.tip().state();
        if (tip.manifestSeq() == Long.MAX_VALUE) {
            throw VaultFailures.protocol("the manifest sequence cannot grow");
        }
        Next n = new Next(tip, tip.manifestSeq() + 1, chain.tipHash());
        change.accept(n);
        return Manifest.sign(n.build(), me.seedRef());
    }

    /**
     * Publishes a signed next state (with its commit) and, once the host accepts it, pins it. The state is
     * checked against the tip first, so the owner never publishes what a client rejects.
     */
    private void publish(SignedManifest signed, Commit commit) {
        VerifiedChain next = chain.copy();
        next.extend(signed);
        try {
            host.publish(me, chain.repoId(), signed, commit);
        } catch (AltsException lost) {
            // SPEC 12.3: an answer that never arrived, or a manifest_conflict for a retry after success. The
            // publication is done iff, once pulled, the verified tip is this very state.
            boolean retryable = lost.kind() == Kind.NETWORK || VaultFailures.hasCode(lost, "manifest_conflict");
            if (!retryable || !landed(signed)) {
                throw lost;
            }
            return;
        }
        int from = chain.size();
        chain = next;
        adoptKeys(from);
        local = local.underPolicy(share());
    }

    /**
     * Pulls after a publication whose answer was lost and tells whether it landed. A pull the host lies on
     * fails the operation as any pull does; one that cannot be made leaves the original failure standing.
     */
    private boolean landed(SignedManifest signed) {
        try {
            fetch(false);
        } catch (AltsException unknown) {
            if (unknown.kind() == Kind.PROTOCOL) {
                throw unknown;
            }
            return false;
        }
        return AvpBytes.same(chain.tipHash(), Manifest.hash(signed));
    }

    /**
     * Runs {@code attempt} once more when the host answers {@code 409 manifest_conflict} (SPEC 6.3, 6.4),
     * after re-pulling the whole chain from seq 0 so the attempt rebuilds on the verified tip. One re-pull and
     * one retry: a second conflict is the operation's failure.
     */
    private <T> T retryConflict(Supplier<T> attempt) {
        try {
            return attempt.get();
        } catch (AltsException e) {
            if (!VaultFailures.hasCode(e, "manifest_conflict")) {
                throw e;
            }
        }
        resync();
        return attempt.get();
    }

    /**
     * Invites a member from an invite token (SPEC 8.1, 8.2). The token's acceptance must verify under its host
     * key, name this repository and the token's Ed25519 key and home host, and not have expired. The current
     * data key is wrapped to exactly the token's X25519 key, never to a key a host served, and the home host
     * is added to {@code hosts} when it is not listed yet.
     *
     * @param token the joiner's invite token
     * @return completes when the state is published; fails with {@code PROTOCOL} for a token whose acceptance
     *     does not check, {@code INVALID_INPUT} unless this device is the owner, or for a current or removed
     *     member, and the pull's and the publication's failures
     */
    public CompletableFuture<Void> invite(InviteToken token) {
        Objects.requireNonNull(token, "token");
        return serial(() -> {
            requireOwner();
            if (!Tokens.verifyInvite(token, chain.repoId(), clock.getAsLong())) {
                throw VaultFailures.protocol("the invite token's host acceptance does not verify for this repository"
                        + " and member, or has expired");
            }
            retryConflict(() -> {
                fetch(false);
                mergeHeadsNow();
                ManifestState s = chain.tip().state();
                if (s.hasMember(token.ed25519PublicKey())) {
                    throw VaultFailures.invalid("the invited key is already a member");
                }
                if (s.removalOf(token.ed25519PublicKey()).isPresent()) {
                    throw VaultFailures.invalid("a removed key is never a member again");
                }
                byte[] key = retained.get(s.keyEpoch());
                if (key == null) {
                    throw VaultFailures.crypto("this device holds no data key for the current epoch");
                }
                MemberEntry entry = new MemberEntry(
                        token.ed25519PublicKey(),
                        token.x25519PublicKey(),
                        AvpCrypto.wrap(token.x25519PublicKey(), key, WrapLabel.DATA_KEY),
                        s.keyEpoch(),
                        token.homeHostKey());
                publish(
                        signNext(n -> {
                            n.members.add(entry);
                            if (n.hosts.stream().noneMatch(h -> AvpBytes.same(h.hostKey(), token.homeHostKey()))) {
                                n.hosts.add(new HostRef(token.homeHostKey(), token.homeHostLocator()));
                            }
                        }),
                        null);
                return null;
            });
            return null;
        });
    }

    /**
     * Removes a member (SPEC 8.3) in one {@code publishManifest}: pulls and merges every readable head,
     * generates the next epoch's data key and wraps it to every remaining member of the verified tip, drops
     * the member with a removal whose frontier is every merged head plus every verified commit by the member
     * that is not an ancestor of one, and carries the rotation commit (the merged state under the new epoch,
     * parents the merged heads, citing the new state).
     *
     * @param member the member's 32-byte Ed25519 key
     * @return completes when the state is published; fails with {@code INVALID_INPUT} unless this device is
     *     the owner, for the owner key or a key that is not a member, and the pull's and the publication's
     *     failures
     */
    public CompletableFuture<Void> remove(byte[] member) {
        byte[] key = member.clone();
        return serial(() -> {
            removeNow(key);
            return null;
        });
    }

    private void removeNow(byte[] member) {
        requireOwner();
        if (me.is(member)) {
            throw VaultFailures.invalid("the owner is never removed");
        }
        retryConflict(() -> {
            fetch(false);
            absorb();
            ManifestState tip = chain.tip().state();
            if (!tip.hasMember(member)) {
                throw VaultFailures.invalid("the key is not a member");
            }
            if (tip.keyEpoch() == Long.MAX_VALUE) {
                throw VaultFailures.protocol("the key epoch cannot grow");
            }
            long epoch = tip.keyEpoch() + 1;
            byte[] newKey = AvpCrypto.randomBytes(32);
            try {
                List<MemberEntry> members = new ArrayList<>();
                for (MemberEntry m : tip.members()) {
                    if (!AvpBytes.same(m.ed25519PublicKey(), member)) {
                        members.add(new MemberEntry(
                                m.ed25519PublicKey(),
                                m.x25519PublicKey(),
                                AvpCrypto.wrap(m.x25519PublicKey(), newKey, WrapLabel.DATA_KEY),
                                epoch,
                                m.homeHostKey()));
                    }
                }
                List<byte[]> parents = HostClient.copyIds(heads);
                List<byte[]> frontier = frontier(member, parents);
                SignedManifest signed = signNext(n -> {
                    n.keyEpoch = epoch;
                    n.members = members;
                    n.removals.add(new Removal(member, n.seq, frontier));
                });
                byte[] plain =
                        local.underPolicy(signed.state().shareRefreshTokens()).encode();
                Commit rotation;
                try {
                    rotation = Commits.seal(
                            newKey,
                            new Commits.Header(
                                    signed.state().repoId(),
                                    parents,
                                    signed.state().manifestSeq(),
                                    Manifest.hash(signed),
                                    epoch),
                            plain,
                            me.seedRef());
                } finally {
                    Arrays.fill(plain, (byte) 0);
                }
                publish(signed, rotation);
                byte[] replaced = retained.put(epoch, newKey.clone());
                if (replaced != null) {
                    // adoptKeys already unwrapped the same key from the published state: zero that copy.
                    Arrays.fill(replaced, (byte) 0);
                }
                recordOwn(rotation);
                leaves = new ArrayList<>(leaves);
                leaves.removeIf(l -> AvpBytes.same(l.memberKey(), member));
                return null;
            } finally {
                Arrays.fill(newKey, (byte) 0);
            }
        });
    }

    /**
     * The removal frontier (SPEC 8.3): the merged heads, plus every verified commit by {@code member} that is
     * neither one of them nor an ancestor of one, sorted.
     */
    private List<byte[]> frontier(byte[] member, List<byte[]> merged) {
        Set<String> listed = new HashSet<>();
        List<byte[]> out = new ArrayList<>();
        for (byte[] h : merged) {
            listed.add(AvpBytes.base64(h));
            out.add(h.clone());
        }
        for (Map.Entry<String, byte[]> e : authors.entrySet()) {
            if (!AvpBytes.same(e.getValue(), member) || listed.contains(e.getKey())) {
                continue;
            }
            byte[] id = java.util.Base64.getDecoder().decode(e.getKey());
            if (!ancestry.isAncestor(id, merged)) {
                listed.add(e.getKey());
                out.add(id);
            }
        }
        out.sort(AvpBytes::compare);
        return out;
    }

    /**
     * Sets the refresh-token policy (SPEC 5.1, 8.5): a new owner-signed state, no commit. Setting the value the
     * tip already has publishes nothing.
     *
     * @param on whether members share refresh tokens
     * @return completes when the state is published; fails with {@code INVALID_INPUT} unless this device is
     *     the owner, and the publication's failures
     */
    public CompletableFuture<Void> setShareRefreshTokens(boolean on) {
        return serial(() -> {
            requireOwner();
            retryConflict(() -> {
                fetch(false);
                mergeHeadsNow();
                if (share() != on) {
                    publish(signNext(n -> n.share = on), null);
                }
                return null;
            });
            return null;
        });
    }

    /**
     * Leaves the repository (SPEC 8.4): sends a signed leave request and stops syncing at once; every later
     * operation that syncs is refused.
     *
     * @return completes when the host stored the request; fails with {@code INVALID_INPUT} for the owner, and
     *     with the host's refusal
     */
    public CompletableFuture<Void> leave() {
        return serial(() -> {
            requireSyncing();
            if (owner()) {
                throw VaultFailures.invalid("the owner cannot leave");
            }
            host.leave(me, Tokens.signLeave(chain.repoId(), clock.getAsLong(), me.seedRef()));
            left = true;
            heads = new ArrayList<>();
            incoming = new ArrayList<>();
            return null;
        });
    }

    /**
     * Processes pending leave requests (SPEC 8.4): pulls, then removes each leaving member that passes the
     * SPEC 8.4 checks against the tip (a signature under its key, this repository, a current member who is
     * not the owner), one removal each.
     *
     * @return the removed keys; fails with {@code INVALID_INPUT} unless this device is the owner, and with the
     *     pull's and the removals' failures
     */
    public CompletableFuture<List<byte[]>> processLeaves() {
        return serial(() -> {
            requireOwner();
            fetch(false);
            mergeHeadsNow();
            List<byte[]> removed = new ArrayList<>();
            ArrayDeque<LeaveRequest> pending = new ArrayDeque<>(leaves);
            while (!pending.isEmpty()) {
                LeaveRequest l = pending.poll();
                if (Tokens.leaveVerdict(l, chain.tip().state()) == Tokens.LeaveVerdict.OK) {
                    removeNow(l.memberKey());
                    removed.add(l.memberKey());
                }
            }
            return removed;
        });
    }
}

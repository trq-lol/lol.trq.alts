package lol.trq.alts.vault;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.UnaryOperator;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.internal.avp.AvpBytes;
import lol.trq.alts.internal.avp.Manifest;
import lol.trq.alts.internal.avp.Payload;
import lol.trq.alts.internal.avp.Tokens.LeaveRequest;
import lol.trq.alts.internal.vault.MemberKeys;
import lol.trq.alts.internal.vault.PullReport;
import lol.trq.alts.internal.vault.VaultEngine;
import lol.trq.alts.model.AltAccount;
import lol.trq.alts.model.BanInfo;

/**
 * One member device's copy of one AVP 0.5 shared alt repository.
 *
 * <p>An instance comes from {@link #create}, {@link #open}, {@link #join} or {@link #resume} and syncs through
 * its home host ({@link VaultHost}, from {@code
 * alts.vault()}). The client never trusts a host: it verifies every owner-signed manifest state from genesis
 * and pins the highest, refuses a rollback, checks every member-signed commit, merges the heads per account
 * and per field, wraps the data key only to invite-token keys, and withholds {@code refreshToken} and {@code
 * expiresAt} on read and on write unless the latest verified state shares them. A forged state or a
 * rollback fails the whole operation with {@code PROTOCOL}, and the pull that met it adopts nothing of what
 * the host served, where the reference client keeps the valid prefix of it. No secret (the owner phrase, its entropy or seed, a private
 * key, a data key, a plaintext account field) is ever sent to a host.
 *
 * <p>The accounts are {@link AltAccount}s ({@link #accounts()}, {@link #put}, {@link #remove(String)}, {@link
 * #markBanned}); the owner manages members and the policy ({@link #invite}, {@link #remove(VaultMember)},
 * {@link #setShareRefreshTokens}, {@link #processLeaves()}); a member can {@link #leave()}. The host persists
 * {@link #snapshot()} after each operation and passes it to {@link #resume} next time. Nothing the vault reads
 * is written to the runtime's account store.
 *
 * <p>Every operation that talks to the host returns a future that fails only with an {@link AltsException}.
 * Operations on one copy run one at a time, in the order they were started; the accessors read the state the
 * last finished operation left and never wait.
 *
 * @author trq
 * @since 0.2.0
 */
public final class SharedVault {

    private final VaultEngine engine;
    private final VaultHost home;

    /**
     * Builds the AVP 0.5 copy around an opened engine.
     *
     * @param engine the engine
     * @param host the home host connection
     */
    private SharedVault(VaultEngine engine, VaultHost host) {
        this.engine = engine;
        this.home = host;
    }

    /** The engine, for a test that writes a payload no {@link AltAccount} can express. */
    VaultEngine engineForTests() {
        return engine();
    }

    private VaultEngine engine() {
        return engine;
    }

    private static CompletableFuture<SharedVault> opened(CompletableFuture<VaultEngine> f, VaultHost host) {
        return VaultFutures.guard(f.thenApply(e -> new SharedVault(e, host)));
    }

    /**
     * Creates a repository on the owner's home host (AVP SPEC 8.2): a fresh genesis state signed by the owner
     * key, listing {@code host} as the one host and the owner's device as the one member, and an empty first
     * commit. The repository withholds refresh tokens until {@link #setShareRefreshTokens(boolean)} turns
     * sharing on.
     *
     * @param host the owner's home host
     * @param owner the owner
     * @return this device's copy; fails with an {@link AltsException} only: the host's refusal by its kind
     *     ({@code CONFLICT} for a repository that exists, {@code UNAUTHORIZED}, {@code RATE_LIMITED}, {@code
     *     NETWORK}), {@code PROTOCOL} for an answer that is not the protocol
     * @since 1.0.0
     */
    public static CompletableFuture<SharedVault> create(VaultHost host, OwnerIdentity owner) {
        Objects.requireNonNull(host, "host");
        Objects.requireNonNull(owner, "owner");
        return opened(VaultEngine.create(host.client(), owner.ownerKeys(), host.clock()), host);
    }

    /**
     * Opens a repository the owner's device is a member of, from its home host, without a snapshot: the way
     * a second owner device (after a {@link LinkSession}) reads the repository. The whole chain is pulled and
     * verified from genesis.
     *
     * @param host the owner's home host, as the verified state lists it
     * @param owner the owner
     * @param repoId the repository
     * @return the copy; fails with {@code PROTOCOL} if the chain does not verify, is another repository, or
     *     does not list {@code host} as the owner's home host
     * @since 1.0.0
     */
    public static CompletableFuture<SharedVault> open(VaultHost host, OwnerIdentity owner, String repoId) {
        Objects.requireNonNull(host, "host");
        Objects.requireNonNull(owner, "owner");
        Objects.requireNonNull(repoId, "repoId");
        return opened(VaultEngine.open(host.client(), owner.memberKeys(), repoId, host.clock()), host);
    }

    /**
     * Opens a repository this member device belongs to, from its home host, without a snapshot. The whole
     * chain is pulled and verified from genesis. Prefer {@link #resume} with the last snapshot: it also
     * refuses a host that rolls the repository back below what this device saw.
     *
     * @param host the member's home host, as the verified state lists it
     * @param member this device's identity
     * @param repoId the repository
     * @return the copy; fails with {@code PROTOCOL} if the chain does not verify, is another repository, or
     *     does not list {@code host} as this member's home host, and {@code INVALID_INPUT} if the identity is
     *     not a member
     * @since 1.0.0
     */
    public static CompletableFuture<SharedVault> open(VaultHost host, VaultIdentity member, String repoId) {
        Objects.requireNonNull(host, "host");
        Objects.requireNonNull(member, "member");
        Objects.requireNonNull(repoId, "repoId");
        MemberKeys me;
        try {
            me = member.memberKeys();
        } catch (AltsException e) {
            return VaultFutures.failed(e);
        }
        return opened(VaultEngine.open(host.client(), me, repoId, host.clock()), host);
    }

    /**
     * The joiner's first step (AVP SPEC 8.1, 8.2): asks the joiner's home host to carry the repository for
     * this member, checks the acceptance the host signs, and builds the invite token to give the owner. The
     * home host may be the owner's ({@code alts.vault().connect(locator)}) or one the joiner picks.
     *
     * @param home the joiner's home host
     * @param member the joiner's identity
     * @param locator the owner's repo locator
     * @return the invite token; fails with {@code PROTOCOL} if the host's acceptance does not verify for this
     *     host, repository and member
     * @since 1.0.0
     */
    public static CompletableFuture<InviteToken> prepareJoin(
            VaultHost home, VaultIdentity member, RepoLocator locator) {
        Objects.requireNonNull(home, "home");
        Objects.requireNonNull(member, "member");
        Objects.requireNonNull(locator, "locator");
        MemberKeys me;
        try {
            me = member.memberKeys();
        } catch (AltsException e) {
            return VaultFutures.failed(e);
        }
        return VaultFutures.guard(
                VaultEngine.prepareJoin(home.client(), me, locator.repoId()).thenApply(InviteToken::new));
    }

    /**
     * The joiner's last step (AVP SPEC 8.1, 11.2), once the owner invited the token from {@link
     * #prepareJoin}: pulls the chain from the joiner's home host, verifies it from genesis, checks that the
     * genesis owner key matches the locator's owner fingerprint, and reads the accounts.
     *
     * @param home the joiner's home host, the one its invite token named
     * @param member the joiner's identity
     * @param locator the owner's repo locator
     * @return the copy; fails with {@code PROTOCOL} for another owner key, a chain that does not verify, or a
     *     host that is not this member's home host in the verified state, and {@code INVALID_INPUT} if the
     *     owner has not invited this member yet
     * @since 1.0.0
     */
    public static CompletableFuture<SharedVault> join(VaultHost home, VaultIdentity member, RepoLocator locator) {
        Objects.requireNonNull(home, "home");
        Objects.requireNonNull(member, "member");
        Objects.requireNonNull(locator, "locator");
        MemberKeys me;
        try {
            me = member.memberKeys();
        } catch (AltsException e) {
            return VaultFutures.failed(e);
        }
        return opened(VaultEngine.join(home.client(), me, locator.token(), home.clock()), home);
    }

    /**
     * Opens the owner device's copy again from its last {@link #snapshot()}: pulls the whole chain, verifies
     * it, and refuses it unless it contains the snapshot's pin or wins the tie rule at or below it (SPEC 6.4,
     * 6.5), then takes the retained keys, the clock and the merged accounts back.
     *
     * @param host the home host the snapshot names ({@link VaultHosts#connect(VaultSnapshot)})
     * @param owner the owner
     * @param snapshot the persisted snapshot
     * @return the copy; fails with {@code PROTOCOL} for a rollback, and {@code INVALID_INPUT} if the snapshot
     *     belongs to another member
     * @since 1.0.0
     */
    public static CompletableFuture<SharedVault> resume(VaultHost host, OwnerIdentity owner, VaultSnapshot snapshot) {
        Objects.requireNonNull(host, "host");
        Objects.requireNonNull(owner, "owner");
        Objects.requireNonNull(snapshot, "snapshot");
        return resume(host, owner.memberKeys(), snapshot);
    }

    /**
     * Opens this member device's copy again from its last {@link #snapshot()}, as {@link
     * #resume(VaultHost, OwnerIdentity, VaultSnapshot)} does for the owner.
     *
     * @param host the home host the snapshot names ({@link VaultHosts#connect(VaultSnapshot)})
     * @param member this device's identity
     * @param snapshot the persisted snapshot
     * @return the copy; fails with {@code PROTOCOL} for a rollback or a host that is not this member's home
     *     host, and {@code INVALID_INPUT} if the snapshot belongs to another member, this member left, or it is
     *     no longer a member
     * @since 1.0.0
     */
    public static CompletableFuture<SharedVault> resume(VaultHost host, VaultIdentity member, VaultSnapshot snapshot) {
        Objects.requireNonNull(host, "host");
        Objects.requireNonNull(member, "member");
        Objects.requireNonNull(snapshot, "snapshot");
        MemberKeys me;
        try {
            me = member.memberKeys();
        } catch (AltsException e) {
            return VaultFutures.failed(e);
        }
        return resume(host, me, snapshot);
    }

    private static CompletableFuture<SharedVault> resume(VaultHost host, MemberKeys me, VaultSnapshot snapshot) {
        if (!me.id().equals(snapshot.memberId())) {
            return VaultFutures.failed(VaultFutures.invalid("the snapshot belongs to another member"));
        }
        return opened(VaultEngine.resume(host.client(), me, snapshot.state(), host.clock()), host);
    }

    // --- Reading ---------------------------------------------------------------------------------

    /**
     * What the pull that opened this copy found: every state of the chain for {@code open} and {@code join},
     * the states past the pin for {@code resume}, nothing for {@code create}.
     *
     * @return the report
     * @since 1.0.0
     */
    public SyncReport openReport() {
        return report(engine().openReport());
    }

    private Map<String, VaultMember> rosterById() {
        Map<String, VaultMember> byId = new HashMap<>();
        for (VaultMember m : roster()) {
            byId.put(m.memberId(), m);
        }
        return byId;
    }

    private static List<VaultMember> members(List<LeaveRequest> leaves, Map<String, VaultMember> byId) {
        List<VaultMember> out = new ArrayList<>();
        for (LeaveRequest l : leaves) {
            VaultMember m = byId.get(AvpBytes.base64(l.memberKey()));
            if (m != null) {
                out.add(m);
            }
        }
        return List.copyOf(out);
    }

    private SyncReport report(PullReport r) {
        return new SyncReport(
                r.newStates(),
                r.divergedAt(),
                r.policyTurnedOn(),
                r.readableHeads().size(),
                r.unreadableHeads().size(),
                r.discardedCommits().size(),
                r.malformedItems(),
                members(r.leaves(), rosterById()),
                r.mergeCommit().isPresent());
    }

    /**
     * Syncs with the home host (AVP SPEC 5, 6.4, 7.5): verifies every new manifest state and pins the
     * highest, checks every head, reads and merges the heads it can, and pushes a merge commit when it read
     * more than one. A head this device cannot read is left alone and counted, never a failure.
     *
     * <p>A forged state, a chain without the pin that does not win the tie rule (a rollback), or any state
     * that fails a SPEC 6.1 check fails the whole sync with {@code PROTOCOL}; such a sync adopts no state,
     * reads no head and pushes no commit, so the copy stays as it was. This is stricter than the reference
     * client, which keeps the valid prefix of what a host served.
     *
     * <p>A sync that finds no new state and at most one readable head pushes nothing. One that finds more
     * than one readable head merges them and pushes a merge commit, even when the host served nothing new
     * (heads that diverged earlier, or a merge push that failed).
     *
     * @return the report; fails with {@code PROTOCOL} as above, {@code INVALID_INPUT} after {@link #leave()},
     *     or the host's refusal by its kind
     * @since 1.0.0
     */
    public CompletableFuture<SyncReport> sync() {
        return VaultFutures.guard(engine().pull().thenApply(this::report));
    }

    /**
     * The accounts of this copy that are not deleted, by player UUID, as the last finished operation left
     * them. While the repository withholds refresh tokens, none carries a {@code refreshToken} or an {@code
     * expiresAt} (SPEC 5.1). Nothing here is written to the runtime's {@link lol.trq.alts.store.AccountStore}:
     * an account of a shared repository is one the user chose not to save, and a host that wants one saved
     * adds it itself.
     *
     * @return the accounts, sorted by UUID
     * @since 1.0.0
     */
    public List<AltAccount> accounts() {
        List<AltAccount> out = new ArrayList<>();
        engine().payload().accounts().forEach((uuid, a) -> {
            if (!a.isDeleted()) {
                out.add(AccountMapping.toAccount(uuid, a));
            }
        });
        return List.copyOf(out);
    }

    /**
     * One account of this copy, unless it is absent or deleted.
     *
     * @param uuid the player UUID
     * @return the account, or empty
     * @since 1.0.0
     */
    public Optional<AltAccount> account(String uuid) {
        Objects.requireNonNull(uuid, "uuid");
        Payload.Account a = engine().payload().accounts().get(uuid);
        return a == null || a.isDeleted() ? Optional.empty() : Optional.of(AccountMapping.toAccount(uuid, a));
    }

    // --- Writing ---------------------------------------------------------------------------------

    private static CompletableFuture<Void> done(CompletableFuture<?> f) {
        return VaultFutures.guard(f.thenApply(x -> null));
    }

    private static AltsException noUuid() {
        return VaultFutures.invalid("an account needs its player UUID");
    }

    /**
     * Edits one account in the repository as one commit (AVP SPEC 5): the recommended way to change an
     * account. {@code edit} runs inside the write, on the account as this copy holds it at that moment, and
     * only the fields where its result differs from what it was given take a fresh stamp from the vault's
     * clock. A remote edit of any other field, merged into this copy before or while the caller worked, is
     * never reverted. A ban server the result drops is cleared. An edit that changes nothing sends no commit.
     * While the repository withholds refresh tokens, the account it is given carries no {@code refreshToken}
     * or {@code expiresAt}, and none is sent.
     *
     * <p>{@code edit} runs on the runtime's executor, one write at a time; it must not block on this vault.
     *
     * @param uuid the player UUID
     * @param edit the change, for example {@code a -> a.withTokens(access, refresh, expiresAt)}
     * @return the account as this copy holds it after the write; fails with {@code NOT_FOUND} if this copy
     *     holds no such account or holds it deleted, {@code INVALID_INPUT} if {@code edit} returns null or
     *     another UUID or after {@link #leave()}, {@code PROTOCOL} if the vault holds an impossible timestamp
     *     from a member, and the host's refusal by its kind
     * @since 1.0.0
     */
    public CompletableFuture<AltAccount> update(String uuid, UnaryOperator<AltAccount> edit) {
        Objects.requireNonNull(uuid, "uuid");
        Objects.requireNonNull(edit, "edit");
        VaultEngine e = engine();
        AtomicReference<AltAccount> stored = new AtomicReference<>();
        return VaultFutures.guard(e.write(editor -> {
                    boolean share = e.tip().state().shareRefreshTokens();
                    Payload.Account current =
                            editor.payload().underPolicy(share).accounts().get(uuid);
                    if (current == null || current.isDeleted()) {
                        throw new AltsException(Kind.NOT_FOUND, "Vault: this copy holds no such account");
                    }
                    AltAccount base = AccountMapping.toAccount(uuid, current);
                    AltAccount edited = edit.apply(base);
                    if (edited == null || !uuid.equals(edited.uuid())) {
                        throw VaultFutures.invalid("an account edit returns the account, with the same UUID");
                    }
                    AccountMapping.write(editor, base, edited, share);
                    Payload after = editor.payload().underPolicy(share);
                    stored.set(AccountMapping.toAccount(uuid, after.accounts().get(uuid)));
                })
                .thenApply(id -> stored.get()));
    }

    /**
     * Writes an edit of an account the caller read earlier, as one commit (AVP SPEC 5): only the fields where
     * {@code base} and {@code edited} differ take a fresh stamp, so a remote edit of any other field, merged
     * into this copy since {@code base} was read, survives. A ban server {@code base} had and {@code edited}
     * drops is cleared. An account this copy does not hold, or holds deleted, is written whole from {@code
     * edited}, including clearing every ban server it held before its deletion that {@code edited} does not
     * carry. An edit that changes nothing sends no commit. While the repository withholds refresh tokens,
     * {@code refreshToken} and {@code expiresAt} are not sent.
     *
     * @param base the account as read, from {@link #account(String)} or {@link #accounts()}
     * @param edited the account as changed; the same UUID
     * @return completes once the host stored the commit; fails with {@code INVALID_INPUT} for a missing or
     *     mismatched UUID or after {@link #leave()}, {@code PROTOCOL} if the vault holds an impossible
     *     timestamp from a member, and the host's refusal by its kind
     * @since 1.0.0
     */
    public CompletableFuture<Void> put(AltAccount base, AltAccount edited) {
        Objects.requireNonNull(base, "base");
        Objects.requireNonNull(edited, "edited");
        if (edited.uuid() == null || edited.uuid().isBlank()) {
            return VaultFutures.failed(noUuid());
        }
        if (!edited.uuid().equals(base.uuid())) {
            return VaultFutures.failed(VaultFutures.invalid("an account edit keeps the account's UUID"));
        }
        VaultEngine e = engine();
        return done(e.write(editor ->
                AccountMapping.write(editor, base, edited, e.tip().state().shareRefreshTokens())));
    }

    /**
     * Writes an account into the repository as one commit (AVP SPEC 5), stamping the fields that differ from
     * the copy as it stands when the write runs; a stale object can revert remote edits; use {@link #update}.
     * A new or deleted account is written whole, and a revived one loses every ban server it held before its
     * deletion that it does not carry now. Each ban the account carries is written per server id; on a live
     * account, a server it does not mention is left as it is (clear one with {@link #markBanned} and a null
     * ban). A put that changes nothing sends no commit. While the repository withholds refresh tokens, its
     * {@code refreshToken} and {@code expiresAt} are not sent.
     *
     * <p>"Stale" means read before the copy merged a remote edit of the same account: such an object differs
     * from the copy in exactly the field the other member changed, and putting it stamps that field back.
     * {@link #update} and {@link #put(AltAccount, AltAccount)} compare with what the caller started from
     * instead, and are safe for a read-modify-write.
     *
     * @param account the account
     * @return completes once the host stored the commit; fails with {@code INVALID_INPUT} for an account
     *     without a UUID or after {@link #leave()}, {@code PROTOCOL} if the vault holds an impossible timestamp
     *     from a member, and the host's refusal by its kind
     * @since 1.0.0
     */
    public CompletableFuture<Void> put(AltAccount account) {
        Objects.requireNonNull(account, "account");
        if (account.uuid() == null || account.uuid().isBlank()) {
            return VaultFutures.failed(noUuid());
        }
        VaultEngine e = engine();
        return done(e.write(
                editor -> AccountMapping.write(editor, account, e.tip().state().shareRefreshTokens())));
    }

    /**
     * Deletes an account from the repository: its deletion marker takes a fresh stamp and its fields stay, so
     * a later {@link #put} brings it back (AVP SPEC 5).
     *
     * @param uuid the player UUID
     * @return completes once the host stored the commit; fails as {@link #put}
     * @since 1.0.0
     */
    public CompletableFuture<Void> remove(String uuid) {
        Objects.requireNonNull(uuid, "uuid");
        if (uuid.isBlank()) {
            return VaultFutures.failed(noUuid());
        }
        return done(engine().write(e -> e.deleteAccount(uuid)));
    }

    /**
     * Records the ban an account was last observed with on one server, as the register for that server id
     * (AVP SPEC 5); other servers' registers stay.
     *
     * @param uuid the player UUID
     * @param serverId the server id, an opaque host-chosen string
     * @param ban the ban, or {@code null} to clear that server's register
     * @return completes once the host stored the commit; fails as {@link #put}
     * @since 1.0.0
     */
    public CompletableFuture<Void> markBanned(String uuid, String serverId, BanInfo ban) {
        Objects.requireNonNull(uuid, "uuid");
        Objects.requireNonNull(serverId, "serverId");
        if (uuid.isBlank()) {
            return VaultFutures.failed(noUuid());
        }
        return done(engine().write(e -> e.setBan(uuid, serverId, AccountMapping.banJson(ban))));
    }

    /**
     * Merges every readable head into this copy and, when there was more than one, pushes the merge commit
     * whose parents are exactly those heads (AVP SPEC 5). {@link #sync()} already does this.
     *
     * @return whether a merge commit was pushed
     * @since 1.0.0
     */
    public CompletableFuture<Boolean> mergeHeads() {
        return VaultFutures.guard(engine().mergeHeads().thenApply(Optional::isPresent));
    }

    // --- Members and hosts -----------------------------------------------------------------------

    /**
     * The members as the latest verified manifest state lists them, the owner's device among them.
     *
     * @return the roster, in the state's order
     * @since 1.0.0
     */
    public List<VaultMember> roster() {
        Manifest.ManifestState tip = engine().tip().state();
        List<VaultMember> out = new ArrayList<>();
        for (Manifest.MemberEntry m : tip.members()) {
            out.add(VaultMember.of(m, tip.ownerKey()));
        }
        return List.copyOf(out);
    }

    /**
     * The hosts of the repository as the latest verified manifest state lists them.
     *
     * @return the hosts, in the state's order
     * @since 1.0.0
     */
    public List<HostRef> hosts() {
        List<HostRef> out = new ArrayList<>();
        for (Manifest.HostRef h : engine().tip().state().hosts()) {
            out.add(HostRef.of(h));
        }
        return List.copyOf(out);
    }

    /**
     * The members whose pending leave request passed the AVP SPEC 8.4 checks at the last pull.
     *
     * @return the leaving members
     * @since 1.0.0
     */
    public List<VaultMember> pendingLeaves() {
        return members(engine().pendingLeaves(), rosterById());
    }

    /**
     * Invites a member from the invite token the joiner sent (AVP SPEC 8.1, 8.2). The token's host acceptance
     * must verify under its host key and name this repository, the token's member key and its home host, and
     * must not have expired. The data key is wrapped to exactly the token's key, never to a key a host
     * served, and the joiner's home host joins the repository's hosts when it is not listed yet. Owner only.
     *
     * @param token the joiner's invite token ({@link InviteToken#parse(String)} reads pasted text)
     * @return completes once the host stored the new state; fails with {@code PROTOCOL} for an acceptance
     *     that does not verify, {@code INVALID_INPUT} unless this device is the owner, or for a current or
     *     removed member, and the host's refusal by its kind
     * @since 1.0.0
     */
    public CompletableFuture<Void> invite(InviteToken token) {
        Objects.requireNonNull(token, "token");
        return done(engine().invite(token.token()));
    }

    /**
     * Removes a member (AVP SPEC 8.3): rotates the data key to a new epoch wrapped to every remaining member,
     * records the removal with its cutoff, and carries the merged accounts forward under the new key. The
     * removed member keeps what it already decrypted. Owner only.
     *
     * @param member the member, from {@link #roster()}
     * @return completes once the host stored the new state; fails with {@code INVALID_INPUT} unless this
     *     device is the owner, for the owner itself or a key that is not a member, and the host's refusal by
     *     its kind
     * @since 1.0.0
     */
    public CompletableFuture<Void> remove(VaultMember member) {
        Objects.requireNonNull(member, "member");
        return done(engine().remove(member.key()));
    }

    /**
     * Sets the refresh-token policy (AVP SPEC 5.1, 8.5) in a new owner-signed state. Sharing is irrevocable
     * for what was shared: turning it off stops future sharing only. Setting the current value publishes
     * nothing. Owner only.
     *
     * @param share whether the members share refresh tokens
     * @return completes once the host stored the new state; fails with {@code INVALID_INPUT} unless this
     *     device is the owner, and the host's refusal by its kind
     * @since 1.0.0
     */
    public CompletableFuture<Void> setShareRefreshTokens(boolean share) {
        return done(engine().setShareRefreshTokens(share));
    }

    /**
     * Whether the latest verified state shares refresh tokens (AVP SPEC 5.1).
     *
     * @return whether the policy shares
     * @since 1.0.0
     */
    public boolean sharesRefreshTokens() {
        return engine().tip().state().shareRefreshTokens();
    }

    /**
     * Pulls, then removes every member whose pending leave request passes the AVP SPEC 8.4 checks, one
     * removal each (as {@link #remove(VaultMember)}). Owner only.
     *
     * @return the members removed, as the roster listed them after the pull; fails with {@code INVALID_INPUT}
     *     unless this device is the owner, and the host's refusal by its kind
     * @since 1.0.0
     */
    public CompletableFuture<List<VaultMember>> processLeaves() {
        VaultEngine e = engine();
        return VaultFutures.guard(e.pull().thenCompose(pulled -> {
            Map<String, VaultMember> before = rosterById();
            return e.processLeaves().thenApply(removed -> {
                List<VaultMember> out = new ArrayList<>();
                for (byte[] key : removed) {
                    VaultMember m = before.get(AvpBytes.base64(key));
                    if (m != null) {
                        out.add(m);
                    }
                }
                return List.copyOf(out);
            });
        }));
    }

    /**
     * Leaves the repository (AVP SPEC 8.4): sends a signed leave request and stops syncing at once; every
     * later operation that talks to the host is refused, and a snapshot taken afterwards does not resume. The
     * owner removes the member when it next processes leaves. The owner cannot leave.
     *
     * @return completes once the host stored the request; fails with {@code INVALID_INPUT} for the owner, and
     *     the host's refusal by its kind
     * @since 1.0.0
     */
    public CompletableFuture<Void> leave() {
        return done(engine().leave());
    }

    /**
     * Whether this member left the repository.
     *
     * @return whether it left
     * @since 1.0.0
     */
    public boolean left() {
        return engine().left();
    }

    /**
     * Whether this device is the owner's.
     *
     * @return whether its key is the owner key
     * @since 1.0.0
     */
    public boolean isOwner() {
        return engine().isOwner();
    }

    /**
     * The repository id.
     *
     * @return the id
     * @since 1.0.0
     */
    public String repoId() {
        return engine().repoId();
    }

    /**
     * This device's member id, as {@code lastUsedBy} and {@code observedBy} name it.
     *
     * @return the member id
     * @since 1.0.0
     */
    public String memberId() {
        return engine().member().id();
    }

    /**
     * The home host this copy syncs through.
     *
     * @return the connection
     * @since 1.0.0
     */
    public VaultHost host() {
        engine();
        return home;
    }

    /**
     * The repo locator to give a joiner (AVP SPEC 11.2): this repository at the owner's home host, with the
     * owner fingerprint. Owner only.
     *
     * @return the locator
     * @throws AltsException of kind {@code INVALID_INPUT} unless this device is the owner
     * @since 1.0.0
     */
    public RepoLocator locator() {
        return new RepoLocator(engine().locator());
    }

    /**
     * The state to persist, so {@link #resume} can open this copy again: the pin, the retained epoch keys,
     * the clock and the merged accounts, as the last finished operation left them. Take one after every
     * operation that changes the copy. It holds secrets (the data keys and the accounts' credentials):
     * persist its {@link VaultSnapshot#toJson()} encrypted, for example in {@link
     * lol.trq.alts.store.HostSecrets}, never in plain text.
     *
     * @return the snapshot
     * @since 1.0.0
     */
    public VaultSnapshot snapshot() {
        VaultEngine e = engine();
        return new VaultSnapshot(e.state(), e.member().id(), home.ref());
    }
}

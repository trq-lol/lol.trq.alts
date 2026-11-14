package lol.trq.alts.vault;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParseException;
import com.google.gson.annotations.SerializedName;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.UnaryOperator;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.crypto.CryptoException;
import lol.trq.alts.crypto.KeyWrapScheme;
import lol.trq.alts.crypto.PayloadCipher;
import lol.trq.alts.crypto.RepoDataKey;
import lol.trq.alts.crypto.X25519;
import lol.trq.alts.internal.avp.AvpBytes;
import lol.trq.alts.internal.avp.Manifest;
import lol.trq.alts.internal.avp.Payload;
import lol.trq.alts.internal.avp.Tokens.LeaveRequest;
import lol.trq.alts.internal.vault.MemberKeys;
import lol.trq.alts.internal.vault.PullReport;
import lol.trq.alts.internal.vault.VaultEngine;
import lol.trq.alts.model.AltAccount;
import lol.trq.alts.model.BanInfo;
import lol.trq.alts.vault.transport.EncryptedEnvelope;
import lol.trq.alts.vault.transport.KeyBindingVerifier;
import lol.trq.alts.vault.transport.MemberEntry;
import lol.trq.alts.vault.transport.VaultManifest;

/**
 * A shared alt repository. This type carries two protocols while the library moves to AVP 0.5, and the 0.4
 * half (the public constructors, their instance methods, {@link CreatedRepo} and {@link RotationResult}) is
 * removed before 1.0.0. An instance is one or the other: a 0.4 facade calling an AVP 0.5 method, or an AVP
 * 0.5 copy calling a 0.4 method, throws {@link IllegalStateException}.
 *
 * <h2>AVP 0.5: one member device's copy</h2>
 *
 * <p>An instance from {@link #create}, {@link #open}, {@link #join} or {@link #resume} is one member
 * device's copy of one AVP 0.5 repository, synced through its home host ({@link VaultHost}, from {@code
 * alts.vault()}). The client never trusts a host: it verifies every owner-signed manifest state from genesis
 * and pins the highest, refuses a rollback, checks every member-signed commit, merges the heads per account
 * and per field, wraps the data key only to invite-token keys, and withholds {@code refreshToken} and {@code
 * expiresAt} on read and on write unless the latest verified state shares them. A forged state or a
 * rollback fails the whole operation with {@code PROTOCOL} and changes nothing, where the reference client
 * keeps the valid prefix of what a host served. No secret (the owner phrase, its entropy or seed, a private
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
 * <h2>AVP 0.4: the local crypto facade</h2>
 *
 * <p>The local, transport-free crypto facade for a shared alt repository. Every method here is pure
 * client-side cryptography over plain DTOs — it creates and opens repositories, wraps the data key to
 * members, and encrypts/decrypts the alt payload. Moving those DTOs to and from a server is a separate
 * concern handled by a {@link lol.trq.alts.vault.transport.VaultTransport}; this class never touches
 * the network, which keeps it trivially unit-testable: the server only ever sees what these methods
 * emit.
 *
 * <p>What that buys is confidentiality against a server that stores and relays faithfully, and against
 * anyone observing the network. It does not, on its own, defend against a server that actively
 * substitutes keys: nothing in the current protocol signs a wrapped data key, a manifest, or an
 * envelope. Two local defences narrow that gap. A {@link KeyBindingVerifier} is consulted before the
 * data key is wrapped to any other member's keys, so a host that supplies a real verifier cannot be
 * tricked into wrapping to keys the server swapped in. And a {@link RepoPin} the host persists between
 * sessions stops a server from rolling a repository back to an earlier key epoch or payload version.
 *
 * <p>The payload carries {@link AltAccount}s — the credential plus shareable account state
 * (last-used activity and observed-ban status, so members coordinate and avoid handing each other a
 * banned alt). What stays local and never enters a repo is the per-member current-account pointer and
 * the user's own secrets (kept in {@link lol.trq.alts.store.HostSecrets}).
 *
 * @author trq
 * @since 0.2.0
 */
public final class SharedVault {

    private static final Gson GSON = new GsonBuilder().create();

    private final KeyWrapScheme scheme;
    private final KeyBindingVerifier keyBindingVerifier;
    private final VaultEngine engine;
    private final VaultHost home;

    /**
     * Creates a vault facade that trusts whatever member keys it is handed, without verification. It
     * installs {@link KeyBindingVerifier#trustTransport()} implicitly, and is the only place a verifier
     * is ever chosen for the caller.
     *
     * @param scheme the key-wrap scheme (for example {@link lol.trq.alts.crypto.X25519HkdfAesGcmKeyWrap})
     * @deprecated use {@link #SharedVault(KeyWrapScheme, KeyBindingVerifier)} and choose the verifier
     *     deliberately. This constructor behaves exactly as if {@link KeyBindingVerifier#trustTransport()}
     *     had been passed, which lets a hostile server substitute a member's keys and receive the
     *     repository data key.
     */
    @Deprecated(since = "0.12.0")
    public SharedVault(KeyWrapScheme scheme) {
        this(scheme, KeyBindingVerifier.trustTransport());
    }

    /**
     * Creates a vault facade over the given key-wrap scheme, verifying every other member's public keys
     * through {@code keyBindingVerifier} before the data key is wrapped to them.
     *
     * <p>Pass a real verifier (for example
     * {@link lol.trq.alts.vault.transport.IssuerSignedKeyBindingVerifier}) whenever member keys reach
     * the host through a server it does not fully trust. Passing
     * {@link KeyBindingVerifier#trustTransport()} is an explicit decision to accept served keys as-is.
     *
     * @param scheme the key-wrap scheme (for example {@link lol.trq.alts.crypto.X25519HkdfAesGcmKeyWrap})
     * @param keyBindingVerifier the check run on a member's keys before wrapping to them
     * @since 0.12.0
     */
    public SharedVault(KeyWrapScheme scheme, KeyBindingVerifier keyBindingVerifier) {
        this.scheme = Objects.requireNonNull(scheme, "scheme");
        this.keyBindingVerifier = Objects.requireNonNull(keyBindingVerifier, "keyBindingVerifier");
        this.engine = null;
        this.home = null;
    }

    /**
     * The product of creating a repository: the working context, the seed manifest to upload, and the
     * initial encrypted payload.
     *
     * @param context the working context for the creator
     * @param manifest the seed manifest (creator-only roster)
     * @param envelope the initial encrypted payload
     */
    public record CreatedRepo(RepoContext context, VaultManifest manifest, EncryptedEnvelope envelope) {}

    /**
     * The product of a key rotation: the advanced context, the re-encrypted payload, the re-wrapped
     * member roster, and the new epoch.
     *
     * @param context the advanced working context (new key, bumped version)
     * @param envelope the payload re-encrypted under the new epoch
     * @param rewrappedMembers the remaining members with the new key wrapped to each
     * @param newKeyEpoch the new key epoch
     */
    public record RotationResult(
            RepoContext context, EncryptedEnvelope envelope, List<MemberEntry> rewrappedMembers, long newKeyEpoch) {}

    /**
     * Creates a fresh repository owned by {@code creator}, with the given initial alts. The repository
     * withholds refresh tokens; use {@link #createRepo(VaultIdentity, List, boolean)} to opt in.
     *
     * @param creator the creating member's unlocked identity
     * @param alts the initial alt payload (may be empty)
     * @return the created repository artifacts
     * @throws CryptoException if key generation or encryption fails
     */
    public CreatedRepo createRepo(VaultIdentity creator, List<AltAccount> alts) throws CryptoException {
        facade();
        return createRepo(creator, alts, false);
    }

    /**
     * Creates a fresh repository owned by {@code creator} with an explicit refresh-token sharing policy.
     *
     * @param creator the creating member's unlocked identity
     * @param alts the initial alt payload (may be empty)
     * @param shareRefreshTokens whether members may share refresh tokens through this repository
     * @return the created repository artifacts
     * @throws CryptoException if key generation or encryption fails
     * @since 0.6.0
     */
    public CreatedRepo createRepo(VaultIdentity creator, List<AltAccount> alts, boolean shareRefreshTokens)
            throws CryptoException {
        facade();
        String repoId = UUID.randomUUID().toString();
        RepoDataKey dataKey = RepoDataKey.generate();
        MemberEntry creatorEntry = selfEntry(creator, dataKey, null);
        long version = 1L;
        VaultManifest manifest = new VaultManifest(
                repoId, scheme.schemeId(), dataKey.epoch(), version, List.of(creatorEntry), shareRefreshTokens);
        EncryptedEnvelope envelope = encrypt(repoId, version, dataKey.epoch(), dataKey, alts, shareRefreshTokens);
        RepoContext context = new RepoContext(repoId, creator, dataKey, version, shareRefreshTokens);
        return new CreatedRepo(context, manifest, envelope);
    }

    /**
     * Opens a repository for {@code identity} by unwrapping the data key from their member entry, with
     * no rollback floor. Prefer {@link #openRepo(VaultManifest, VaultIdentity, RepoPin)} once the host
     * has seen the repository before: without a pin, a server can serve an older manifest unnoticed.
     *
     * @param manifest the repository manifest
     * @param identity the opening member's unlocked identity
     * @return the working context
     * @throws CryptoException if unwrapping fails
     * @throws VaultException if the identity is not a member of the repository, or the manifest names a
     *     different key-wrap scheme or is inconsistent
     */
    public RepoContext openRepo(VaultManifest manifest, VaultIdentity identity) throws CryptoException, VaultException {
        facade();
        return openRepo(manifest, identity, RepoPin.none());
    }

    /**
     * Opens a repository for {@code identity}, refusing a manifest older than the host last saw.
     *
     * <p>The manifest comes from the server, so its key epoch and payload version are claims. The pin is
     * the host's own record of the highest values it has already accepted for this repository; a
     * manifest below either is a rollback and is rejected. After a successful open (and after each
     * accepted pull, push, or rotation) persist {@link RepoContext#pin()} and pass it back next time.
     *
     * @param manifest the repository manifest
     * @param identity the opening member's unlocked identity
     * @param pin the lowest key epoch and payload version to accept ({@link RepoPin#none()} on first
     *     contact)
     * @return the working context; its {@link RepoContext#pin()} is the value to persist
     * @throws CryptoException if unwrapping fails
     * @throws VaultException if the identity is not a member of the repository, the manifest names a
     *     different key-wrap scheme, is inconsistent, or falls below the pin
     * @since 0.12.0
     */
    public RepoContext openRepo(VaultManifest manifest, VaultIdentity identity, RepoPin pin)
            throws CryptoException, VaultException {
        facade();
        Objects.requireNonNull(pin, "pin");
        served(manifest, "manifest");
        if (!scheme.schemeId().equals(manifest.schemeId())) {
            throw new VaultException("manifest key-wrap scheme " + manifest.schemeId()
                    + " is not the configured scheme " + scheme.schemeId());
        }
        if (manifest.keyEpoch() < pin.minimumKeyEpoch()) {
            throw new VaultException("key epoch rollback: " + manifest.keyEpoch() + " < " + pin.minimumKeyEpoch());
        }
        if (manifest.payloadVersion() < pin.minimumPayloadVersion()) {
            throw new VaultException(
                    "payload version rollback: " + manifest.payloadVersion() + " < " + pin.minimumPayloadVersion());
        }
        String memberId = identity.identityId();
        MemberEntry entry = manifest.findMember(memberId);
        if (entry == null) {
            throw new VaultException("identity is not a member of repository " + manifest.repoId());
        }
        if (entry.keyEpoch() != manifest.keyEpoch()) {
            throw new VaultException(
                    "member entry key epoch " + entry.keyEpoch() + " does not match manifest " + manifest.keyEpoch());
        }
        RepoDataKey dataKey = RepoDataKey.unwrap(
                scheme, entry.wrappedDataKey(), identity.keyAgreementPrivateKey(), manifest.keyEpoch());
        return new RepoContext(
                manifest.repoId(), identity, dataKey, manifest.payloadVersion(), manifest.shareRefreshTokens());
    }

    /**
     * Builds a member entry for a prospective member, wrapping the current data key to their X25519 key.
     * The configured {@link KeyBindingVerifier} is run with no key-binding signature, so this only
     * succeeds for a verifier that needs none.
     *
     * @param ctx the working context
     * @param member the prospective member's public keys
     * @return the member entry to upload
     * @throws CryptoException if wrapping fails, or the verifier refuses the keys
     * @deprecated use {@link #addMember(RepoContext, MemberPublicKey, String)}, which carries the
     *     key-binding signature to the verifier and reports a refusal as a {@link VaultException}
     */
    @Deprecated(since = "0.12.0")
    public MemberEntry addMember(RepoContext ctx, MemberPublicKey member) throws CryptoException {
        facade();
        try {
            return addMember(ctx, member, null);
        } catch (VaultException e) {
            throw new CryptoException("member keys were not verified: " + e.getMessage(), e);
        }
    }

    /**
     * Builds a member entry for a prospective member: verifies their public keys through the configured
     * {@link KeyBindingVerifier}, then wraps the current data key to the verified X25519 key.
     *
     * @param ctx the working context
     * @param member the prospective member's public keys, as claimed
     * @param keyBindingSig the issuer signature binding those keys to the identity, Base64, or
     *     {@code null} when none was published
     * @return the member entry to upload, carrying {@code keyBindingSig}
     * @throws CryptoException if a key is malformed or wrapping fails
     * @throws VaultException if the verifier refuses the keys
     * @since 0.12.0
     */
    public MemberEntry addMember(RepoContext ctx, MemberPublicKey member, String keyBindingSig)
            throws CryptoException, VaultException {
        facade();
        Objects.requireNonNull(member, "member");
        return verifiedEntry(ctx.repoId(), member, keyBindingSig, ctx.dataKey());
    }

    /**
     * Encrypts a new payload at {@code ctx.payloadVersion() + 1}. The caller advances its context with
     * {@link RepoContext#withPayloadVersion(long)} once the push is accepted.
     *
     * @param ctx the working context
     * @param alts the alts to encrypt
     * @return the encrypted envelope at the next version
     * @throws CryptoException if encryption fails
     */
    public EncryptedEnvelope encryptPayload(RepoContext ctx, List<AltAccount> alts) throws CryptoException {
        facade();
        long nextVersion = ctx.payloadVersion() + 1;
        return encrypt(ctx.repoId(), nextVersion, ctx.dataKey().epoch(), ctx.dataKey(), alts, ctx.shareRefreshTokens());
    }

    /**
     * Decrypts a payload envelope, rejecting an envelope from a different repository, one sealed under
     * a different key epoch than the context holds, or one that rolls the version back below
     * {@code expectedMinVersion}.
     *
     * @param ctx the working context
     * @param env the encrypted envelope
     * @param expectedMinVersion the lowest acceptable payload version (pass {@code ctx.payloadVersion()}
     *     to forbid rollback, or 0 to allow any)
     * @return the decrypted alts
     * @throws CryptoException if decryption fails (wrong key or tampering)
     * @throws VaultException if the repo id or key epoch mismatches, the version is rolled back, or the
     *     envelope or its payload is malformed
     */
    public List<AltAccount> decryptPayload(RepoContext ctx, EncryptedEnvelope env, long expectedMinVersion)
            throws CryptoException, VaultException {
        facade();
        served(env, "envelope");
        if (!env.repoId().equals(ctx.repoId())) {
            throw new VaultException("envelope repo id does not match context");
        }
        if (env.keyEpoch() != ctx.dataKey().epoch()) {
            throw new VaultException("envelope key epoch " + env.keyEpoch() + " does not match the open data key epoch "
                    + ctx.dataKey().epoch());
        }
        if (env.payloadVersion() < expectedMinVersion) {
            throw new VaultException("payload rollback: " + env.payloadVersion() + " < " + expectedMinVersion);
        }
        byte[] iv = decodeEnvelope(env.iv(), "iv");
        byte[] ciphertext = decodeEnvelope(env.ciphertext(), "ciphertext");
        byte[] aad = PayloadCipher.aad(env.repoId(), env.payloadVersion(), env.keyEpoch());
        byte[] plaintext = PayloadCipher.decrypt(ctx.dataKey().secretKey(), iv, aad, ciphertext);
        VaultPayload payload;
        try {
            payload = GSON.fromJson(new String(plaintext, StandardCharsets.UTF_8), VaultPayload.class);
        } catch (JsonParseException e) {
            throw new VaultException("payload is not a well-formed alt list", e);
        } finally {
            Arrays.fill(plaintext, (byte) 0);
        }
        return payload == null || payload.alts() == null
                ? new ArrayList<>()
                : applyPolicy(payload.alts(), ctx.shareRefreshTokens());
    }

    /**
     * Rotates the data key to a fresh one at the next epoch, re-encrypts the payload, and re-wraps the
     * new key to {@code remainingMembers}. The configured {@link KeyBindingVerifier} is run on every
     * member other than the caller with no key-binding signature, so this only succeeds for a verifier
     * that needs none.
     *
     * @param ctx the working context
     * @param currentAlts the alts to carry into the new epoch
     * @param remainingMembers the members who retain access
     * @return the rotation result
     * @throws CryptoException if key generation, wrapping, or encryption fails, or the verifier refuses
     *     a member's keys
     * @deprecated use {@link #rotateKey(RepoContext, List, VaultManifest)}, which verifies each served
     *     member entry with its key-binding signature and keeps that signature on the re-wrapped roster
     */
    @Deprecated(since = "0.12.0")
    public RotationResult rotateKey(
            RepoContext ctx, List<AltAccount> currentAlts, List<MemberPublicKey> remainingMembers)
            throws CryptoException {
        facade();
        List<Claim> claimed = new ArrayList<>(remainingMembers.size());
        for (MemberPublicKey member : remainingMembers) {
            if (member == null) {
                throw new CryptoException("member list contains a null entry");
            }
            claimed.add(new Claim(member, null));
        }
        try {
            return rotate(ctx, currentAlts, claimed);
        } catch (VaultException e) {
            throw new CryptoException("member keys were not verified: " + e.getMessage(), e);
        }
    }

    /**
     * Rotates the data key to a fresh one at the next epoch, re-encrypts the payload, and re-wraps the
     * new key to every member of {@code roster}. Each entry other than the caller's own is verified
     * through the configured {@link KeyBindingVerifier} first, using the key-binding signature the entry
     * carries; the caller's own entry must name the caller's real X25519 key. Signatures are carried
     * over to the re-wrapped entries.
     *
     * @param ctx the working context
     * @param currentAlts the alts to carry into the new epoch
     * @param roster the manifest whose members retain access (the caller must be among them)
     * @return the rotation result
     * @throws CryptoException if key generation, wrapping, or encryption fails
     * @throws VaultException if the roster belongs to another repository, omits the caller, is
     *     malformed, or holds a member whose keys the verifier refuses
     * @since 0.12.0
     */
    public RotationResult rotateKey(RepoContext ctx, List<AltAccount> currentAlts, VaultManifest roster)
            throws CryptoException, VaultException {
        facade();
        return rotate(ctx, currentAlts, rosterOf(ctx, roster, null));
    }

    /**
     * Removes a member: rotates the key to exactly the members in {@code remainingMembers} (which must
     * exclude the removed member). Equivalent to the deprecated list-based {@code rotateKey}.
     *
     * @param ctx the working context
     * @param currentAlts the alts to carry forward
     * @param remainingMembers the members who retain access (excluding the removed one)
     * @return the rotation result
     * @throws CryptoException if rotation fails, or the verifier refuses a member's keys
     * @deprecated use {@link #removeMember(RepoContext, List, VaultManifest, String)}
     */
    @Deprecated(since = "0.12.0")
    public RotationResult removeMember(
            RepoContext ctx, List<AltAccount> currentAlts, List<MemberPublicKey> remainingMembers)
            throws CryptoException {
        facade();
        return rotateKey(ctx, currentAlts, remainingMembers);
    }

    /**
     * Removes a member: rotates the key to every member of {@code roster} except
     * {@code removedMemberId}, verifying the others exactly as
     * {@link #rotateKey(RepoContext, List, VaultManifest)} does.
     *
     * @param ctx the working context
     * @param currentAlts the alts to carry forward
     * @param roster the current manifest, still listing the member being removed
     * @param removedMemberId the Ed25519 identity (member id) to drop
     * @return the rotation result
     * @throws CryptoException if rotation fails
     * @throws VaultException if the roster belongs to another repository, does not list the removed
     *     member, would remove the caller, is malformed, or holds a member whose keys the verifier refuses
     * @since 0.12.0
     */
    public RotationResult removeMember(
            RepoContext ctx, List<AltAccount> currentAlts, VaultManifest roster, String removedMemberId)
            throws CryptoException, VaultException {
        facade();
        Objects.requireNonNull(removedMemberId, "removedMemberId");
        if (removedMemberId.equals(ctx.identity().identityId())) {
            throw new VaultException("a member cannot remove itself by rotating the key");
        }
        served(roster, "roster");
        if (roster.findMember(removedMemberId) == null) {
            throw new VaultException("member to remove is not in the roster");
        }
        return rotate(ctx, currentAlts, rosterOf(ctx, roster, removedMemberId));
    }

    private List<Claim> rosterOf(RepoContext ctx, VaultManifest roster, String excludedMemberId)
            throws CryptoException, VaultException {
        served(roster, "roster");
        if (!roster.repoId().equals(ctx.repoId())) {
            throw new VaultException("roster repo id does not match context");
        }
        String selfId = ctx.identity().identityId();
        List<Claim> kept = new ArrayList<>(roster.members().size());
        boolean self = false;
        for (MemberEntry entry : roster.members()) {
            if (entry == null) {
                throw new VaultException("roster contains a null member entry");
            }
            if (entry.ed25519PublicKey().equals(excludedMemberId)) {
                continue;
            }
            self |= entry.ed25519PublicKey().equals(selfId);
            kept.add(new Claim(
                    new MemberPublicKey(entry.ed25519PublicKey(), entry.x25519PublicKey()), entry.keyBindingSig()));
        }
        if (!self) {
            throw new VaultException("roster does not list the rotating member");
        }
        return kept;
    }

    private RotationResult rotate(RepoContext ctx, List<AltAccount> currentAlts, List<Claim> claimed)
            throws CryptoException, VaultException {
        long newEpoch = ctx.dataKey().epoch() + 1;
        RepoDataKey newDataKey = RepoDataKey.generate(newEpoch);
        String selfId = ctx.identity().identityId();
        List<MemberEntry> rewrapped = new ArrayList<>(claimed.size());
        for (Claim claim : claimed) {
            if (claim.keys().ed25519PublicKey().equals(selfId)) {
                String ownKey = encodeKey(ctx.identity().keyAgreementPublicKey());
                if (!ownKey.equals(claim.keys().x25519PublicKey())) {
                    throw new VaultException("roster lists a different X25519 key for the rotating member");
                }
                rewrapped.add(selfEntry(ctx.identity(), newDataKey, claim.keyBindingSig()));
            } else {
                rewrapped.add(verifiedEntry(ctx.repoId(), claim.keys(), claim.keyBindingSig(), newDataKey));
            }
        }
        long newVersion = ctx.payloadVersion() + 1;
        RepoContext newCtx =
                new RepoContext(ctx.repoId(), ctx.identity(), newDataKey, newVersion, ctx.shareRefreshTokens());
        EncryptedEnvelope envelope =
                encrypt(ctx.repoId(), newVersion, newEpoch, newDataKey, currentAlts, ctx.shareRefreshTokens());
        return new RotationResult(newCtx, envelope, rewrapped, newEpoch);
    }

    /**
     * Wraps {@code dataKey} to a member only after the verifier has vouched for the keys. The verifier
     * runs first, on the claimed keys and their signature alone, and the data key is then wrapped to
     * the keys it returned: no wrap to an unverified key is ever computed, not even one to discard.
     */
    private MemberEntry verifiedEntry(String repoId, MemberPublicKey claimed, String keyBindingSig, RepoDataKey dataKey)
            throws CryptoException, VaultException {
        MemberPublicKey verified = keyBindingVerifier.verify(repoId, claimed, keyBindingSig);
        if (verified == null) {
            throw new VaultException("key-binding verifier returned no keys for member " + claimed.ed25519PublicKey());
        }
        MemberEntry entry = unverifiedEntry(verified, dataKey);
        // The signature covers the claimed pair, so it stays on the entry only when that is the pair used.
        return verified.equals(claimed) ? entry.withKeyBindingSig(keyBindingSig) : entry;
    }

    private MemberEntry unverifiedEntry(MemberPublicKey member, RepoDataKey dataKey) throws CryptoException {
        byte[] raw;
        try {
            raw = Base64.getDecoder().decode(member.x25519PublicKey());
        } catch (IllegalArgumentException e) {
            throw new CryptoException("member X25519 public key is not Base64", e);
        }
        PublicKey recipient = X25519.decodePublicKey(raw);
        return new MemberEntry(
                member.ed25519PublicKey(),
                member.x25519PublicKey(),
                dataKey.wrapTo(scheme, recipient),
                dataKey.epoch());
    }

    private MemberEntry selfEntry(VaultIdentity identity, RepoDataKey dataKey, String keyBindingSig)
            throws CryptoException {
        PublicKey own = identity.keyAgreementPublicKey();
        return new MemberEntry(
                identity.identityId(), encodeKey(own), dataKey.wrapTo(scheme, own), dataKey.epoch(), keyBindingSig);
    }

    private static String encodeKey(PublicKey x25519Public) throws CryptoException {
        return Base64.getEncoder().encodeToString(X25519.encodePublicKey(x25519Public));
    }

    /**
     * Refuses an object the transport was supposed to serve and did not. A transport that maps a
     * missing or empty response to null is an ordinary thing for a server to cause, so it is reported
     * as the checked exception a caller already handles rather than as a NullPointerException.
     *
     * @param dto what the transport returned
     * @param what its name, for the message
     * @throws VaultException if the transport returned nothing
     */
    private static void served(Object dto, String what) throws VaultException {
        if (dto == null) {
            throw new VaultException("no " + what + " was served");
        }
    }

    private static byte[] decodeEnvelope(String base64, String what) throws VaultException {
        if (base64 == null) {
            throw new VaultException("envelope " + what + " is missing");
        }
        try {
            return Base64.getDecoder().decode(base64);
        } catch (IllegalArgumentException e) {
            throw new VaultException("envelope " + what + " is not Base64", e);
        }
    }

    private EncryptedEnvelope encrypt(
            String repoId,
            long version,
            long epoch,
            RepoDataKey dataKey,
            List<AltAccount> alts,
            boolean shareRefreshTokens)
            throws CryptoException {
        String json = GSON.toJson(new VaultPayload(applyPolicy(alts, shareRefreshTokens), version));
        byte[] iv = PayloadCipher.newIv();
        byte[] aad = PayloadCipher.aad(repoId, version, epoch);
        byte[] plaintext = json.getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext;
        try {
            ciphertext = PayloadCipher.encrypt(dataKey.secretKey(), iv, aad, plaintext);
        } finally {
            Arrays.fill(plaintext, (byte) 0);
        }
        Base64.Encoder b64 = Base64.getEncoder();
        return new EncryptedEnvelope(repoId, version, epoch, b64.encodeToString(iv), b64.encodeToString(ciphertext));
    }

    /**
     * Applies the repository's refresh-token policy to a list of alts. Stripping happens on both write
     * and read: on write so the credential never reaches the server, and on read so a peer running a
     * modified build cannot push tokens into a repository whose policy forbids them. A null element
     * (which a peer can put in a payload) carries nothing and is dropped rather than dereferenced.
     */
    private static List<AltAccount> applyPolicy(List<AltAccount> alts, boolean shareRefreshTokens) {
        List<AltAccount> copy = new ArrayList<>(alts.size());
        for (AltAccount alt : alts) {
            if (alt == null) {
                continue;
            }
            copy.add(shareRefreshTokens ? alt : alt.withTokens(alt.accessToken(), null, 0L));
        }
        return copy;
    }

    // =================================================================================================
    // AVP 0.5: one member device's copy of a repository.
    // =================================================================================================

    /**
     * Builds the AVP 0.5 copy around an opened engine.
     *
     * @param engine the engine
     * @param host the home host connection
     */
    private SharedVault(VaultEngine engine, VaultHost host) {
        this.scheme = null;
        this.keyBindingVerifier = null;
        this.engine = engine;
        this.home = host;
    }

    /**
     * Refuses a 0.4 operation on an AVP 0.5 copy, which holds no key-wrap scheme or verifier.
     *
     * @throws IllegalStateException on an AVP 0.5 copy
     */
    private void facade() {
        if (engine != null) {
            throw new IllegalStateException("an AVP 0.5 copy is not a 0.4 facade");
        }
    }

    /** The engine, for a test that writes a payload no {@link AltAccount} can express. */
    VaultEngine engineForTests() {
        return engine();
    }

    private VaultEngine engine() {
        if (engine == null) {
            throw new IllegalStateException("a 0.4 facade holds no AVP 0.5 repository copy");
        }
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
     * that fails a SPEC 6.1 check fails the whole sync with {@code PROTOCOL} and changes nothing. This is
     * stricter than the reference client, which keeps the valid prefix of what a host served.
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
     * edited}. An edit that changes nothing sends no commit. While the repository withholds refresh tokens,
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
     * A new or deleted account is written whole. Each ban the account carries is written per server id; a
     * server it does not mention is left as it is (clear one with {@link #markBanned} and a null ban). A put
     * that changes nothing sends no commit. While the repository withholds refresh tokens, its {@code
     * refreshToken} and {@code expiresAt} are not sent.
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

    /**
     * A member's public keys as claimed by whoever supplied them, with the key-binding signature (if
     * any) that is meant to vouch for them.
     *
     * @param keys the claimed public keys
     * @param keyBindingSig the issuer signature over them, Base64, or null
     */
    private record Claim(MemberPublicKey keys, String keyBindingSig) {}

    /**
     * The plaintext payload structure encrypted into an envelope: the alts plus a redundant version
     * stamp (the authoritative version is the envelope header, bound into the AAD).
     *
     * @param alts the shared alts
     * @param payloadVersion the version stamp
     */
    private record VaultPayload(
            @SerializedName("alts") List<AltAccount> alts,
            @SerializedName("payloadVersion") long payloadVersion) {}
}

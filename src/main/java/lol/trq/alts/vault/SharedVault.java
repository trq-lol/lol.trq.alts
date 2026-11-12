package lol.trq.alts.vault;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.annotations.SerializedName;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import lol.trq.alts.crypto.CryptoException;
import lol.trq.alts.crypto.KeyWrapScheme;
import lol.trq.alts.crypto.PayloadCipher;
import lol.trq.alts.crypto.RepoDataKey;
import lol.trq.alts.crypto.VaultIdentity;
import lol.trq.alts.crypto.X25519;
import lol.trq.alts.model.AltAccount;
import lol.trq.alts.vault.transport.EncryptedEnvelope;
import lol.trq.alts.vault.transport.KeyBindingVerifier;
import lol.trq.alts.vault.transport.MemberEntry;
import lol.trq.alts.vault.transport.VaultManifest;

/**
 * The local, transport-free crypto facade for a shared alt repository. Every method here is pure
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
 * the user's own secrets (kept in {@link lol.trq.alts.store.SecretStore}).
 *
 * @author trq
 * @since 0.2.0
 */
public final class SharedVault {

    private static final Gson GSON = new GsonBuilder().create();

    private final KeyWrapScheme scheme;
    private final KeyBindingVerifier keyBindingVerifier;

    /**
     * Creates a vault facade that trusts whatever member keys it is handed, without verification.
     *
     * @param scheme the key-wrap scheme (for example {@link lol.trq.alts.crypto.X25519HkdfAesGcmKeyWrap})
     * @deprecated use {@link #SharedVault(KeyWrapScheme, KeyBindingVerifier)} and choose the verifier
     *     deliberately. This constructor behaves as if {@link KeyBindingVerifier#trustTransport()} had
     *     been passed, which lets a hostile server substitute a member's keys.
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
        Objects.requireNonNull(pin, "pin");
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
     * @throws VaultException if the repo id or key epoch mismatches, or the version is rolled back
     */
    public List<AltAccount> decryptPayload(RepoContext ctx, EncryptedEnvelope env, long expectedMinVersion)
            throws CryptoException, VaultException {
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
        byte[] iv = Base64.getDecoder().decode(env.iv());
        byte[] ciphertext = Base64.getDecoder().decode(env.ciphertext());
        byte[] aad = PayloadCipher.aad(env.repoId(), env.payloadVersion(), env.keyEpoch());
        byte[] plaintext = PayloadCipher.decrypt(ctx.dataKey().secretKey(), iv, aad, ciphertext);
        VaultPayload payload;
        try {
            payload = GSON.fromJson(new String(plaintext, StandardCharsets.UTF_8), VaultPayload.class);
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
        Objects.requireNonNull(removedMemberId, "removedMemberId");
        if (removedMemberId.equals(ctx.identity().identityId())) {
            throw new VaultException("a member cannot remove itself by rotating the key");
        }
        if (roster.findMember(removedMemberId) == null) {
            throw new VaultException("member to remove is not in the roster");
        }
        return rotate(ctx, currentAlts, rosterOf(ctx, roster, removedMemberId));
    }

    private List<Claim> rosterOf(RepoContext ctx, VaultManifest roster, String excludedMemberId)
            throws CryptoException, VaultException {
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
     * takes a {@link MemberEntry}, which cannot exist without a wrapped key, so a candidate is built
     * first and discarded unless verification passes; nothing leaves this method otherwise.
     */
    private MemberEntry verifiedEntry(String repoId, MemberPublicKey claimed, String keyBindingSig, RepoDataKey dataKey)
            throws CryptoException, VaultException {
        MemberEntry candidate = unverifiedEntry(claimed, dataKey).withKeyBindingSig(keyBindingSig);
        MemberPublicKey verified = keyBindingVerifier.verify(repoId, candidate);
        if (verified == null) {
            throw new VaultException("key-binding verifier returned no keys for member " + claimed.ed25519PublicKey());
        }
        return verified.equals(claimed) ? candidate : unverifiedEntry(verified, dataKey);
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
     * modified build cannot push tokens into a repository whose policy forbids them.
     */
    private static List<AltAccount> applyPolicy(List<AltAccount> alts, boolean shareRefreshTokens) {
        List<AltAccount> copy = new ArrayList<>(alts.size());
        for (AltAccount alt : alts) {
            copy.add(shareRefreshTokens ? alt : alt.withTokens(alt.accessToken(), null, 0L));
        }
        return copy;
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

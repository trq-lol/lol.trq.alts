package lol.trq.alts.internal.avp;

import com.google.gson.JsonObject;
import java.util.Arrays;
import java.util.regex.Pattern;
import lol.trq.alts.internal.avp.AvpCrypto.WrapLabel;

/**
 * The out-of-band tokens and addressing of AVP SPEC 11: the repo locator and {@code avp://} URI, the
 * invite token with its host acceptance, the device link request and grant with the confirmation code,
 * the leave request, and the key fingerprints.
 *
 * <p>A token is base64url-nopad over compact JSON with its fields in the SPEC order and {@code "v": 2}
 * (SPEC 11.1). {@link #encode(JsonObject)} writes the object a {@code toJson} method builds, in that
 * order; {@link #decode(String)} accepts any field order and whitespace, and the typed decoders refuse a
 * {@code v} other than the integer 2 and a binary field of the wrong length. Every decoding failure is an
 * {@link lol.trq.alts.AltsException} of kind {@code PROTOCOL}.
 *
 * <p>Ported from the Alt Vault Protocol reference implementation (MIT).
 *
 * @author trq
 * @since 1.0.0
 */
public final class Tokens {

    private static final Pattern REPO_ID = Pattern.compile("[A-Za-z0-9_-]{22}");

    private Tokens() {}

    /**
     * A host's signed agreement to carry a repository for one joining member (SPEC 8.2, 11.3).
     *
     * @param repoId the repository
     * @param memberKey the joining member's 32-byte Ed25519 key
     * @param hostKey the accepting host's 32-byte key
     * @param expiresAt epoch milliseconds after which it is void
     * @param signature the host's 64-byte signature over {@link #acceptanceMessage(Acceptance)}
     */
    public record Acceptance(String repoId, byte[] memberKey, byte[] hostKey, long expiresAt, byte[] signature) {
        /** Copies the arrays. */
        public Acceptance {
            memberKey = memberKey.clone();
            hostKey = hostKey.clone();
            signature = signature.clone();
        }
    }

    /**
     * {@code InviteToken}, sent by a joiner to the owner (SPEC 11.3).
     *
     * @param ed25519PublicKey the joiner's 32-byte Ed25519 key
     * @param x25519PublicKey the joiner's 32-byte X25519 key, the only key the owner wraps to
     * @param homeHostKey the joiner's 32-byte home host key
     * @param homeHostLocator the joiner's home host locator
     * @param acceptance the home host's acceptance
     */
    public record InviteToken(
            byte[] ed25519PublicKey,
            byte[] x25519PublicKey,
            byte[] homeHostKey,
            String homeHostLocator,
            Acceptance acceptance) {
        /** Copies the keys. */
        public InviteToken {
            ed25519PublicKey = ed25519PublicKey.clone();
            x25519PublicKey = x25519PublicKey.clone();
            homeHostKey = homeHostKey.clone();
        }
    }

    /**
     * {@code RepoLocator}, sent by the owner to a joiner (SPEC 11.2).
     *
     * @param repoId the repository
     * @param hostKey the owner's 32-byte home host key
     * @param hostLocator the owner's home host locator
     * @param ownerFingerprint {@link #ownerFingerprint(byte[])} of the owner key
     */
    public record RepoLocator(String repoId, byte[] hostKey, String hostLocator, String ownerFingerprint) {
        /** Copies the key. */
        public RepoLocator {
            hostKey = hostKey.clone();
        }
    }

    /**
     * {@code LinkRequest}, shown by a new owner device (SPEC 11.6).
     *
     * @param ephemeralPublicKey the new device's 32-byte ephemeral X25519 public key
     */
    public record LinkRequest(byte[] ephemeralPublicKey) {
        /** Copies the key. */
        public LinkRequest {
            ephemeralPublicKey = ephemeralPublicKey.clone();
        }
    }

    /**
     * {@code LinkGrant}, returned by an existing owner device (SPEC 11.6).
     *
     * @param wrap the 32-byte mnemonic entropy wrapped under {@code avp/owner-link/v1}
     */
    public record LinkGrant(WrappedKey wrap) {}

    /**
     * A member's signed request to leave a repository (SPEC 8.4, 11.4), sent as a JSON body.
     *
     * @param repoId the repository
     * @param memberKey the leaving member's 32-byte Ed25519 key
     * @param at the leaving client's time in epoch milliseconds
     * @param signature the member's 64-byte signature over {@link #leaveMessage(LeaveRequest)}
     */
    public record LeaveRequest(String repoId, byte[] memberKey, long at, byte[] signature) {
        /** Copies the arrays. */
        public LeaveRequest {
            memberKey = memberKey.clone();
            signature = signature.clone();
        }
    }

    /**
     * An {@code avp://<hostLocator>/<repoId>} locator (SPEC 11.2): where a repository can be reached. The
     * repository's identity is the id alone.
     *
     * @param hostLocator {@code host} or {@code host:port}
     * @param repoId the 22-character repository id
     */
    public record AvpUri(String hostLocator, String repoId) {
        /**
         * The URI text.
         *
         * @return {@code avp://<hostLocator>/<repoId>}
         */
        @Override
        public String toString() {
            return "avp://" + hostLocator + "/" + repoId;
        }
    }

    // --- Token encoding (SPEC 11.1) ----------------------------------------------------------------

    /**
     * Encodes a token: base64url-nopad over the compact JSON of {@code json}, in its member order.
     *
     * @param json the token object, as a {@code toJson} method builds it
     * @return the token text
     */
    public static String encode(JsonObject json) {
        return AvpBytes.base64Url(AvpJson.write(json));
    }

    /**
     * Decodes a token's outer encoding.
     *
     * @param token the token text
     * @return the JSON object, for a typed decoder
     * @throws lol.trq.alts.AltsException of kind {@code PROTOCOL} if the text is not canonical
     *     base64url-nopad over a strict JSON object
     */
    public static JsonObject decode(String token) {
        return AvpJson.object(AvpJson.parse(AvpBytes.fromBase64Url(token, "the token")), "a token");
    }

    private static void requireV2(JsonObject o) {
        if (AvpJson.int64(o, "v") != 2) {
            throw AvpFailures.protocol("the token is not version 2");
        }
    }

    private static JsonObject v2() {
        JsonObject o = new JsonObject();
        o.addProperty("v", 2);
        return o;
    }

    // --- Acceptance and invite (SPEC 8.2, 11.3) ----------------------------------------------------

    /**
     * {@code CE(tag "avp/accept/v1", str(repoId), bytes(memberKey), bytes(hostKey), i64(expiresAt))}.
     *
     * @param a the acceptance
     * @return the signed message
     */
    public static byte[] acceptanceMessage(Acceptance a) {
        return Ce.tag(Ce.ACCEPT)
                .str(a.repoId())
                .bytes(a.memberKey())
                .bytes(a.hostKey())
                .i64(a.expiresAt())
                .finish();
    }

    /**
     * Signs an acceptance with a host key, as a host does; the acceptance names that key.
     *
     * @param repoId the repository
     * @param memberKey the joining member's key
     * @param expiresAt when it expires
     * @param hostSeed the host's 32-byte Ed25519 seed
     * @return the acceptance
     */
    public static Acceptance signAcceptance(String repoId, byte[] memberKey, long expiresAt, byte[] hostSeed) {
        byte[] hostKey = Ed25519Strict.publicKey(hostSeed);
        Acceptance unsigned = new Acceptance(repoId, memberKey, hostKey, expiresAt, new byte[64]);
        return new Acceptance(
                repoId, memberKey, hostKey, expiresAt, Ed25519Strict.sign(hostSeed, acceptanceMessage(unsigned)));
    }

    /**
     * Verifies an acceptance's signature, strictly, under a given host key.
     *
     * @param a the acceptance
     * @param hostKey the key to verify under
     * @return whether it verifies; never throws
     */
    public static boolean verifyAcceptance(Acceptance a, byte[] hostKey) {
        return Ed25519Strict.verify(hostKey, acceptanceMessage(a), a.signature());
    }

    /**
     * The owner's check of an invite token before it adds the member or the host (SPEC 8.2): the
     * acceptance verifies under its {@code hostKey}, names this repository, names the token's Ed25519 key
     * and its home host key, and has not expired.
     *
     * @param t the invite token
     * @param repoId the repository the owner is adding the member to
     * @param nowMillis the owner client's current time
     * @return whether every condition holds; never throws
     */
    public static boolean verifyInvite(InviteToken t, String repoId, long nowMillis) {
        Acceptance a = t.acceptance();
        return verifyAcceptance(a, a.hostKey())
                && a.repoId().equals(repoId)
                && Arrays.equals(a.memberKey(), t.ed25519PublicKey())
                && Arrays.equals(a.hostKey(), t.homeHostKey())
                && a.expiresAt() > nowMillis;
    }

    /**
     * Decodes an acceptance from its JSON form.
     *
     * @param json the object
     * @return the acceptance
     */
    public static Acceptance acceptanceFromJson(JsonObject json) {
        return new Acceptance(
                AvpJson.string(json, "repoId"),
                AvpJson.bytes(json, "memberKey", 32),
                AvpJson.bytes(json, "hostKey", 32),
                AvpJson.int64(json, "expiresAt"),
                AvpJson.bytes(json, "signature", 64));
    }

    /**
     * The JSON form of an acceptance, in the SPEC order.
     *
     * @param a the acceptance
     * @return the object
     */
    public static JsonObject toJson(Acceptance a) {
        JsonObject o = new JsonObject();
        o.addProperty("repoId", a.repoId());
        o.addProperty("memberKey", AvpBytes.base64(a.memberKey()));
        o.addProperty("hostKey", AvpBytes.base64(a.hostKey()));
        o.addProperty("expiresAt", a.expiresAt());
        o.addProperty("signature", AvpBytes.base64(a.signature()));
        return o;
    }

    /**
     * Decodes an invite token from its JSON form.
     *
     * @param json the object, from {@link #decode(String)}
     * @return the token
     */
    public static InviteToken inviteFromJson(JsonObject json) {
        requireV2(json);
        return new InviteToken(
                AvpJson.bytes(json, "ed25519PublicKey", 32),
                AvpJson.bytes(json, "x25519PublicKey", 32),
                AvpJson.bytes(json, "homeHostKey", 32),
                AvpJson.string(json, "homeHostLocator"),
                acceptanceFromJson(AvpJson.object(AvpJson.required(json, "acceptance"), "the acceptance")));
    }

    /**
     * The JSON form of an invite token, in the SPEC order.
     *
     * @param t the token
     * @return the object, for {@link #encode(JsonObject)}
     */
    public static JsonObject toJson(InviteToken t) {
        JsonObject o = v2();
        o.addProperty("ed25519PublicKey", AvpBytes.base64(t.ed25519PublicKey()));
        o.addProperty("x25519PublicKey", AvpBytes.base64(t.x25519PublicKey()));
        o.addProperty("homeHostKey", AvpBytes.base64(t.homeHostKey()));
        o.addProperty("homeHostLocator", t.homeHostLocator());
        o.add("acceptance", toJson(t.acceptance()));
        return o;
    }

    // --- Repo locator (SPEC 11.2) ------------------------------------------------------------------

    /**
     * Decodes a repo locator from its JSON form.
     *
     * @param json the object
     * @return the locator
     */
    public static RepoLocator locatorFromJson(JsonObject json) {
        requireV2(json);
        return new RepoLocator(
                AvpJson.string(json, "repoId"),
                AvpJson.bytes(json, "hostKey", 32),
                AvpJson.string(json, "hostLocator"),
                AvpJson.string(json, "ownerFingerprint"));
    }

    /**
     * The JSON form of a repo locator, in the SPEC order.
     *
     * @param r the locator
     * @return the object, for {@link #encode(JsonObject)}
     */
    public static JsonObject toJson(RepoLocator r) {
        JsonObject o = v2();
        o.addProperty("repoId", r.repoId());
        o.addProperty("hostKey", AvpBytes.base64(r.hostKey()));
        o.addProperty("hostLocator", r.hostLocator());
        o.addProperty("ownerFingerprint", r.ownerFingerprint());
        return o;
    }

    // --- Device linking (SPEC 11.6) ----------------------------------------------------------------

    /**
     * Decodes a link request from its JSON form.
     *
     * @param json the object
     * @return the request
     */
    public static LinkRequest linkRequestFromJson(JsonObject json) {
        requireV2(json);
        return new LinkRequest(AvpJson.bytes(json, "ephemeralPublicKey", 32));
    }

    /**
     * The JSON form of a link request.
     *
     * @param r the request
     * @return the object, for {@link #encode(JsonObject)}
     */
    public static JsonObject toJson(LinkRequest r) {
        JsonObject o = v2();
        o.addProperty("ephemeralPublicKey", AvpBytes.base64(r.ephemeralPublicKey()));
        return o;
    }

    /**
     * Decodes a link grant from its JSON form.
     *
     * @param json the object
     * @return the grant
     */
    public static LinkGrant linkGrantFromJson(JsonObject json) {
        requireV2(json);
        return new LinkGrant(Manifest.wrappedKeyFromJson(AvpJson.required(json, "wrap")));
    }

    /**
     * The JSON form of a link grant.
     *
     * @param g the grant
     * @return the object, for {@link #encode(JsonObject)}
     */
    public static JsonObject toJson(LinkGrant g) {
        JsonObject o = v2();
        o.add("wrap", Manifest.toJson(g.wrap()));
        return o;
    }

    /**
     * The confirmation code of a link request (SPEC 11.6): the first 4 bytes of {@code SHA-256(CE(tag
     * "avp/link-code/v1", bytes(ephemeralPublicKey)))} as {@code u32BE}, modulo 1 000 000, as 6 digits.
     *
     * @param ephemeralPublicKey the new device's ephemeral X25519 public key
     * @return the 6-digit code, leading zeros kept
     */
    public static String linkConfirmationCode(byte[] ephemeralPublicKey) {
        byte[] d =
                AvpCrypto.sha256(Ce.tag(Ce.LINK_CODE).bytes(ephemeralPublicKey).finish());
        long u32 = ((d[0] & 0xffL) << 24) | ((d[1] & 0xffL) << 16) | ((d[2] & 0xffL) << 8) | (d[3] & 0xffL);
        return String.format("%06d", u32 % 1_000_000L);
    }

    /**
     * Wraps the owner's 32-byte mnemonic entropy to a link request's key under {@code avp/owner-link/v1},
     * with a fresh ephemeral key and IV.
     *
     * @param entropy the owner's mnemonic entropy
     * @param ephemeralPublicKey the link request's key
     * @return the grant
     * @throws lol.trq.alts.AltsException of kind {@code INVALID_INPUT} if the entropy is not 32 bytes
     */
    public static LinkGrant sealLinkGrant(byte[] entropy, byte[] ephemeralPublicKey) {
        if (entropy.length != 32) {
            throw AvpFailures.invalidInput("owner entropy is 32 bytes");
        }
        return new LinkGrant(AvpCrypto.wrap(ephemeralPublicKey, entropy, WrapLabel.OWNER_LINK));
    }

    /**
     * Opens a link grant with the new device's ephemeral private key under {@code avp/owner-link/v1}; a
     * grant that does not open under that label is refused (SPEC 11.6).
     *
     * @param grant the grant
     * @param ephemeralPrivate the new device's 32-byte ephemeral scalar
     * @return the 32-byte mnemonic entropy, which the caller zeroes
     * @throws lol.trq.alts.AltsException of kind {@code CRYPTO} if it does not open, and of kind {@code
     *     PROTOCOL} if the secret is not 32 bytes
     */
    public static byte[] openLinkGrant(LinkGrant grant, byte[] ephemeralPrivate) {
        byte[] secret = AvpCrypto.unwrap(ephemeralPrivate, grant.wrap(), WrapLabel.OWNER_LINK);
        if (secret.length != 32) {
            Arrays.fill(secret, (byte) 0);
            throw AvpFailures.protocol("a link grant does not hold 32 bytes of entropy");
        }
        return secret;
    }

    // --- Leave request (SPEC 8.4, 11.4) ------------------------------------------------------------

    /**
     * {@code CE(tag "avp/leave/v1", str(repoId), bytes(memberKey), i64(at))}.
     *
     * @param l the leave request
     * @return the signed message
     */
    public static byte[] leaveMessage(LeaveRequest l) {
        return Ce.tag(Ce.LEAVE).str(l.repoId()).bytes(l.memberKey()).i64(l.at()).finish();
    }

    /**
     * Signs a leave request with a member key; the request names that key.
     *
     * @param repoId the repository
     * @param at the client's time in epoch milliseconds
     * @param memberSeed the member's 32-byte Ed25519 seed
     * @return the leave request
     */
    public static LeaveRequest signLeave(String repoId, long at, byte[] memberSeed) {
        byte[] memberKey = Ed25519Strict.publicKey(memberSeed);
        LeaveRequest unsigned = new LeaveRequest(repoId, memberKey, at, new byte[64]);
        return new LeaveRequest(repoId, memberKey, at, Ed25519Strict.sign(memberSeed, leaveMessage(unsigned)));
    }

    /**
     * Verifies a leave request's signature, strictly, under its own {@code memberKey}.
     *
     * @param l the leave request
     * @return whether it verifies; never throws
     */
    public static boolean verifyLeave(LeaveRequest l) {
        return Ed25519Strict.verify(l.memberKey(), leaveMessage(l), l.signature());
    }

    /**
     * Decodes a leave request from its JSON body.
     *
     * @param json the object
     * @return the leave request
     */
    public static LeaveRequest leaveFromJson(JsonObject json) {
        return new LeaveRequest(
                AvpJson.string(json, "repoId"),
                AvpJson.bytes(json, "memberKey", 32),
                AvpJson.int64(json, "at"),
                AvpJson.bytes(json, "signature", 64));
    }

    /**
     * The JSON body of a leave request, in the SPEC order.
     *
     * @param l the leave request
     * @return the object
     */
    public static JsonObject toJson(LeaveRequest l) {
        JsonObject o = new JsonObject();
        o.addProperty("repoId", l.repoId());
        o.addProperty("memberKey", AvpBytes.base64(l.memberKey()));
        o.addProperty("at", l.at());
        o.addProperty("signature", AvpBytes.base64(l.signature()));
        return o;
    }

    // --- Fingerprints and locators (SPEC 3.2, 11.2) ------------------------------------------------

    /**
     * The member key fingerprint (SPEC 3.2): {@code hex(SHA-256(ed25519 || x25519)[0..8])} as {@code
     * xxxx-xxxx-xxxx-xxxx}.
     *
     * @param ed25519Public the member's raw Ed25519 key
     * @param x25519Public the member's raw X25519 key
     * @return the fingerprint
     */
    public static String memberFingerprint(byte[] ed25519Public, byte[] x25519Public) {
        String h = AvpBytes.hex(Arrays.copyOf(AvpCrypto.sha256(AvpBytes.concat(ed25519Public, x25519Public)), 8));
        return h.substring(0, 4) + "-" + h.substring(4, 8) + "-" + h.substring(8, 12) + "-" + h.substring(12, 16);
    }

    /**
     * The owner fingerprint of a repo locator (SPEC 11.2): {@code hex(SHA-256(ownerKey)[0..8])}.
     *
     * @param ownerKey the owner's raw Ed25519 key
     * @return 16 hex digits
     */
    public static String ownerFingerprint(byte[] ownerKey) {
        return AvpBytes.hex(Arrays.copyOf(AvpCrypto.sha256(ownerKey), 8));
    }

    /**
     * Parses {@code avp://<hostLocator>/<repoId>}.
     *
     * @param uri the text
     * @return the locator
     * @throws lol.trq.alts.AltsException of kind {@code PROTOCOL} if the scheme is not {@code avp://},
     *     the host locator is empty, or the id is not 22 base64url characters
     */
    public static AvpUri parseUri(String uri) {
        if (!uri.startsWith("avp://")) {
            throw AvpFailures.protocol("not an avp:// locator");
        }
        String rest = uri.substring("avp://".length());
        int slash = rest.indexOf('/');
        if (slash <= 0) {
            throw AvpFailures.protocol("not an avp:// locator");
        }
        String repoId = rest.substring(slash + 1);
        if (!REPO_ID.matcher(repoId).matches()) {
            throw AvpFailures.protocol("not an avp:// locator");
        }
        return new AvpUri(rest.substring(0, slash), repoId);
    }
}

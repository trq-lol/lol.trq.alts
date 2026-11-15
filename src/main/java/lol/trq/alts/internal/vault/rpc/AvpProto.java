package lol.trq.alts.internal.vault.rpc;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * The message table of AVP's {@code proto/avp.proto}: for each message, its fields by number, with the
 * camelCase JSON name the HTTP/JSON profile uses, the kind, and whether it is repeated. The codec is driven
 * by this table alone, so a field AVP adds is one line here, and {@code grpc.json} pins the result.
 *
 * @author trq
 * @since 1.1.0
 */
final class AvpProto {

    /** What a field holds. */
    enum Kind {
        STRING,
        INT64,
        BOOL,
        MESSAGE
    }

    /**
     * One field of a message.
     *
     * @param number the field number
     * @param json the JSON member name
     * @param kind what it holds
     * @param message the full name of the message it holds, for {@link Kind#MESSAGE}; else null
     * @param repeated whether it is repeated
     */
    record Field(int number, String json, Kind kind, String message, boolean repeated) {}

    /**
     * One message: its fields in ascending number, by number and by JSON name.
     *
     * @param name the full name, {@code avp.PushRequest}
     * @param fields the fields in ascending number
     */
    record Message(String name, List<Field> fields) {

        Field byNumber(int number) {
            for (Field f : fields) {
                if (f.number() == number) {
                    return f;
                }
            }
            return null;
        }

        Field byJson(String json) {
            for (Field f : fields) {
                if (f.json().equals(json)) {
                    return f;
                }
            }
            return null;
        }
    }

    private static final Map<String, Message> MESSAGES = new HashMap<>();

    static {
        msg("WrappedKey", s(1, "schemeId"), s(2, "ephemeralPublicKey"), s(3, "iv"), s(4, "ciphertext"));
        msg("HostRef", s(1, "hostKey"), s(2, "locator"));
        msg(
                "MemberEntry",
                s(1, "ed25519PublicKey"),
                s(2, "x25519PublicKey"),
                m(3, "wrappedDataKey", "WrappedKey"),
                i(4, "keyEpoch"),
                s(6, "homeHostKey"));
        msg("Removal", s(1, "memberKey"), i(2, "removedAtSeq"), rs(3, "frontier"));
        msg(
                "ManifestState",
                s(1, "repoId"),
                i(2, "manifestSeq"),
                s(3, "prevManifestHash"),
                s(4, "ownerKey"),
                s(5, "genesisNonce"),
                s(6, "schemeId"),
                i(7, "keyEpoch"),
                b(8, "shareRefreshTokens"),
                rm(9, "hosts", "HostRef"),
                rm(10, "members", "MemberEntry"),
                rm(11, "removals", "Removal"));
        msg("SignedManifest", m(1, "state", "ManifestState"), s(2, "ownerSignature"));
        msg(
                "Commit",
                s(1, "repoId"),
                s(2, "commitId"),
                rs(3, "parents"),
                i(4, "manifestSeq"),
                s(5, "manifestHash"),
                i(6, "keyEpoch"),
                s(7, "author"),
                s(8, "iv"),
                s(9, "ciphertext"),
                s(10, "authorSignature"));
        msg("LeaveRequest", s(1, "repoId"), s(2, "memberKey"), i(3, "at"), s(4, "signature"));
        msg("LeaveResponse");
        msg("Acceptance", s(1, "repoId"), s(2, "memberKey"), s(3, "hostKey"), i(4, "expiresAt"), s(5, "signature"));
        msg("CreateRepoRequest", m(1, "manifest", "SignedManifest"), m(2, "commit", "Commit"));
        msg("PullRequest", i(1, "sinceManifestSeq"), rs(2, "knownHeads"), s(3, "repoId"));
        msg(
                "PullResponse",
                rm(1, "manifests", "SignedManifest"),
                rm(2, "heads", "Commit"),
                rm(3, "leaves", "LeaveRequest"));
        msg("PushRequest", m(1, "commit", "Commit"));
        msg("PushResponse", b(1, "accepted"), rs(2, "heads"));
        msg("PublishManifestRequest", m(1, "manifest", "SignedManifest"), m(2, "commit", "Commit"));
        msg("PrepareJoinRequest", s(1, "repoId"), s(2, "memberKey"));
        msg("ManifestTip", i(1, "manifestSeq"), s(2, "manifestHash"));
        msg("HeadsRequest", s(1, "repoId"));
        msg("HeadsResponse", m(1, "manifestTip", "ManifestTip"), rs(2, "heads"));
        msg("FetchRequest", s(1, "repoId"), rs(2, "ids"));
        msg(
                "FetchResponse",
                rm(1, "manifests", "SignedManifest"),
                rm(2, "commits", "Commit"),
                rm(3, "leaves", "LeaveRequest"));
        msg(
                "OfferRequest",
                s(1, "repoId"),
                rm(2, "manifests", "SignedManifest"),
                rm(3, "commits", "Commit"),
                rm(4, "leaves", "LeaveRequest"));
        msg("RejectedItem", s(1, "id"), s(2, "code"));
        msg("OfferResponse", rs(1, "accepted"), rm(2, "rejected", "RejectedItem"));
        msg("HostInfoRequest");
        msg("HostInfo", s(1, "version"), rs(2, "profiles"), s(3, "hostKey"));
        msg("ChallengeRequest", s(1, "ed25519PublicKey"));
        msg("AuthChallenge", s(1, "nonce"));
        msg("TokenRequest", s(1, "ed25519PublicKey"), s(2, "nonce"), s(3, "signature"));
        msg("AuthToken", s(1, "token"), i(2, "expiresAt"));
    }

    private AvpProto() {}

    /**
     * A message by its full name.
     *
     * @param name the full name, {@code avp.PushRequest}
     * @return the message
     * @throws IllegalArgumentException if AVP has no such message
     */
    static Message message(String name) {
        Message m = MESSAGES.get(name);
        if (m == null) {
            throw new IllegalArgumentException("not an AVP message");
        }
        return m;
    }

    private static void msg(String name, Field... fields) {
        MESSAGES.put("avp." + name, new Message("avp." + name, List.of(fields)));
    }

    private static Field s(int n, String json) {
        return new Field(n, json, Kind.STRING, null, false);
    }

    private static Field rs(int n, String json) {
        return new Field(n, json, Kind.STRING, null, true);
    }

    private static Field i(int n, String json) {
        return new Field(n, json, Kind.INT64, null, false);
    }

    private static Field b(int n, String json) {
        return new Field(n, json, Kind.BOOL, null, false);
    }

    private static Field m(int n, String json, String message) {
        return new Field(n, json, Kind.MESSAGE, "avp." + message, false);
    }

    private static Field rm(int n, String json, String message) {
        return new Field(n, json, Kind.MESSAGE, "avp." + message, true);
    }
}

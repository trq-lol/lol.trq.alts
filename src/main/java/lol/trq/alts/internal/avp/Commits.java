package lol.trq.alts.internal.avp;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Commits of the member-signed commit graph (AVP SPEC 4.3): the header {@code H}, the commit id, the
 * author signature, AAD v2, and the payload AEAD.
 *
 * <p>As with {@link Manifest}, the records copy what they are given and compare arrays by identity;
 * compare commits by id.
 *
 * <p>Ported from the Alt Vault Protocol reference implementation (MIT).
 *
 * @author trq
 * @since 1.0.0
 */
public final class Commits {

    private Commits() {}

    /**
     * The fields an author chooses before sealing a commit.
     *
     * @param repoId the repository
     * @param parents the parent ids: none for the first commit, two or more for a merge
     * @param manifestSeq the manifest state the author writes under
     * @param manifestHash the {@code manifestHash} of that state
     * @param keyEpoch the epoch of the data key that encrypts the payload
     */
    public record Header(String repoId, List<byte[]> parents, long manifestSeq, byte[] manifestHash, long keyEpoch) {
        /** Copies the ids. */
        public Header {
            parents = Manifest.copyIds(parents);
            manifestHash = manifestHash.clone();
        }
    }

    /**
     * A commit, field names as on the wire.
     *
     * @param repoId the repository
     * @param commitId the 32-byte id, {@code SHA-256(H)}
     * @param parents the 32-byte parent ids
     * @param manifestSeq the manifest state the author wrote under
     * @param manifestHash the 32-byte {@code manifestHash} of that state
     * @param keyEpoch the epoch of the data key that encrypts the payload
     * @param author the author's 32-byte member Ed25519 key
     * @param iv the 12-byte payload IV
     * @param ciphertext the payload ciphertext with its 16-byte tag
     * @param authorSignature the 64-byte author signature over {@code CE(tag "avp/commit-sig/v1",
     *     bytes(commitId))}
     */
    public record Commit(
            String repoId,
            byte[] commitId,
            List<byte[]> parents,
            long manifestSeq,
            byte[] manifestHash,
            long keyEpoch,
            byte[] author,
            byte[] iv,
            byte[] ciphertext,
            byte[] authorSignature) {
        /** Copies the arrays and ids. */
        public Commit {
            commitId = commitId.clone();
            parents = Manifest.copyIds(parents);
            manifestHash = manifestHash.clone();
            author = author.clone();
            iv = iv.clone();
            ciphertext = ciphertext.clone();
            authorSignature = authorSignature.clone();
        }

        /**
         * Names the commit by its id only.
         *
         * @return a short description
         */
        @Override
        public String toString() {
            return "Commit[" + AvpBytes.base64(commitId) + ", seq " + manifestSeq + ", epoch " + keyEpoch + "]";
        }
    }

    private static void writeParents(Ce w, List<byte[]> parents) {
        List<byte[]> sorted = AvpBytes.sortedUnique(parents, "parent id");
        w.count(sorted.size());
        for (byte[] p : sorted) {
            w.bytes(p);
        }
    }

    /**
     * The payload AAD v2 (SPEC 4.3), parents sorted.
     *
     * @param repoId the repository
     * @param keyEpoch the epoch
     * @param author the author's Ed25519 key
     * @param parents the parent ids
     * @return the AAD bytes
     * @throws lol.trq.alts.AltsException of kind {@code PROTOCOL} if a parent repeats
     */
    public static byte[] aadV2(String repoId, long keyEpoch, byte[] author, List<byte[]> parents) {
        Ce w = Ce.tag(Ce.AAD).str(repoId).i64(keyEpoch).bytes(author);
        writeParents(w, parents);
        return w.finish();
    }

    /**
     * The message an author signs: {@code CE(tag "avp/commit-sig/v1", bytes(commitId))}.
     *
     * @param commitId the commit id
     * @return the message
     */
    public static byte[] sigMessage(byte[] commitId) {
        return Ce.tag(Ce.COMMIT_SIG).bytes(commitId).finish();
    }

    /**
     * The header bytes {@code H} (SPEC 4.3), parents sorted.
     *
     * @param c the commit
     * @return {@code H}
     * @throws lol.trq.alts.AltsException of kind {@code PROTOCOL} if a parent repeats
     */
    public static byte[] headerBytes(Commit c) {
        Ce w = Ce.tag(Ce.COMMIT).str(c.repoId());
        writeParents(w, c.parents());
        return w.i64(c.manifestSeq())
                .bytes(c.manifestHash())
                .i64(c.keyEpoch())
                .bytes(c.author())
                .bytes(c.iv())
                .bytes(c.ciphertext())
                .finish();
    }

    /**
     * The id recomputed from the header, {@code SHA-256(H)}; {@link #verify(Commit)} compares it with
     * the {@code commitId} field.
     *
     * @param c the commit
     * @return the 32-byte id
     */
    public static byte[] id(Commit c) {
        return AvpCrypto.sha256(headerBytes(c));
    }

    /**
     * The binary fields have their lengths, the counters are in range, the ciphertext holds at least its
     * tag, and no parent repeats (SPEC 7.1).
     *
     * @param c the commit
     * @return whether the shape is right
     */
    public static boolean shapeOk(Commit c) {
        if (c.commitId().length != 32
                || c.manifestHash().length != 32
                || c.author().length != 32
                || c.iv().length != 12
                || c.authorSignature().length != 64
                || c.ciphertext().length < 16
                || c.manifestSeq() < 1
                || c.keyEpoch() < 0) {
            return false;
        }
        Set<String> seen = new HashSet<>();
        for (byte[] p : c.parents()) {
            if (p.length != 32 || !seen.add(AvpBytes.base64(p))) {
                return false;
            }
        }
        return true;
    }

    /**
     * SPEC 7.1 and 7.5 rule 1: the shape is right, the id recomputes from the header, and the author
     * signature verifies strictly under {@code author} over the commit-sig message.
     *
     * @param c the commit
     * @return whether all hold; never throws
     */
    public static boolean verify(Commit c) {
        if (!shapeOk(c)) {
            return false;
        }
        return AvpBytes.same(id(c), c.commitId())
                && Ed25519Strict.verify(c.author(), sigMessage(c.commitId()), c.authorSignature());
    }

    /**
     * Encrypts a payload under a data key with a fresh random IV and AAD v2, computes the id, and signs
     * it with the author key.
     *
     * @param dataKey the 32-byte data key of {@code header.keyEpoch()}
     * @param header the header fields
     * @param plaintext the payload JSON bytes
     * @param authorSeed the author's 32-byte Ed25519 seed
     * @return the commit
     */
    public static Commit seal(byte[] dataKey, Header header, byte[] plaintext, byte[] authorSeed) {
        return sealWithIv(dataKey, header, plaintext, authorSeed, AvpCrypto.randomBytes(12));
    }

    /**
     * {@link #seal} with a caller-chosen IV, to reproduce the vectors. A real commit uses {@link #seal}.
     *
     * @param dataKey the data key
     * @param header the header fields
     * @param plaintext the payload JSON bytes
     * @param authorSeed the author's seed
     * @param iv the 12-byte IV
     * @return the commit
     */
    static Commit sealWithIv(byte[] dataKey, Header header, byte[] plaintext, byte[] authorSeed, byte[] iv) {
        byte[] author = Ed25519Strict.publicKey(authorSeed);
        byte[] aad = aadV2(header.repoId(), header.keyEpoch(), author, header.parents());
        byte[] ciphertext = AvpCrypto.aesGcmSeal(dataKey, iv, plaintext, aad);
        Commit unsigned = new Commit(
                header.repoId(),
                new byte[32],
                header.parents(),
                header.manifestSeq(),
                header.manifestHash(),
                header.keyEpoch(),
                author,
                iv,
                ciphertext,
                new byte[64]);
        byte[] commitId = id(unsigned);
        return new Commit(
                header.repoId(),
                commitId,
                header.parents(),
                header.manifestSeq(),
                header.manifestHash(),
                header.keyEpoch(),
                author,
                iv,
                ciphertext,
                Ed25519Strict.sign(authorSeed, sigMessage(commitId)));
    }

    /**
     * Decrypts the payload with the AAD v2 built from the commit's own header fields.
     *
     * @param c the commit
     * @param dataKey the 32-byte data key of {@code c.keyEpoch()}
     * @return the payload plaintext, which the caller zeroes once parsed
     * @throws lol.trq.alts.AltsException of kind {@code CRYPTO} if it does not authenticate: a wrong key,
     *     or a repository, epoch, author or parent set other than the one sealed
     */
    public static byte[] open(Commit c, byte[] dataKey) {
        return AvpCrypto.aesGcmOpen(
                dataKey, c.iv(), c.ciphertext(), aadV2(c.repoId(), c.keyEpoch(), c.author(), c.parents()));
    }

    /**
     * Decodes a commit from its HTTP/JSON form. Unknown fields are ignored.
     *
     * @param json the value
     * @return the commit
     * @throws lol.trq.alts.AltsException of kind {@code PROTOCOL} if a field is missing or has the wrong
     *     type, or a fixed binary field has the wrong length
     */
    public static Commit fromJson(JsonElement json) {
        JsonObject o = AvpJson.object(json, "a commit");
        return new Commit(
                AvpJson.string(o, "repoId"),
                AvpJson.bytes(o, "commitId", 32),
                Manifest.ids(o, "parents"),
                AvpJson.int64(o, "manifestSeq"),
                AvpJson.bytes(o, "manifestHash", 32),
                AvpJson.int64(o, "keyEpoch"),
                AvpJson.bytes(o, "author", 32),
                AvpJson.bytes(o, "iv", 12),
                AvpJson.bytes(o, "ciphertext"),
                AvpJson.bytes(o, "authorSignature", 64));
    }

    /**
     * The HTTP/JSON form of a commit, fields in the proto order.
     *
     * @param c the commit
     * @return the object
     */
    public static JsonObject toJson(Commit c) {
        JsonObject o = new JsonObject();
        o.addProperty("repoId", c.repoId());
        o.addProperty("commitId", AvpBytes.base64(c.commitId()));
        o.add("parents", Manifest.idsJson(c.parents()));
        o.addProperty("manifestSeq", c.manifestSeq());
        o.addProperty("manifestHash", AvpBytes.base64(c.manifestHash()));
        o.addProperty("keyEpoch", c.keyEpoch());
        o.addProperty("author", AvpBytes.base64(c.author()));
        o.addProperty("iv", AvpBytes.base64(c.iv()));
        o.addProperty("ciphertext", AvpBytes.base64(c.ciphertext()));
        o.addProperty("authorSignature", AvpBytes.base64(c.authorSignature()));
        return o;
    }
}

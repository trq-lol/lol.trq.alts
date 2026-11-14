package lol.trq.alts.internal.vault.legacy;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.internal.avp.AvpCrypto;
import lol.trq.alts.internal.avp.AvpCrypto.WrapLabel;
import lol.trq.alts.internal.avp.AvpFailures;
import lol.trq.alts.internal.avp.AvpJson;
import lol.trq.alts.internal.avp.WrappedKey;
import lol.trq.alts.model.AltAccount;

/**
 * Reads one AVP 0.4 repository, once, for the read-only importer: the manifest and the envelope as a 0.4
 * host served them, and the reading member's id and X25519 key, in; the accounts out. It writes nothing
 * and talks to no host.
 *
 * <p>The checks are the ones the 0.12 {@code SharedVault.openRepo} and {@code decryptPayload} made, so an
 * import accepts what a 0.12 member could read, and nothing more:
 *
 * <ul>
 *   <li>the manifest names the wrap scheme {@value #SCHEME_ID};
 *   <li>the member is listed (by its base64 Ed25519 key, the first entry that names it), and its entry is
 *       from the manifest's key epoch;
 *   <li>the data key unwraps from that entry under the {@code avp/rdk-wrap/v1} label;
 *   <li>the envelope names the manifest's repository and key epoch, and a payload version no lower than the
 *       manifest's;
 *   <li>the payload authenticates under the 0.4 AAD {@code UTF8(repoId) || 0x1F || int64BE(payloadVersion)
 *       || int64BE(keyEpoch)}, built from the envelope header;
 *   <li>a {@code null} account in the payload is dropped, and while the manifest withholds refresh tokens
 *       (its {@code shareRefreshTokens} is false or absent) no account keeps a {@code refreshToken} or an
 *       {@code expiresAt}.
 * </ul>
 *
 * <p>The 0.12 rollback floor ({@code RepoPin}) has no counterpart: an import is one read with no earlier
 * state to compare with, and it proves nothing a 0.4 host could not have forged before it.
 *
 * <p>Text that is not strict JSON is {@code INVALID_INPUT}; JSON that is not the 0.4 shape, a member that is
 * not listed, or a check above that fails is {@code PROTOCOL}; a data key that does not unwrap or a payload
 * that does not authenticate is {@code CRYPTO}. Every message starts {@code "Vault 0.4 import: "}, and none
 * quotes an input.
 *
 * @author trq
 * @since 1.0.0
 */
public final class LegacyRepository {

    /** The only 0.4 key-wrap scheme. */
    public static final String SCHEME_ID = "X25519-HKDF-SHA256-AESGCM-v1";

    private static final String PREFIX = "Vault 0.4 import: ";
    private static final byte AAD_SEPARATOR = 0x1F;
    private static final int KEY_BYTES = 32;
    private static final int IV_BYTES = 12;
    private static final Gson GSON = new Gson();

    private LegacyRepository() {}

    /**
     * Reads the accounts of a 0.4 repository.
     *
     * @param manifestJson the manifest JSON, as the 0.4 host served it
     * @param envelopeJson the envelope JSON, as the 0.4 host served it
     * @param memberId the reading member's base64 Ed25519 public key
     * @param x25519Private the reading member's 32-byte X25519 private key; not kept
     * @return the accounts, in payload order
     * @throws AltsException of kind {@code INVALID_INPUT}, {@code PROTOCOL} or {@code CRYPTO}, as the class
     *     says
     */
    public static List<AltAccount> read(
            String manifestJson, String envelopeJson, String memberId, byte[] x25519Private) {
        Objects.requireNonNull(manifestJson, "manifestJson");
        Objects.requireNonNull(envelopeJson, "envelopeJson");
        Objects.requireNonNull(memberId, "memberId");
        Objects.requireNonNull(x25519Private, "x25519Private");
        try {
            return readChecked(manifestJson, envelopeJson, memberId, x25519Private);
        } catch (AltsException e) {
            throw relabelled(e);
        }
    }

    /**
     * Gives a failure from the shared AVP helpers (a field of the wrong type, a wrap that does not open)
     * the importer's own prefix, so every message the importer raises starts the same way. Kind and wait
     * are kept, and the original stays the cause.
     *
     * @param e the failure
     * @return {@code e} itself when it already carries the prefix, else a relabelled copy
     */
    private static AltsException relabelled(AltsException e) {
        String message = e.failure().message();
        if (message.startsWith(PREFIX)) {
            return e;
        }
        String detail =
                message.startsWith(AvpFailures.PREFIX) ? message.substring(AvpFailures.PREFIX.length()) : message;
        return new AltsException(e.failure().withMessage(PREFIX + detail), e);
    }

    private static List<AltAccount> readChecked(
            String manifestJson, String envelopeJson, String memberId, byte[] x25519Private) {
        JsonObject manifest = document(manifestJson, "manifest");
        JsonObject envelope = document(envelopeJson, "envelope");

        String repoId = AvpJson.string(manifest, "repoId");
        if (!SCHEME_ID.equals(AvpJson.string(manifest, "schemeId"))) {
            throw protocol("the manifest names another key-wrap scheme");
        }
        long keyEpoch = AvpJson.int64(manifest, "keyEpoch");
        long payloadVersion = AvpJson.int64(manifest, "payloadVersion");
        Optional<JsonElement> shareFlag = AvpJson.optional(manifest, "shareRefreshTokens");
        boolean share = shareFlag.isPresent() && AvpJson.bool(manifest, "shareRefreshTokens");
        JsonObject entry = memberEntry(AvpJson.array(AvpJson.required(manifest, "members"), "members"), memberId);
        if (AvpJson.int64(entry, "keyEpoch") != keyEpoch) {
            throw protocol("the member entry is from another key epoch than the manifest");
        }
        JsonObject wrapped = AvpJson.object(AvpJson.required(entry, "wrappedDataKey"), "wrappedDataKey");

        if (!repoId.equals(AvpJson.string(envelope, "repoId"))) {
            throw protocol("the envelope belongs to another repository");
        }
        long envelopeEpoch = AvpJson.int64(envelope, "keyEpoch");
        if (envelopeEpoch != keyEpoch) {
            throw protocol("the envelope is sealed under another key epoch than the manifest");
        }
        long envelopeVersion = AvpJson.int64(envelope, "payloadVersion");
        if (envelopeVersion < payloadVersion) {
            throw protocol("the envelope is older than the manifest");
        }
        byte[] iv = AvpJson.bytes(envelope, "iv", IV_BYTES);
        byte[] ciphertext = AvpJson.bytes(envelope, "ciphertext");

        byte[] dataKey = unwrapDataKey(wrapped, x25519Private);
        try {
            byte[] plaintext = openPayload(dataKey, iv, ciphertext, repoId, envelopeVersion, envelopeEpoch);
            try {
                return accounts(plaintext, share);
            } finally {
                Arrays.fill(plaintext, (byte) 0);
            }
        } finally {
            Arrays.fill(dataKey, (byte) 0);
        }
    }

    /**
     * The 0.4 payload AAD: {@code UTF8(repoId) || 0x1F || int64BE(payloadVersion) || int64BE(keyEpoch)}.
     *
     * @param repoId the repository id
     * @param payloadVersion the payload version
     * @param keyEpoch the key epoch
     * @return the AAD bytes
     */
    public static byte[] aad(String repoId, long payloadVersion, long keyEpoch) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(repoId.getBytes(StandardCharsets.UTF_8));
        out.write(AAD_SEPARATOR);
        out.writeBytes(int64(payloadVersion));
        out.writeBytes(int64(keyEpoch));
        return out.toByteArray();
    }

    /**
     * Unwraps a 0.4 data key: the JSON {@code WrappedKey} ({@code schemeId}, base64 {@code
     * ephemeralPublicKey}, {@code iv}, {@code ciphertext}) under the {@code avp/rdk-wrap/v1} label.
     *
     * @param wrapped the wrapped key object
     * @param x25519Private the recipient's 32-byte X25519 private key
     * @return the 32-byte data key, which the caller zeroes
     * @throws AltsException of kind {@code PROTOCOL} for another scheme or a malformed field, {@code CRYPTO}
     *     if it does not unwrap
     */
    public static byte[] unwrapDataKey(JsonObject wrapped, byte[] x25519Private) {
        String scheme = AvpJson.string(wrapped, "schemeId");
        if (!SCHEME_ID.equals(scheme)) {
            throw protocol("the data key is wrapped under another scheme");
        }
        WrappedKey key = new WrappedKey(
                scheme,
                AvpJson.bytes(wrapped, "ephemeralPublicKey", KEY_BYTES),
                AvpJson.bytes(wrapped, "iv", IV_BYTES),
                AvpJson.bytes(wrapped, "ciphertext"));
        byte[] dataKey = AvpCrypto.unwrap(x25519Private, key, WrapLabel.DATA_KEY);
        if (dataKey.length != KEY_BYTES) {
            Arrays.fill(dataKey, (byte) 0);
            throw protocol("the data key is not 32 bytes");
        }
        return dataKey;
    }

    /**
     * Opens a 0.4 payload ciphertext (AES-256-GCM, tag appended) under the 0.4 AAD.
     *
     * @param dataKey the 32-byte data key
     * @param iv the 12-byte IV
     * @param ciphertext the ciphertext with its tag
     * @param repoId the envelope's repository id
     * @param payloadVersion the envelope's payload version
     * @param keyEpoch the envelope's key epoch
     * @return the plaintext, which the caller zeroes
     * @throws AltsException of kind {@code CRYPTO} if it does not authenticate
     */
    public static byte[] openPayload(
            byte[] dataKey, byte[] iv, byte[] ciphertext, String repoId, long payloadVersion, long keyEpoch) {
        return AvpCrypto.aesGcmOpen(dataKey, iv, ciphertext, aad(repoId, payloadVersion, keyEpoch));
    }

    private static JsonObject document(String text, String what) {
        JsonElement value;
        try {
            value = AvpJson.parse(text.getBytes(StandardCharsets.UTF_8));
        } catch (AltsException e) {
            throw new AltsException(Kind.INVALID_INPUT, PREFIX + "the " + what + " is not strict JSON");
        }
        if (!value.isJsonObject()) {
            throw protocol("the " + what + " is not a JSON object");
        }
        return value.getAsJsonObject();
    }

    private static JsonObject memberEntry(JsonArray members, String memberId) {
        JsonObject found = null;
        for (JsonElement element : members) {
            if (element.isJsonNull()) {
                continue; // 0.12 skipped a null entry rather than failing the lookup
            }
            JsonObject member = AvpJson.object(element, "a member entry");
            if (found == null && memberId.equals(AvpJson.string(member, "ed25519PublicKey"))) {
                found = member;
            }
        }
        if (found == null) {
            throw protocol("this identity is not a member of the repository");
        }
        return found;
    }

    private static List<AltAccount> accounts(byte[] plaintext, boolean share) {
        JsonObject payload = AvpJson.object(AvpJson.parse(plaintext), "the payload");
        Optional<JsonElement> alts = AvpJson.optional(payload, "alts");
        if (alts.isEmpty()) {
            return List.of();
        }
        List<AltAccount> out = new ArrayList<>();
        for (JsonElement element : AvpJson.array(alts.get(), "alts")) {
            if (element.isJsonNull()) {
                continue; // a peer can put a null in a payload; it carries nothing
            }
            JsonObject json = AvpJson.object(element, "an account");
            AltAccount account;
            try {
                account = GSON.fromJson(json, AltAccount.class);
            } catch (RuntimeException e) {
                throw protocol("an account in the payload is malformed");
            }
            out.add(share ? account : account.withTokens(account.accessToken(), null, 0L));
        }
        return List.copyOf(out);
    }

    private static byte[] int64(long value) {
        byte[] b = new byte[8];
        for (int i = 7; i >= 0; i--) {
            b[i] = (byte) (value & 0xFF);
            value >>>= 8;
        }
        return b;
    }

    private static AltsException protocol(String what) {
        return new AltsException(Kind.PROTOCOL, PREFIX + what);
    }
}

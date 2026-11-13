package lol.trq.alts.internal.avp;

import java.util.Objects;

/**
 * The challenge transcript of host-issued authentication (AVP SPEC 3.3).
 *
 * <p>A client never signs the nonce a host chose as given, nor any other host-supplied bytes outside a
 * CE construction (SPEC 4.1). It signs:
 *
 * <pre>
 * challengeMessage = CE(tag "avp/challenge/v1", bytes(hostKey), bytes(ed25519PublicKey), bytes(nonce))
 * </pre>
 *
 * <p>whose tag keeps it apart from every other signed construction, so no nonce makes it equal to a
 * commit, leave, manifest or acceptance message, and whose {@code hostKey} (the key the client matched
 * the host by) binds the signature to that one host. Because the tag does that work, this route needs no
 * prefix guard on the nonce, unlike a raw-bytes signer.
 *
 * <p>Ported from the Alt Vault Protocol reference implementation (MIT).
 *
 * @author trq
 * @since 1.0.0
 */
public final class Challenge {

    /** The least nonce a host may issue (SPEC 3.3). */
    public static final int MIN_NONCE_BYTES = 32;

    private Challenge() {}

    /**
     * The message a client signs to redeem a challenge.
     *
     * @param hostKey the 32-byte host key of the host being authenticated to
     * @param ed25519PublicKey the 32-byte key requesting the token
     * @param nonce the raw (base64-decoded) nonce
     * @return the message
     * @throws lol.trq.alts.AltsException of kind {@code PROTOCOL} if a key is not 32 bytes
     */
    public static byte[] message(byte[] hostKey, byte[] ed25519PublicKey, byte[] nonce) {
        if (hostKey.length != 32 || ed25519PublicKey.length != 32) {
            throw AvpFailures.protocol("a challenge names two 32-byte keys");
        }
        return Ce.tag(Ce.CHALLENGE)
                .bytes(hostKey)
                .bytes(ed25519PublicKey)
                .bytes(nonce)
                .finish();
    }

    /**
     * Signs the challenge transcript for the key of {@code seed} and the host {@code hostKey}.
     *
     * @param hostKey the 32-byte key the client matched the host by
     * @param seed the 32-byte Ed25519 seed of the key requesting the token
     * @param nonce the raw nonce the host issued
     * @return the 64-byte signature
     * @throws lol.trq.alts.AltsException of kind {@code PROTOCOL} if the nonce is shorter than {@value
     *     #MIN_NONCE_BYTES} bytes or a key has the wrong length
     */
    public static byte[] sign(byte[] hostKey, byte[] seed, byte[] nonce) {
        if (nonce.length < MIN_NONCE_BYTES) {
            throw AvpFailures.protocol("the host issued a challenge nonce shorter than 32 bytes");
        }
        return Ed25519Strict.sign(seed, message(hostKey, Ed25519Strict.publicKey(seed), nonce));
    }

    /**
     * Verifies a challenge signature, strictly, under {@code ed25519PublicKey} over the transcript built
     * with {@code hostKey}, the verifying host's own key. A signature over the raw nonce, or over a
     * transcript for another host key, does not verify.
     *
     * @param hostKey the verifying host's 32-byte key
     * @param ed25519PublicKey the 32-byte key that requested the token
     * @param nonce the raw nonce
     * @param signature the 64-byte signature
     * @return whether it verifies; keys or a signature of the wrong length are simply false
     * @throws NullPointerException if an argument is null
     */
    public static boolean verify(byte[] hostKey, byte[] ed25519PublicKey, byte[] nonce, byte[] signature) {
        Objects.requireNonNull(hostKey, "hostKey");
        Objects.requireNonNull(ed25519PublicKey, "ed25519PublicKey");
        Objects.requireNonNull(nonce, "nonce");
        Objects.requireNonNull(signature, "signature");
        if (hostKey.length != 32 || ed25519PublicKey.length != 32) {
            return false;
        }
        return Ed25519Strict.verify(ed25519PublicKey, message(hostKey, ed25519PublicKey, nonce), signature);
    }
}

package lol.trq.alts.internal.avp;

import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure;
import lol.trq.alts.AltsFailure.Kind;

/**
 * The failures the AVP constructions raise. Every message is built here from a fixed phrase: none quotes
 * an input, a key or a plaintext.
 *
 * <ul>
 *   <li>{@link Kind#PROTOCOL}: an item that does not decode, has the wrong shape, repeats a list key, or
 *       whose signature or id does not check.
 *   <li>{@link Kind#CRYPTO}: an AEAD or key agreement that fails: a wrong key, a wrong label or AAD, a
 *       tampered ciphertext.
 *   <li>{@link Kind#INVALID_INPUT}: input a person typed or a host passed in, such as a recovery phrase
 *       that is not 24 known words with a matching checksum.
 * </ul>
 *
 * @author trq
 * @since 1.0.0
 */
public final class AvpFailures {

    private static final String PREFIX = "Vault protocol: ";

    private AvpFailures() {}

    /**
     * A malformed or unverifiable protocol item.
     *
     * @param what a fixed description of what failed
     * @return the exception, of kind {@link Kind#PROTOCOL}
     */
    public static AltsException protocol(String what) {
        return new AltsException(Kind.PROTOCOL, PREFIX + what);
    }

    /**
     * A cryptographic operation that failed.
     *
     * @param what a fixed description of what failed
     * @param cause the underlying failure, kept for deliberate logging only, or {@code null}
     * @return the exception, of kind {@link Kind#CRYPTO}
     */
    public static AltsException crypto(String what, Throwable cause) {
        return new AltsException(AltsFailure.of(Kind.CRYPTO, PREFIX + what), cause);
    }

    /**
     * Input the caller supplied that cannot be used.
     *
     * @param what a fixed description of what is wrong with it
     * @return the exception, of kind {@link Kind#INVALID_INPUT}
     */
    public static AltsException invalidInput(String what) {
        return new AltsException(Kind.INVALID_INPUT, PREFIX + what);
    }
}

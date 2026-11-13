package lol.trq.alts.internal.avp;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

/**
 * The wire forms of binary values (AVP SPEC 2) and the order every sorted CE list uses.
 *
 * <p>JSON carries binary as standard base64 with padding; repository ids and token text are base64url
 * without padding. Both decoders are canonical: they accept exactly the text the matching encoder
 * produces, so a padded token, a token with whitespace, or base64 with stray bits is refused.
 *
 * <p>Ported from the Alt Vault Protocol reference implementation (MIT).
 *
 * @author trq
 * @since 1.0.0
 */
public final class AvpBytes {

    private static final Base64.Encoder B64 = Base64.getEncoder();
    private static final Base64.Decoder UNB64 = Base64.getDecoder();
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder UNB64URL = Base64.getUrlDecoder();
    private static final HexFormat HEX = HexFormat.of();

    private AvpBytes() {}

    /**
     * Compares two byte strings as unsigned bytes, a shorter prefix first: the order of every sorted list
     * (SPEC 2).
     *
     * @param a the first byte string
     * @param b the second byte string
     * @return negative, zero or positive as {@code a} sorts before, with or after {@code b}
     */
    public static int compare(byte[] a, byte[] b) {
        return Arrays.compareUnsigned(a, b);
    }

    /**
     * Returns the byte strings sorted by {@link #compare(byte[], byte[])}.
     *
     * @param items the byte strings
     * @param what what the list holds, for the failure message
     * @return a new sorted list
     * @throws lol.trq.alts.AltsException of kind {@code PROTOCOL} if two are equal: a list key repeated
     *     makes the wire form malformed (SPEC 4.2, 4.3)
     */
    public static List<byte[]> sortedUnique(List<byte[]> items, String what) {
        List<byte[]> out = new ArrayList<>(items);
        out.sort(AvpBytes::compare);
        for (int k = 1; k < out.size(); k++) {
            if (compare(out.get(k - 1), out.get(k)) == 0) {
                throw AvpFailures.protocol("a " + what + " appears twice");
            }
        }
        return out;
    }

    /**
     * Concatenates two byte strings.
     *
     * @param a the first
     * @param b the second
     * @return {@code a || b}
     */
    public static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    /**
     * Encodes standard base64 with padding.
     *
     * @param b the bytes
     * @return the text
     */
    public static String base64(byte[] b) {
        return B64.encodeToString(b);
    }

    /**
     * Decodes canonical standard base64 with padding.
     *
     * @param s the text
     * @param what what the value is, for the failure message
     * @return the bytes
     * @throws lol.trq.alts.AltsException of kind {@code PROTOCOL} if the text is not exactly what {@link
     *     #base64(byte[])} produces for some bytes
     */
    public static byte[] fromBase64(String s, String what) {
        byte[] out;
        try {
            out = UNB64.decode(s);
        } catch (IllegalArgumentException e) {
            throw AvpFailures.protocol(what + " is not base64");
        }
        if (!B64.encodeToString(out).equals(s)) {
            throw AvpFailures.protocol(what + " is not canonical base64");
        }
        return out;
    }

    /**
     * Decodes canonical standard base64 that must hold exactly {@code length} bytes.
     *
     * @param s the text
     * @param length the required length
     * @param what what the value is, for the failure message
     * @return the bytes
     * @throws lol.trq.alts.AltsException of kind {@code PROTOCOL} if the text is not canonical base64 or
     *     has another length
     */
    public static byte[] fromBase64(String s, int length, String what) {
        byte[] out = fromBase64(s, what);
        if (out.length != length) {
            throw AvpFailures.protocol(what + " must be " + length + " bytes");
        }
        return out;
    }

    /**
     * Encodes base64url without padding.
     *
     * @param b the bytes
     * @return the text
     */
    public static String base64Url(byte[] b) {
        return B64URL.encodeToString(b);
    }

    /**
     * Decodes canonical base64url without padding.
     *
     * @param s the text
     * @param what what the value is, for the failure message
     * @return the bytes
     * @throws lol.trq.alts.AltsException of kind {@code PROTOCOL} if the text carries padding, characters
     *     outside the alphabet, or stray bits
     */
    public static byte[] fromBase64Url(String s, String what) {
        byte[] out;
        try {
            out = UNB64URL.decode(s);
        } catch (IllegalArgumentException e) {
            throw AvpFailures.protocol(what + " is not base64url");
        }
        if (!B64URL.encodeToString(out).equals(s)) {
            throw AvpFailures.protocol(what + " is not canonical base64url without padding");
        }
        return out;
    }

    /**
     * Encodes lowercase hex.
     *
     * @param b the bytes
     * @return the text
     */
    public static String hex(byte[] b) {
        return HEX.formatHex(b);
    }
}

package lol.trq.alts.internal.avp;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * The canonical encoding writer, CE (AVP SPEC 4.1): every signed or hashed AVP structure is one of these
 * byte strings, never JSON text.
 *
 * <p>A CE string starts with exactly one {@link #tag(String)} and then appends items in the order a
 * construction lists them:
 *
 * <table>
 *   <caption>CE items</caption>
 *   <tr><th>Item</th><th>Bytes</th></tr>
 *   <tr><td>{@code tag(label)}</td><td>the UTF-8 label, then one {@code 0x00}</td></tr>
 *   <tr><td>{@code bytes(b)}</td><td>{@code u32BE(len(b)) || b}</td></tr>
 *   <tr><td>{@code str(s)}</td><td>{@code bytes(UTF8(s))}</td></tr>
 *   <tr><td>{@code i64(n)}</td><td>8 bytes, big-endian two's complement</td></tr>
 *   <tr><td>{@code bool(b)}</td><td>{@code 0x00} or {@code 0x01}</td></tr>
 *   <tr><td>{@code count(n)}</td><td>{@code u32BE(n)}</td></tr>
 * </table>
 *
 * <p>The labels are the constants of this class. Each signed construction has its own (the domain
 * separation table of SPEC 4.1): no label holds {@code 0x00}, so the tags are prefix-free and no message
 * of one construction equals a message of another. A writer is not thread safe.
 *
 * <p>Ported from the Alt Vault Protocol reference implementation (MIT).
 *
 * @author trq
 * @since 1.0.0
 */
public final class Ce {

    /** The manifest state {@code S}, signed by the owner key (SPEC 4.2). */
    public static final String MANIFEST = "avp/manifest/v1";

    /** The repository id derivation, hashed (SPEC 4.2). */
    public static final String REPO_ID = "avp/repo-id/v1";

    /** The commit header {@code H}, hashed to the commit id (SPEC 4.3). */
    public static final String COMMIT = "avp/commit/v1";

    /** The commit author signature over the commit id (SPEC 4.3). */
    public static final String COMMIT_SIG = "avp/commit-sig/v1";

    /** The payload AAD v2 (SPEC 4.3). */
    public static final String AAD = "avp/aad/v2";

    /** The leave request, signed by the member key (SPEC 11.4). */
    public static final String LEAVE = "avp/leave/v1";

    /** The challenge transcript, signed by the key requesting a token (SPEC 3.3). */
    public static final String CHALLENGE = "avp/challenge/v1";

    /** The host acceptance, signed by the host key (SPEC 11.3). */
    public static final String ACCEPT = "avp/accept/v1";

    /** The device link confirmation code, hashed (SPEC 11.6). */
    public static final String LINK_CODE = "avp/link-code/v1";

    private final ByteArrayOutputStream buf = new ByteArrayOutputStream();

    private Ce(String label) {
        byte[] b = label.getBytes(StandardCharsets.UTF_8);
        for (byte x : b) {
            if (x == 0) {
                throw new IllegalArgumentException("a CE tag label must not contain 0x00");
            }
        }
        buf.writeBytes(b);
        buf.write(0);
    }

    /**
     * Starts a CE string with {@code tag(label)}.
     *
     * @param label the domain label, one of the constants of this class
     * @return a new writer
     * @throws IllegalArgumentException if the label contains {@code 0x00}
     */
    public static Ce tag(String label) {
        return new Ce(label);
    }

    /**
     * Appends {@code bytes(b)}: {@code u32BE(len(b)) || b}.
     *
     * @param b the bytes
     * @return this writer
     */
    public Ce bytes(byte[] b) {
        count(b.length);
        buf.writeBytes(b);
        return this;
    }

    /**
     * Appends {@code str(s)}: {@code bytes(UTF8(s))}.
     *
     * @param s the string
     * @return this writer
     */
    public Ce str(String s) {
        return bytes(s.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Appends {@code i64(n)}: eight bytes, big-endian two's complement.
     *
     * @param n the integer
     * @return this writer
     */
    public Ce i64(long n) {
        for (int shift = 56; shift >= 0; shift -= 8) {
            buf.write((int) (n >>> shift) & 0xff);
        }
        return this;
    }

    /**
     * Appends {@code bool(b)}: {@code 0x01} for true, {@code 0x00} for false.
     *
     * @param b the boolean
     * @return this writer
     */
    public Ce bool(boolean b) {
        buf.write(b ? 1 : 0);
        return this;
    }

    /**
     * Appends {@code count(n)}: {@code u32BE(n)}.
     *
     * @param n the count, at least zero
     * @return this writer
     * @throws IllegalArgumentException if {@code n} is negative
     */
    public Ce count(int n) {
        if (n < 0) {
            throw new IllegalArgumentException("a CE count must not be negative");
        }
        buf.write((n >>> 24) & 0xff);
        buf.write((n >>> 16) & 0xff);
        buf.write((n >>> 8) & 0xff);
        buf.write(n & 0xff);
        return this;
    }

    /**
     * Returns the finished CE byte string.
     *
     * @return a fresh copy of the bytes written
     */
    public byte[] finish() {
        return buf.toByteArray();
    }
}

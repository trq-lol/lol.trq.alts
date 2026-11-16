package lol.trq.alts.internal.vault.rpc;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure.Kind;

/**
 * The proto3 binary wire format, the part of it AVP uses: varints (an {@code int64} is its two's complement,
 * not zigzag), length-delimited fields, and skipping the fixed-width wire types of fields it does not know.
 *
 * <p>Every malformed input is an {@link AltsException} of kind {@link Kind#PROTOCOL} with a fixed message:
 * a varint over ten bytes, a length past the end, a truncated field, a group, an unknown wire type, field
 * number zero, invalid UTF-8.
 *
 * @author trq
 * @since 1.1.0
 */
final class ProtoWire {

    /** Wire type of a varint. */
    static final int VARINT = 0;

    /** Wire type of a fixed 64-bit value. */
    static final int FIXED64 = 1;

    /** Wire type of a length-delimited value. */
    static final int LEN = 2;

    /** Wire type of a fixed 32-bit value. */
    static final int FIXED32 = 5;

    private ProtoWire() {}

    static AltsException malformed(String what) {
        return new AltsException(Kind.PROTOCOL, "Vault: the host sent a malformed message (" + what + ")");
    }

    /** Appends fields to a growing buffer. */
    static final class Writer {

        private final ByteArrayOutputStream out = new ByteArrayOutputStream();

        void tag(int field, int wireType) {
            varint(((long) field << 3) | wireType);
        }

        void varint(long value) {
            long v = value;
            while ((v & ~0x7FL) != 0) {
                out.write((int) ((v & 0x7F) | 0x80));
                v >>>= 7;
            }
            out.write((int) v);
        }

        void bytes(int field, byte[] value) {
            tag(field, LEN);
            varint(value.length);
            out.writeBytes(value);
        }

        byte[] toByteArray() {
            return out.toByteArray();
        }
    }

    /** Reads fields from a slice of a message, refusing anything malformed. */
    static final class Reader {

        private final byte[] buf;
        private int pos;
        private final int end;

        Reader(byte[] buf) {
            this(buf, 0, buf.length);
        }

        private Reader(byte[] buf, int from, int end) {
            this.buf = buf;
            this.pos = from;
            this.end = end;
        }

        boolean atEnd() {
            return pos >= end;
        }

        /**
         * The next tag, as {@code field << 3 | wireType}.
         *
         * @return the tag
         */
        int tag() {
            long t = varint();
            if (t >>> 3 == 0 || t >>> 3 > 0x1FFF_FFFFL) {
                throw malformed("bad field number");
            }
            return (int) t;
        }

        long varint() {
            long result = 0;
            for (int i = 0; i < 10; i++) {
                if (pos >= end) {
                    throw malformed("truncated varint");
                }
                int b = buf[pos++] & 0xFF;
                if (i == 9 && b > 1) {
                    throw malformed("overlong varint");
                }
                result |= (long) (b & 0x7F) << (7 * i);
                if ((b & 0x80) == 0) {
                    return result;
                }
            }
            throw malformed("overlong varint");
        }

        /**
         * The next length-delimited value, as a reader over its bytes.
         *
         * @return the reader
         */
        Reader slice() {
            long n = varint();
            if (n < 0 || n > end - pos) {
                throw malformed("length past the end");
            }
            Reader r = new Reader(buf, pos, pos + (int) n);
            pos += (int) n;
            return r;
        }

        String string() {
            Reader r = slice();
            try {
                return StandardCharsets.UTF_8
                        .newDecoder()
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT)
                        .decode(ByteBuffer.wrap(Arrays.copyOfRange(r.buf, r.pos, r.end)))
                        .toString();
            } catch (CharacterCodingException e) {
                throw malformed("invalid UTF-8");
            }
        }

        void skip(int wireType) {
            switch (wireType) {
                case VARINT -> varint();
                case FIXED64 -> advance(8);
                case LEN -> slice();
                case FIXED32 -> advance(4);
                default -> throw malformed("unsupported wire type");
            }
        }

        private void advance(int n) {
            if (n > end - pos) {
                throw malformed("truncated field");
            }
            pos += n;
        }
    }
}

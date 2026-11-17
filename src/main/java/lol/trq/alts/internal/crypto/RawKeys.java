package lol.trq.alts.internal.crypto;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

/**
 * Ed25519 and X25519 keys held as their raw 32 bytes, for runtimes without the JCA curves. They are ordinary
 * {@link PublicKey} and {@link PrivateKey} objects, and {@link #getEncoded()} gives the standard X.509 and
 * PKCS #8 encodings, so a host that only stores or compares keys sees no difference.
 */
final class RawKeys {

    static final String ED25519 = "Ed25519";
    static final String X25519 = "X25519";

    private static final byte[] ED_SPKI = hex("302a300506032b6570032100");
    private static final byte[] ED_PKCS8 = hex("302e020100300506032b657004220420");
    private static final byte[] X_SPKI = hex("302a300506032b656e032100");
    private static final byte[] X_PKCS8 = hex("302e020100300506032b656e04220420");

    private RawKeys() {}

    static Public publicKey(String algorithm, byte[] raw) {
        return new Public(algorithm, raw.clone());
    }

    static Private privateKey(String algorithm, byte[] raw) {
        return new Private(algorithm, raw.clone());
    }

    /** A raw public key. */
    static final class Public implements PublicKey {
        private static final long serialVersionUID = 1L;
        private final String algorithm;
        private final byte[] raw;

        private Public(String algorithm, byte[] raw) {
            this.algorithm = algorithm;
            this.raw = raw;
        }

        byte[] raw() {
            return raw.clone();
        }

        @Override
        public String getAlgorithm() {
            return algorithm;
        }

        @Override
        public String getFormat() {
            return "X.509";
        }

        @Override
        public byte[] getEncoded() {
            return concat(ED25519.equals(algorithm) ? ED_SPKI : X_SPKI, raw);
        }

        @Override
        public boolean equals(Object other) {
            return other instanceof Public
                    && algorithm.equals(((Public) other).algorithm)
                    && Arrays.equals(raw, ((Public) other).raw);
        }

        @Override
        public int hashCode() {
            return 31 * algorithm.hashCode() + Arrays.hashCode(raw);
        }
    }

    /** A raw private key: the Ed25519 seed or the X25519 scalar. */
    static final class Private implements PrivateKey {
        private static final long serialVersionUID = 1L;
        private final String algorithm;
        private final byte[] raw;

        private Private(String algorithm, byte[] raw) {
            this.algorithm = algorithm;
            this.raw = raw;
        }

        byte[] raw() {
            return raw.clone();
        }

        @Override
        public String getAlgorithm() {
            return algorithm;
        }

        @Override
        public String getFormat() {
            return "PKCS#8";
        }

        @Override
        public byte[] getEncoded() {
            return concat(ED25519.equals(algorithm) ? ED_PKCS8 : X_PKCS8, raw);
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }
}

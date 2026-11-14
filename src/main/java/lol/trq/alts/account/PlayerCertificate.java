package lol.trq.alts.account;

import com.google.gson.annotations.SerializedName;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure;
import lol.trq.alts.AltsFailure.Kind;

/**
 * An account's chat-signing key pair, from {@code POST /player/certificates}: an RSA key pair, the
 * service's signature over the public key, and how long the pair is good for.
 *
 * <p>The private key signs chat as the account, so it is a credential: it is redacted from
 * {@link #toString()}, and the library neither stores nor logs it. A host that wants to reuse a pair
 * across launches persists it itself, under whatever protection it gives the account's tokens, and asks
 * for a new one once {@link #shouldRefresh(Instant)} says so.
 *
 * @param privateKeyPem the PEM-encoded RSA private key
 * @param publicKeyPem the PEM-encoded RSA public key
 * @param publicKeySignatureV2 the service's Base64 signature over the public key, in the current scheme
 * @param publicKeySignature the signature in the older scheme, which the services have deprecated; may
 *     be {@code null}
 * @param expiresAt when the pair stops being valid, or {@code null} when the service did not say
 * @param refreshedAfter when the service suggests fetching a new pair, ahead of the expiry; may be
 *     {@code null}
 * @author trq
 * @since 0.12.0
 */
public record PlayerCertificate(
        @SerializedName("privateKey") String privateKeyPem,
        @SerializedName("publicKey") String publicKeyPem,
        @SerializedName("publicKeySignatureV2") String publicKeySignatureV2,
        @SerializedName("publicKeySignature") String publicKeySignature,
        @SerializedName("expiresAt") Instant expiresAt,
        @SerializedName("refreshedAfter") Instant refreshedAfter) {

    /**
     * Decodes the private key.
     *
     * @return the RSA private key
     * @throws AltsException of kind {@code INVALID_INPUT} if the PEM is absent or its body is not Base64,
     *     or of kind {@code CRYPTO} if what it decodes to is not a PKCS#8 RSA key; the message never
     *     quotes the key
     * @since 0.12.0
     */
    public PrivateKey privateKey() {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der(privateKeyPem));
        return decode("private key", factory -> factory.generatePrivate(spec));
    }

    /**
     * Decodes the public key.
     *
     * @return the RSA public key
     * @throws AltsException of kind {@code INVALID_INPUT} if the PEM is absent or its body is not Base64,
     *     or of kind {@code CRYPTO} if what it decodes to is not an X.509 RSA key
     * @since 0.12.0
     */
    public PublicKey publicKey() {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(der(publicKeyPem));
        return decode("public key", factory -> factory.generatePublic(spec));
    }

    /** One RSA key decoding, which may fail as the JDK's key factory does. */
    @FunctionalInterface
    private interface KeyDecoding<K> {
        K decode(KeyFactory factory) throws GeneralSecurityException;
    }

    /**
     * Runs one decoding, reporting a key the factory refuses as {@code CRYPTO} with the JDK's exception
     * kept as the cause and its message, which may quote key material, not repeated.
     *
     * @param what which key, for the message
     * @param decoding the decoding to run
     * @param <K> the key type
     * @return the key
     */
    private static <K> K decode(String what, KeyDecoding<K> decoding) {
        try {
            return decoding.decode(KeyFactory.getInstance("RSA"));
        } catch (GeneralSecurityException refused) {
            throw new AltsException(AltsFailure.of(Kind.CRYPTO, "Certificate " + what + " is not an RSA key"), refused);
        }
    }

    /**
     * Returns whether the pair is no longer valid at the given instant. A pair with no stated expiry is
     * treated as expired, since nothing vouches for it.
     *
     * @param now the instant to measure against
     * @return true if the pair has expired or carries no expiry
     * @since 0.12.0
     */
    public boolean expired(Instant now) {
        return expiresAt == null || !now.isBefore(expiresAt);
    }

    /**
     * Returns whether a new pair should be fetched: the service's suggested refresh time has passed, or
     * the pair has expired.
     *
     * @param now the instant to measure against
     * @return true if it is time to fetch a new pair
     * @since 0.12.0
     */
    public boolean shouldRefresh(Instant now) {
        return expired(now) || (refreshedAfter != null && !now.isBefore(refreshedAfter));
    }

    /**
     * Returns a description with the private key redacted.
     *
     * @return a string safe to log
     * @since 0.12.0
     */
    @Override
    public String toString() {
        return "PlayerCertificate[privateKeyPem=" + (privateKeyPem == null ? "null" : "<redacted>")
                + ", publicKeyPem=" + publicKeyPem
                + ", publicKeySignatureV2=" + publicKeySignatureV2
                + ", publicKeySignature=" + publicKeySignature
                + ", expiresAt=" + expiresAt
                + ", refreshedAfter=" + refreshedAfter + "]";
    }

    /**
     * Strips a PEM's armour and decodes what is left. The label on the armour is ignored: the services
     * label these keys as bare RSA while encoding them as PKCS#8 and X.509, so the label is not a
     * reliable guide to the contents.
     *
     * @param pem the PEM text
     * @return the DER bytes
     * @throws AltsException of kind {@code INVALID_INPUT} if the PEM is absent or its body is not Base64
     */
    private static byte[] der(String pem) {
        if (pem == null || pem.isBlank()) {
            throw new AltsException(Kind.INVALID_INPUT, "Certificate: no key present");
        }
        StringBuilder body = new StringBuilder();
        for (String line : pem.split("\\R")) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty() && !trimmed.startsWith("-----")) {
                body.append(trimmed);
            }
        }
        try {
            return Base64.getDecoder().decode(body.toString());
        } catch (IllegalArgumentException notBase64) {
            throw new AltsException(Kind.INVALID_INPUT, "Certificate: key is not valid PEM");
        }
    }
}

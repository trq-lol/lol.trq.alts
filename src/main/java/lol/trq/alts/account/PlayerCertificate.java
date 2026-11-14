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
     * @throws GeneralSecurityException if the PEM is absent or is not a PKCS#8 RSA key
     * @since 0.12.0
     */
    public PrivateKey privateKey() throws GeneralSecurityException {
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der(privateKeyPem)));
    }

    /**
     * Decodes the public key.
     *
     * @return the RSA public key
     * @throws GeneralSecurityException if the PEM is absent or is not an X.509 RSA key
     * @since 0.12.0
     */
    public PublicKey publicKey() throws GeneralSecurityException {
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der(publicKeyPem)));
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
     * @throws GeneralSecurityException if the PEM is absent or its body is not Base64
     */
    private static byte[] der(String pem) throws GeneralSecurityException {
        if (pem == null || pem.isBlank()) {
            throw new GeneralSecurityException("no key present");
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
            throw new GeneralSecurityException("key is not valid PEM");
        }
    }
}

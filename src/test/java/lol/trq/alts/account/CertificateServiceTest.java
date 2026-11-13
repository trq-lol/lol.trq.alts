package lol.trq.alts.account;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The chat-signing key pair. What matters is that the PEMs decode to keys that actually work together,
 * and that the private half never reaches a string a host might log.
 */
class CertificateServiceTest {

    private static KeyPair keys;
    private static String privatePem;
    private static String publicPem;

    private LoopbackServices server;

    @BeforeAll
    static void generateKeys() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        keys = generator.generateKeyPair();
        // Labelled the way the services label them: as bare RSA keys, over PKCS#8 and X.509 bodies.
        privatePem = pem("RSA PRIVATE KEY", keys.getPrivate().getEncoded());
        publicPem = pem("RSA PUBLIC KEY", keys.getPublic().getEncoded());
    }

    private static String pem(String label, byte[] der) {
        String body = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der);
        return "-----BEGIN " + label + "-----\n" + body + "\n-----END " + label + "-----\n";
    }

    private static String json(String text) {
        return text.replace("\n", "\\n");
    }

    private static String certificateBody(String legacySignature) {
        return "{\"keyPair\":{\"privateKey\":\"" + json(privatePem) + "\",\"publicKey\":\"" + json(publicPem) + "\"},"
                + "\"publicKeySignatureV2\":\"c2lnbmF0dXJlLXYy\","
                + (legacySignature == null ? "" : "\"publicKeySignature\":\"" + legacySignature + "\",")
                + "\"expiresAt\":\"2030-06-01T12:00:00.123456789Z\","
                + "\"refreshedAfter\":\"2030-06-01T04:00:00.123456789Z\"}";
    }

    @BeforeEach
    void setUp() throws IOException {
        server = new LoopbackServices();
    }

    @AfterEach
    void tearDown() {
        server.close();
    }

    @Test
    void theKeyPairIsRequestedWithAnEmptyPostAndDecodesToWorkingKeys() throws Exception {
        server.canned(200, certificateBody("bGVnYWN5"));

        PlayerCertificate certificate = server.services().certificates().fetch();

        assertEquals("POST", server.last().method());
        assertEquals("/player/certificates", server.last().rawPath());
        assertEquals(0, server.last().body().length, "the request body is empty");
        assertEquals("Bearer test-token", server.last().authorization());

        assertEquals(privatePem, certificate.privateKeyPem(), "the raw PEM is handed back untouched");
        assertEquals(publicPem, certificate.publicKeyPem());
        assertEquals("c2lnbmF0dXJlLXYy", certificate.publicKeySignatureV2());
        assertEquals("bGVnYWN5", certificate.publicKeySignature());
        assertArrayEquals(
                keys.getPrivate().getEncoded(), certificate.privateKey().getEncoded());
        assertArrayEquals(keys.getPublic().getEncoded(), certificate.publicKey().getEncoded());

        // The decoded halves are a pair: what one signs the other verifies.
        byte[] message = "signed chat".getBytes();
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(certificate.privateKey());
        signer.update(message);
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(certificate.publicKey());
        verifier.update(message);
        assertTrue(verifier.verify(signer.sign()));
    }

    @Test
    void theDeprecatedSignatureIsOptional() throws Exception {
        server.canned(200, certificateBody(null));

        PlayerCertificate certificate = server.services().certificates().fetch();

        assertNull(certificate.publicKeySignature());
        assertEquals("c2lnbmF0dXJlLXYy", certificate.publicKeySignatureV2());
    }

    @Test
    void expiryAndRefreshAreMeasuredAgainstTheGivenInstant() throws Exception {
        server.canned(200, certificateBody(null));

        PlayerCertificate certificate = server.services().certificates().fetch();

        assertEquals(Instant.parse("2030-06-01T12:00:00.123456789Z"), certificate.expiresAt());
        assertEquals(Instant.parse("2030-06-01T04:00:00.123456789Z"), certificate.refreshedAfter());

        Instant early = Instant.parse("2030-06-01T00:00:00Z");
        assertFalse(certificate.expired(early));
        assertFalse(certificate.shouldRefresh(early));

        Instant pastRefresh = Instant.parse("2030-06-01T06:00:00Z");
        assertFalse(certificate.expired(pastRefresh), "past the refresh hint the pair is still valid");
        assertTrue(certificate.shouldRefresh(pastRefresh), "but a new one should be fetched");

        Instant late = Instant.parse("2030-06-02T00:00:00Z");
        assertTrue(certificate.expired(late));
        assertTrue(certificate.shouldRefresh(late));

        PlayerCertificate undated = new PlayerCertificate(privatePem, publicPem, "sig", null, null, null);
        assertTrue(undated.expired(early), "a pair with no stated expiry is not trusted to be valid");
        assertTrue(undated.shouldRefresh(early));
    }

    @Test
    void toStringNeverCarriesThePrivateKey() throws Exception {
        server.canned(200, certificateBody("bGVnYWN5"));

        String printed = server.services().certificates().fetch().toString();

        String keyMaterial =
                Base64.getEncoder().encodeToString(keys.getPrivate().getEncoded());
        assertFalse(printed.contains(keyMaterial.substring(0, 40)), "no private key material in toString");
        assertFalse(printed.contains("PRIVATE KEY"), "nor its PEM armour");
        assertTrue(printed.contains("<redacted>"));
        assertTrue(printed.contains("c2lnbmF0dXJlLXYy"), "the public parts are still printed");
    }

    @Test
    void aKeyThatIsNotPemFailsToDecodeRatherThanReturningGarbage() {
        PlayerCertificate broken = new PlayerCertificate("not a key", "%%%", "sig", null, null, null);
        PlayerCertificate absent = new PlayerCertificate(null, null, "sig", null, null, null);

        assertThrows(GeneralSecurityException.class, broken::privateKey);
        assertThrows(GeneralSecurityException.class, broken::publicKey);
        assertThrows(GeneralSecurityException.class, absent::privateKey);
        assertFalse(absent.toString().contains("<redacted>"), "an absent key is shown as absent");
    }

    @Test
    void aResponseWithNoKeyPairIsAFailure() {
        server.canned(200, "{\"publicKeySignatureV2\":\"sig\"}");
        assertThrows(
                AccountException.class, () -> server.services().certificates().fetch());

        server.canned(204, "");
        assertThrows(
                AccountException.class, () -> server.services().certificates().fetch());
    }

    @Test
    void certificateFailuresCarryTheirStatus() {
        server.canned(401, "{\"errorMessage\":\"Invalid token\"}");
        AccountException refused = assertThrows(
                AccountException.class, () -> server.services().certificates().fetch());
        assertTrue(refused.tokenRefused());

        server.rateLimited(30);
        AccountException limited = assertThrows(
                AccountException.class, () -> server.services().certificates().fetch());
        assertTrue(limited.rateLimited());
        assertEquals(Duration.ofSeconds(30), limited.retryAfter());
    }
}

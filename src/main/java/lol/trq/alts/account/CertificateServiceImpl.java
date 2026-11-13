package lol.trq.alts.account;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import lol.trq.alts.net.NetworkScope;

/**
 * Concrete {@link CertificateService}: one bearer POST with an empty body, read into a
 * {@link PlayerCertificate}.
 *
 * @author trq
 * @since 0.12.0
 */
final class CertificateServiceImpl implements CertificateService {

    private final AccountHttp http;
    private final AccountEndpoints endpoints;

    CertificateServiceImpl(AccountHttp http, AccountEndpoints endpoints) {
        this.http = http;
        this.endpoints = endpoints;
    }

    @Override
    public PlayerCertificate fetch() {
        // An explicitly empty body rather than none: the endpoint is a POST, and a POST with no declared
        // length is refused by some intermediaries.
        JsonObject body = http.sendRaw(
                "POST", endpoints.playerCertificates(), "application/json", new byte[0], NetworkScope.Purpose.PROFILE);
        if (body == null) {
            throw AccountHttp.unreadable("Player certificate");
        }
        JsonElement pair = body.get("keyPair");
        JsonObject keyPair = pair != null && pair.isJsonObject() ? pair.getAsJsonObject() : null;
        String privateKey = AccountHttp.string(keyPair, "privateKey");
        String publicKey = AccountHttp.string(keyPair, "publicKey");
        if (privateKey == null || publicKey == null) {
            throw AccountHttp.unreadable("Player certificate");
        }
        return new PlayerCertificate(
                privateKey,
                publicKey,
                AccountHttp.string(body, "publicKeySignatureV2"),
                AccountHttp.string(body, "publicKeySignature"),
                instant(AccountHttp.string(body, "expiresAt")),
                instant(AccountHttp.string(body, "refreshedAfter")));
    }

    private static Instant instant(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return Instant.parse(value);
        } catch (DateTimeParseException notIso) {
            return null;
        }
    }
}

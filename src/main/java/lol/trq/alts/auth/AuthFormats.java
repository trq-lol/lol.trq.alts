package lol.trq.alts.auth;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.regex.Pattern;

/**
 * The two small text conversions every login route needs, kept in one place so the routes cannot drift
 * apart on what a UUID or a token payload looks like.
 *
 * @author trq
 * @since 0.12.0
 */
final class AuthFormats {

    private static final Pattern UNDASHED_UUID =
            Pattern.compile("(\\p{XDigit}{8})(\\p{XDigit}{4})(\\p{XDigit}{4})(\\p{XDigit}{4})(\\p{XDigit}+)");

    private AuthFormats() {}

    /**
     * Adds the dashes to a UUID the services returned without them.
     *
     * @param uuid the UUID, dashed or not
     * @return the dashed form; the input unchanged when it already carries dashes
     */
    static String dashedUuid(String uuid) {
        return uuid.contains("-") ? uuid : UNDASHED_UUID.matcher(uuid).replaceFirst("$1-$2-$3-$4-$5");
    }

    /**
     * Decodes the payload segment of a JSON Web Token. Accepts both Base64 alphabets and either padding
     * convention, since tokens are pasted from sources that normalise them differently. The payload is
     * <strong>not verified</strong>: the library holds no key to check the signature with, so nothing
     * read from it may be trusted beyond what the caller would accept from the user directly.
     *
     * @param token the full token
     * @return the payload as JSON text
     * @throws IllegalArgumentException if the token has no payload segment or it is not Base64
     */
    static String jwtPayload(String token) {
        String[] parts = token.split("\\.");
        if (parts.length < 2) {
            throw new IllegalArgumentException("token has no payload segment");
        }
        String urlSafe = parts[1].replace('+', '-').replace('/', '_').replace("=", "");
        return new String(Base64.getUrlDecoder().decode(urlSafe), StandardCharsets.UTF_8);
    }
}

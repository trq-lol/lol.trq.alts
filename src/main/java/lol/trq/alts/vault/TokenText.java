package lol.trq.alts.vault;

import com.google.gson.JsonObject;
import java.util.Objects;
import java.util.function.Function;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.internal.avp.Tokens;

/**
 * Pasted token text (AVP SPEC 11.1): base64url-nopad over a JSON object. The alphabet holds no whitespace,
 * so every whitespace character a paste brings along (around the token, or a line break inside one a chat
 * client wrapped) is dropped before decoding.
 *
 * @author trq
 * @since 1.0.0
 */
final class TokenText {

    private TokenText() {}

    /**
     * {@code text} without whitespace.
     *
     * @param text the pasted text
     * @return the token characters
     */
    static String clean(String text) {
        StringBuilder out = new StringBuilder(text.length());
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (!Character.isWhitespace(c) && !Character.isSpaceChar(c)) {
                out.append(c);
            }
        }
        return out.toString();
    }

    /**
     * Decodes pasted token text.
     *
     * @param text the pasted text
     * @param what the token's name, a fixed phrase for the message
     * @param decoder the typed decoder
     * @param <T> the token
     * @return the token
     * @throws AltsException of kind {@code INVALID_INPUT} if the text is not that token
     */
    static <T> T parse(String text, String what, Function<JsonObject, T> decoder) {
        Objects.requireNonNull(text, "text");
        try {
            return decoder.apply(Tokens.decode(clean(text)));
        } catch (RuntimeException malformed) {
            // The decoder's own message may quote the input; the library's message names the token only.
            throw new AltsException(
                    AltsFailure.of(Kind.INVALID_INPUT, "Vault: this is not a valid " + what), malformed);
        }
    }

    /**
     * The text of a token.
     *
     * @param json the token object
     * @return the base64url-nopad text
     */
    static String format(JsonObject json) {
        return Tokens.encode(json);
    }
}

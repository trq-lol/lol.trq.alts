package lol.trq.alts.vault;

import java.util.Objects;
import lol.trq.alts.AltsException;
import lol.trq.alts.internal.avp.Tokens;

/**
 * The request a new owner device shows (AVP SPEC 11.6): its ephemeral public key. It travels to an existing
 * owner device out of band, which shows the same {@link #confirmationCode()} and, once the owner confirms the
 * two match, answers with a {@link LinkGrant} ({@link LinkSession#approve}).
 *
 * <p>It holds no secret.
 *
 * @author trq
 * @since 1.0.0
 */
public final class LinkRequest {

    private final Tokens.LinkRequest token;

    LinkRequest(Tokens.LinkRequest token) {
        this.token = Objects.requireNonNull(token, "token");
    }

    /**
     * Reads a link request from pasted text. Whitespace anywhere in the text is ignored.
     *
     * @param text the pasted text
     * @return the request
     * @throws AltsException of kind {@code INVALID_INPUT} if the text is not a version 2 link request
     * @since 1.0.0
     */
    public static LinkRequest parse(String text) {
        return new LinkRequest(TokenText.parse(text, "link request", Tokens::linkRequestFromJson));
    }

    /**
     * The token text to carry to the existing owner device.
     *
     * @return the text
     * @since 1.0.0
     */
    public String text() {
        return TokenText.format(Tokens.toJson(token));
    }

    /**
     * The 6-digit code both devices show (SPEC 11.6), leading zeros kept.
     *
     * @return the code
     * @since 1.0.0
     */
    public String confirmationCode() {
        return Tokens.linkConfirmationCode(token.ephemeralPublicKey());
    }

    Tokens.LinkRequest token() {
        return token;
    }

    /**
     * Whether {@code o} is a request with the same text.
     *
     * @param o the other object
     * @return whether they are equal
     */
    @Override
    public boolean equals(Object o) {
        return o instanceof LinkRequest other && text().equals(other.text());
    }

    @Override
    public int hashCode() {
        return text().hashCode();
    }

    /**
     * The confirmation code.
     *
     * @return a description
     */
    @Override
    public String toString() {
        return "LinkRequest[code " + confirmationCode() + "]";
    }
}

package lol.trq.alts.vault;

import java.util.Objects;
import lol.trq.alts.AltsException;
import lol.trq.alts.internal.avp.Tokens;

/**
 * The answer of an existing owner device to a {@link LinkRequest} (AVP SPEC 11.6): the owner's mnemonic
 * entropy, wrapped to the request's ephemeral key under {@code avp/owner-link/v1}. Only the new device's
 * {@link LinkSession} opens it.
 *
 * <p>It carries the owner key, encrypted: carry it only to the device that showed the request, and do not
 * log or keep it. {@link #toString()} shows nothing of it.
 *
 * @author trq
 * @since 1.0.0
 */
public final class LinkGrant {

    private final Tokens.LinkGrant token;

    LinkGrant(Tokens.LinkGrant token) {
        this.token = Objects.requireNonNull(token, "token");
    }

    /**
     * Reads a link grant from pasted text. Whitespace anywhere in the text is ignored.
     *
     * @param text the pasted text
     * @return the grant
     * @throws AltsException of kind {@code INVALID_INPUT} if the text is not a version 2 link grant
     * @since 1.0.0
     */
    public static LinkGrant parse(String text) {
        return new LinkGrant(TokenText.parse(text, "link grant", Tokens::linkGrantFromJson));
    }

    /**
     * The token text to carry back to the new device.
     *
     * @return the text
     * @since 1.0.0
     */
    public String text() {
        return TokenText.format(Tokens.toJson(token));
    }

    Tokens.LinkGrant token() {
        return token;
    }

    /**
     * Names the type only; the grant carries the owner key, encrypted.
     *
     * @return a description
     * @since 1.0.0
     */
    @Override
    public String toString() {
        return "LinkGrant[redacted]";
    }
}

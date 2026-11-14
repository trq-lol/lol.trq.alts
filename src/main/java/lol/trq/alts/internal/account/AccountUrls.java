package lol.trq.alts.internal.account;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import lol.trq.alts.account.AccountEndpoints;

/**
 * The request addresses of the account services, built from the runtime's {@link AccountEndpoints}. Kept off
 * the public record, which names only the base a host points the services at.
 *
 * @author trq
 * @since 1.0.0
 */
public final class AccountUrls {

    private final String base;

    /**
     * The addresses under an endpoint base.
     *
     * @param endpoints the endpoints; {@code null} means {@link AccountEndpoints#defaults()}
     */
    public AccountUrls(AccountEndpoints endpoints) {
        this.base = (endpoints == null ? AccountEndpoints.defaults() : endpoints).base();
    }

    public String profile() {
        return base + "/minecraft/profile";
    }

    public String entitlements() {
        return base + "/entitlements/mcstore";
    }

    public String nameAvailability(String name) {
        return base + "/minecraft/profile/name/" + segment(name) + "/available";
    }

    public String nameChange(String name) {
        return base + "/minecraft/profile/name/" + segment(name);
    }

    public String nameChangeInfo() {
        return base + "/minecraft/profile/namechange";
    }

    public String skins() {
        return base + "/minecraft/profile/skins";
    }

    public String activeSkin() {
        return base + "/minecraft/profile/skins/active";
    }

    public String activeCape() {
        return base + "/minecraft/profile/capes/active";
    }

    public String playerAttributes() {
        return base + "/player/attributes";
    }

    public String playerCertificates() {
        return base + "/player/certificates";
    }

    public String blocklist() {
        return base + "/privacy/blocklist";
    }

    public String lookupByName(String name) {
        return base + "/minecraft/profile/lookup/name/" + segment(name);
    }

    /** The batch lookup, which takes a JSON array of names and answers with an array of the ones that exist. */
    public String lookupByNames() {
        return base + "/minecraft/profile/lookup/bulk/byname";
    }

    public String lookupByUuid(String undashedUuid) {
        return base + "/minecraft/profile/lookup/" + segment(undashedUuid);
    }

    /**
     * Encodes a caller-supplied value as one path segment. Concatenated raw, a name carrying a slash, a
     * question mark, or a fragment marker would address a different endpoint than the one the caller
     * asked for, or fail to parse as a URL at all.
     *
     * @param value the value to place in a path
     * @return the percent-encoded segment
     */
    static String segment(String value) {
        // URLEncoder speaks form encoding, where a space is a plus; in a path a plus is a literal plus.
        return URLEncoder.encode(value == null ? "" : value, StandardCharsets.UTF_8)
                .replace("+", "%20");
    }
}

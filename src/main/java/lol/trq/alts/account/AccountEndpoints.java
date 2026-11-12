package lol.trq.alts.account;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * The Minecraft services base a host's account calls go to. Defaults to the public host; a host fronting
 * the services with its own proxy, or a test pointing at a loopback, overrides the base and every path
 * is built from it.
 *
 * @param base the Minecraft services origin, without a trailing slash
 * @author trq
 * @since 1.0.0
 */
public record AccountEndpoints(String base) {

    /** The public Minecraft services origin. */
    public static final String DEFAULT_BASE = "https://api.minecraftservices.com";

    /** Substitutes the default base for a blank one, and trims any trailing slash. */
    public AccountEndpoints {
        base = base == null || base.isBlank() ? DEFAULT_BASE : base;
        if (base.endsWith("/")) {
            base = base.substring(0, base.length() - 1);
        }
    }

    /** Returns the endpoints for the public Minecraft services. */
    public static AccountEndpoints defaults() {
        return new AccountEndpoints(DEFAULT_BASE);
    }

    String profile() {
        return base + "/minecraft/profile";
    }

    String entitlements() {
        return base + "/entitlements/mcstore";
    }

    String nameAvailability(String name) {
        return base + "/minecraft/profile/name/" + segment(name) + "/available";
    }

    String nameChange(String name) {
        return base + "/minecraft/profile/name/" + segment(name);
    }

    String nameChangeInfo() {
        return base + "/minecraft/profile/namechange";
    }

    String skins() {
        return base + "/minecraft/profile/skins";
    }

    String activeSkin() {
        return base + "/minecraft/profile/skins/active";
    }

    String activeCape() {
        return base + "/minecraft/profile/capes/active";
    }

    String playerAttributes() {
        return base + "/player/attributes";
    }

    String playerCertificates() {
        return base + "/player/certificates";
    }

    String blocklist() {
        return base + "/privacy/blocklist";
    }

    String lookupByName(String name) {
        return base + "/minecraft/profile/lookup/name/" + segment(name);
    }

    /** The batch lookup, which takes a JSON array of names and answers with an array of the ones that exist. */
    String lookupByNames() {
        return base + "/minecraft/profile/lookup/bulk/byname";
    }

    String lookupByUuid(String undashedUuid) {
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

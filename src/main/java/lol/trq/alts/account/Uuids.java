package lol.trq.alts.account;

import java.util.Locale;
import java.util.regex.Pattern;

/**
 * UUID text handling for the account services. The Minecraft services hand ids out undashed; the rest of
 * the library — the store, the session, a request's routing scope — speaks dashed, so an id that leaves
 * this package as an identity is dashed.
 *
 * @author trq
 * @since 0.12.0
 */
final class Uuids {

    private static final Pattern UNDASHED = Pattern.compile("[0-9a-fA-F]{32}");

    private Uuids() {}

    /**
     * Returns an id in dashed, lower-case form.
     *
     * @param id a dashed or undashed UUID, or null
     * @return the dashed form; the input unchanged when it is not thirty-two hex digits, null for null
     */
    static String dashed(String id) {
        String undashed = undashed(id);
        if (undashed == null) {
            return id;
        }
        return undashed.substring(0, 8)
                + "-"
                + undashed.substring(8, 12)
                + "-"
                + undashed.substring(12, 16)
                + "-"
                + undashed.substring(16, 20)
                + "-"
                + undashed.substring(20);
    }

    /**
     * Returns an id as thirty-two lower-case hex digits, the form the services take in a path.
     *
     * @param id a dashed or undashed UUID, or null
     * @return the undashed form, or null when the input is not a UUID
     */
    static String undashed(String id) {
        if (id == null) {
            return null;
        }
        String stripped = id.trim().replace("-", "");
        return UNDASHED.matcher(stripped).matches() ? stripped.toLowerCase(Locale.ROOT) : null;
    }
}

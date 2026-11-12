package lol.trq.alts.account;

import java.util.regex.Pattern;

/**
 * The shape of a Minecraft username, checked locally so a request that can only be refused is not sent.
 *
 * @author trq
 * @since 0.12.0
 */
final class NameRules {

    private static final Pattern VALID = Pattern.compile("[A-Za-z0-9_]{3,16}");

    private NameRules() {}

    /**
     * Returns whether a name is three to sixteen letters, digits, or underscores.
     *
     * @param name the candidate name, or null
     * @return true if the services could accept it
     */
    static boolean valid(String name) {
        return name != null && VALID.matcher(name).matches();
    }
}

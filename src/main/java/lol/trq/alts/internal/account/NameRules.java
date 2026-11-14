package lol.trq.alts.internal.account;

import java.util.regex.Pattern;

/**
 * The shape of a Minecraft username, checked locally so a request that can only be refused is not sent.
 *
 * @author trq
 * @since 0.12.0
 */
public final class NameRules {

    private static final Pattern VALID = Pattern.compile("[A-Za-z0-9_]{3,16}");

    /** The shape of a name that may exist, as opposed to one that may be taken today. */
    private static final Pattern LOOKUPABLE = Pattern.compile("[A-Za-z0-9_]{1,16}");

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

    /**
     * Returns whether {@code name} could be a name some player already holds. Wider than
     * {@link #valid(String)}: nobody can take a name of one or two characters any more, but accounts
     * that took one before the minimum was raised still have it, and looking one up is not creating one.
     *
     * @param name the name to test, or null
     * @return true for 1 to 16 characters of letters, digits, and underscore
     */
    static boolean lookupable(String name) {
        return name != null && LOOKUPABLE.matcher(name).matches();
    }
}

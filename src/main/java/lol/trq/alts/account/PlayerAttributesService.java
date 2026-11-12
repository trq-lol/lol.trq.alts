package lol.trq.alts.account;

/**
 * Reads what an account may do online — privileges, safety preferences, bans — and sets the one
 * preference the services let an account change here, the profanity filter.
 *
 * <p>The friends and presence endpoints that sit beside these are deliberately absent: the services mark
 * them unstable, and a surface that is about to be frozen should not be built on them.
 *
 * @author trq
 * @since 0.12.0
 */
public interface PlayerAttributesService {

    /**
     * Fetches the account's attributes.
     *
     * @return the attributes
     * @throws AccountException if the token was refused or the service failed
     * @since 0.12.0
     */
    PlayerAttributes fetch() throws AccountException;

    /**
     * Turns the profanity filter on or off.
     *
     * @param enabled whether the filter should be on
     * @return the attributes as the service holds them after the change
     * @throws AccountException if the token was refused or the service failed
     * @since 0.12.0
     */
    PlayerAttributes setProfanityFilter(boolean enabled) throws AccountException;
}

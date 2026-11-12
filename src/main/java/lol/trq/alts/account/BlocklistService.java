package lol.trq.alts.account;

/**
 * Reads the account's privacy blocklist. Read-only: the list is edited in the game and on the account
 * site, not here.
 *
 * @author trq
 * @since 0.12.0
 */
public interface BlocklistService {

    /**
     * Fetches the players the account has blocked.
     *
     * @return the blocklist
     * @throws AccountException if the token was refused or the service failed
     * @since 0.12.0
     */
    Blocklist fetch() throws AccountException;
}

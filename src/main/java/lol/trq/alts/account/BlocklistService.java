package lol.trq.alts.account;

/**
 * Reads the account's privacy blocklist. Read-only: the list is edited in the game and on the account
 * site, not here.
 *
 * <p>Not designed for host implementation; methods may be added in minor releases.
 *
 * @author trq
 * @since 0.12.0
 */
public interface BlocklistService {

    /**
     * Fetches the players the account has blocked.
     *
     * @return the blocklist
     * @throws lol.trq.alts.AltsException if the token was refused or the service failed
     * @since 0.12.0
     */
    Blocklist fetch();
}

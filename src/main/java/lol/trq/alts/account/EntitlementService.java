package lol.trq.alts.account;

/**
 * Reads what an account owns.
 *
 * <p>Not designed for host implementation; methods may be added in minor releases.
 *
 * @author trq
 * @since 0.11.0
 */
public interface EntitlementService {

    /**
     * Fetches the account's entitlements.
     *
     * @return the products the account holds
     * @throws lol.trq.alts.AltsException if the token was refused or the service failed
     * @since 0.11.0
     */
    Entitlements fetch();
}

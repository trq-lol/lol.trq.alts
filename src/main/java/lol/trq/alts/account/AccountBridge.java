package lol.trq.alts.account;

import lol.trq.alts.internal.account.AccountAccess;
import lol.trq.alts.net.HttpTransport;

/**
 * The account package's side of {@link AccountAccess}: the runtime builds the services through it, so
 * neither {@link AccountServices} nor {@link ProfileLookupService} needs a public factory. Installed
 * exactly once, when {@link AccountServices} initializes.
 *
 * @author trq
 * @since 1.0.0
 */
final class AccountBridge implements AccountAccess.Bridge {

    static {
        AccountAccess.install(new AccountBridge());
    }

    private AccountBridge() {}

    /** Initializes this class, and with it the bridge; repeat calls do nothing. */
    static void install() {
        // The static initializer above does the work.
    }

    @Override
    public AccountServices services(
            HttpTransport transport, String token, String accountUuid, AccountEndpoints endpoints) {
        return AccountServices.create(transport, token, accountUuid, endpoints);
    }

    @Override
    public ProfileLookupService profileLookup(HttpTransport transport, AccountEndpoints endpoints) {
        return new ProfileLookupServiceImpl(transport, endpoints == null ? AccountEndpoints.defaults() : endpoints);
    }
}

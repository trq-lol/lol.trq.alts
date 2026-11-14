package lol.trq.alts.internal.account;

import java.util.Objects;
import lol.trq.alts.account.AccountEndpoints;
import lol.trq.alts.account.AccountServices;
import lol.trq.alts.account.ProfileLookupService;
import lol.trq.alts.internal.net.HttpTransport;

/**
 * How the runtime builds the account services and the profile lookup without either having a public
 * factory. The account package installs the one {@link Bridge} when {@link AccountServices} initializes,
 * and {@link #install} accepts no other: only the library's own bridge class, loaded by this class's own
 * loader, and only once. Not part of the library's API: a host reaches the services through
 * {@code AltsRuntime#accountServices} and {@code AltsRuntime#profileLookup}.
 *
 * <p>Known limit, on the class path only: the module does not export this package, so on the module path
 * nothing outside the library can reach it, but on the class path a descriptor restricts nothing, and code
 * there can call {@link #bridge()} and build services of its own over a token it already holds.
 *
 * @author trq
 * @since 1.0.0
 */
public final class AccountAccess {

    /** The one class whose instance {@link #install} accepts. */
    private static final String BRIDGE_CLASS = "lol.trq.alts.account.AccountBridge";

    private static volatile Bridge bridge;

    private AccountAccess() {}

    /**
     * Installs the bridge. Called once, by the account package, as it initializes.
     *
     * @param value the bridge
     * @throws IllegalArgumentException if {@code value} is not the library's own account bridge, loaded
     *     by this class's loader; nothing is installed
     * @throws IllegalStateException if a bridge is already installed
     * @since 1.0.0
     */
    public static synchronized void install(Bridge value) {
        Objects.requireNonNull(value, "bridge");
        Class<?> type = value.getClass();
        if (!type.getName().equals(BRIDGE_CLASS) || type.getClassLoader() != AccountAccess.class.getClassLoader()) {
            throw new IllegalArgumentException("not the library's account bridge");
        }
        if (bridge != null) {
            throw new IllegalStateException("account bridge already installed");
        }
        bridge = value;
    }

    /**
     * Returns the bridge, initializing the account package first when nothing has yet.
     *
     * @return the installed bridge
     * @since 1.0.0
     */
    public static Bridge bridge() {
        try {
            Class.forName(AccountServices.class.getName(), true, AccountAccess.class.getClassLoader());
        } catch (ClassNotFoundException impossible) {
            throw new IllegalStateException("account package unavailable", impossible);
        }
        return Objects.requireNonNull(bridge, "account bridge not installed");
    }

    /**
     * The runtime's way into the account package.
     *
     * @since 1.0.0
     */
    public interface Bridge {

        /**
         * Builds the services for one account.
         *
         * @param transport the runtime's transport
         * @param token the account's Minecraft access token
         * @param accountUuid the account UUID, for per-account request routing; may be null
         * @param endpoints the Minecraft services base
         * @return the services
         */
        AccountServices services(HttpTransport transport, String token, String accountUuid, AccountEndpoints endpoints);

        /**
         * Builds the public profile lookup.
         *
         * @param transport the runtime's transport
         * @param endpoints the Minecraft services base
         * @return the lookup service
         */
        ProfileLookupService profileLookup(HttpTransport transport, AccountEndpoints endpoints);
    }
}

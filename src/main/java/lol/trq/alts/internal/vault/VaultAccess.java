package lol.trq.alts.internal.vault;

import java.net.URI;
import java.util.Objects;
import java.util.function.Function;
import lol.trq.alts.internal.net.HttpTransport;
import lol.trq.alts.vault.VaultHosts;

/**
 * How the runtime builds and closes its {@link VaultHosts} without the type having a public constructor. The
 * vault package installs the one {@link Bridge} when {@link VaultHosts} initializes, and {@link #install}
 * accepts no other: only the library's own bridge class, loaded by this class's own loader, and only once.
 * Not part of the library's API: a host reaches the vault through {@code AltsRuntime#vault()}.
 *
 * <p>Known limit, on the class path only: the module does not export this package, so on the module path
 * nothing outside the library can reach it, but on the class path a descriptor restricts nothing, and code
 * there can call {@link #bridge()} and build a {@link VaultHosts} of its own over a transport it holds.
 *
 * @author trq
 * @since 1.0.0
 */
public final class VaultAccess {

    /** The one class whose instance {@link #install} accepts. */
    private static final String BRIDGE_CLASS = "lol.trq.alts.vault.VaultBridge";

    private static volatile Bridge bridge;

    private VaultAccess() {}

    /**
     * Installs the bridge. Called once, by the vault package, as it initializes.
     *
     * @param value the bridge
     * @throws IllegalArgumentException if {@code value} is not the library's own vault bridge, loaded by this
     *     class's loader; nothing is installed
     * @throws IllegalStateException if a bridge is already installed
     * @since 1.0.0
     */
    public static synchronized void install(Bridge value) {
        Objects.requireNonNull(value, "bridge");
        Class<?> type = value.getClass();
        if (!type.getName().equals(BRIDGE_CLASS) || type.getClassLoader() != VaultAccess.class.getClassLoader()) {
            throw new IllegalArgumentException("not the library's vault bridge");
        }
        if (bridge != null) {
            throw new IllegalStateException("vault bridge already installed");
        }
        bridge = value;
    }

    /**
     * Returns the bridge, initializing the vault package first when nothing has yet.
     *
     * @return the installed bridge
     * @since 1.0.0
     */
    public static Bridge bridge() {
        try {
            Class.forName(VaultHosts.class.getName(), true, VaultAccess.class.getClassLoader());
        } catch (ClassNotFoundException impossible) {
            throw new IllegalStateException("vault package unavailable", impossible);
        }
        return Objects.requireNonNull(bridge, "vault bridge not installed");
    }

    /**
     * The runtime's way into the vault package.
     *
     * @since 1.0.0
     */
    public interface Bridge {

        /**
         * Builds the runtime's vault entry on its transport, with a token cache of its own.
         *
         * @param transport the runtime's transport
         * @param addresses maps a host locator to the base URL it is reached at, or {@code null} for {@code
         *     https://<locator>}
         * @return the vault entry
         */
        VaultHosts hosts(HttpTransport transport, Function<String, URI> addresses);

        /**
         * Closes the vault entry: drops every cached token.
         *
         * @param hosts the vault entry
         */
        void close(VaultHosts hosts);
    }
}

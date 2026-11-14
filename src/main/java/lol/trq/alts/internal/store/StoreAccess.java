package lol.trq.alts.internal.store;

import java.nio.file.Path;
import java.util.Objects;
import lol.trq.alts.spi.StoreKeyProvider;
import lol.trq.alts.store.AccountStore;
import lol.trq.alts.store.HostSecrets;

/**
 * How the runtime opens and closes its stores without either operation being public on the store types.
 * The store package installs the one {@link Bridge} when its types initialize, and {@link #install}
 * accepts no other: only the library's own bridge class, loaded by this class's own loader, and only
 * once. Not part of the library's API: a host gets its stores from {@code AltsRuntime#store()} and
 * {@code AltsRuntime#secrets()}, and closes them by closing the runtime.
 *
 * <p>Known limit, on the class path only: the module does not export this package, so on the module path
 * nothing outside the library can reach it, but on the class path a descriptor restricts nothing, and code
 * there can still call {@link #bridge()} and close or open a store through it. It cannot substitute a bridge
 * of its own: the sealed jar refuses a split package, and only the library's own bridge class from the
 * library's class loader installs, so it never sees a key provider or a store the library did not open.
 *
 * @author trq
 * @since 1.0.0
 */
public final class StoreAccess {

    /** The one class whose instance {@link #install} accepts. */
    private static final String BRIDGE_CLASS = "lol.trq.alts.store.StoreBridge";

    private static volatile Bridge bridge;

    private StoreAccess() {}

    /**
     * Installs the bridge. Called once, by the store package, as it initializes.
     *
     * @param value the bridge
     * @throws IllegalArgumentException if {@code value} is not the library's own store bridge, loaded by
     *     this class's loader; nothing is installed
     * @throws IllegalStateException if a bridge is already installed
     * @since 1.0.0
     */
    public static synchronized void install(Bridge value) {
        Objects.requireNonNull(value, "bridge");
        // Checked before anything else, and whatever has been installed: a bridge sees every key provider
        // and every store the runtime opens, so only the store package's own may ever be the one.
        Class<?> type = value.getClass();
        if (!type.getName().equals(BRIDGE_CLASS) || type.getClassLoader() != StoreAccess.class.getClassLoader()) {
            throw new IllegalArgumentException("not the library's store bridge");
        }
        if (bridge != null) {
            throw new IllegalStateException("store bridge already installed");
        }
        bridge = value;
    }

    /**
     * Returns the bridge, initializing the store package first when nothing has yet.
     *
     * @return the installed bridge
     * @since 1.0.0
     */
    public static Bridge bridge() {
        // Always, not only when nothing is installed yet: initializing the store package is what installs
        // the library's bridge, and it must have had the chance to before the field is read.
        try {
            Class.forName(AccountStore.class.getName(), true, StoreAccess.class.getClassLoader());
        } catch (ClassNotFoundException impossible) {
            throw new IllegalStateException("store package unavailable", impossible);
        }
        return Objects.requireNonNull(bridge, "store bridge not installed");
    }

    /**
     * The runtime's way into the store package.
     *
     * @since 1.0.0
     */
    public interface Bridge {

        /**
         * Opens and locks an account store with the coalesced write delay a runtime uses. Nothing is read.
         *
         * @param directory the store directory; created when missing
         * @param fileName the filename, or null/blank for the default
         * @param keyBinding the key-binding constant, or null/blank for the default
         * @param keyProvider the host key provider, or null for the machine-derived key
         * @param migrateFromMachineKey whether a file from before the key provider may be resealed
         * @return the open store
         * @throws lol.trq.alts.AltsException of kind {@code CONFLICT} when the file is in use by another owner, or
         *     {@code STORAGE} when it cannot be locked
         */
        AccountStore openAccounts(
                Path directory,
                String fileName,
                String keyBinding,
                StoreKeyProvider keyProvider,
                boolean migrateFromMachineKey);

        /**
         * Opens and locks the host secrets with the coalesced write delay a runtime uses. Nothing is read.
         *
         * @param directory the store directory; created when missing
         * @param fileName the filename, or null/blank for the default
         * @param keyBinding the key-binding constant, or null/blank for the default
         * @param keyProvider the host key provider, or null for the machine-derived key
         * @param migrateFromMachineKey whether a file from before the key provider may be resealed
         * @return the open store
         * @throws lol.trq.alts.AltsException of kind {@code CONFLICT} when the file is in use by another owner, or
         *     {@code STORAGE} when it cannot be locked
         */
        HostSecrets openSecrets(
                Path directory,
                String fileName,
                String keyBinding,
                StoreKeyProvider keyProvider,
                boolean migrateFromMachineKey);

        /**
         * Flushes and closes an account store, releasing its lock. Idempotent.
         *
         * @param store the store
         */
        void close(AccountStore store);

        /**
         * Flushes and closes the host secrets, releasing their lock. Idempotent.
         *
         * @param secrets the secrets
         */
        void close(HostSecrets secrets);
    }
}

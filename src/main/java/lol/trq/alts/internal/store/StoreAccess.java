package lol.trq.alts.internal.store;

import java.nio.file.Path;
import java.util.Objects;
import lol.trq.alts.spi.StoreKeyProvider;
import lol.trq.alts.store.AccountStore;
import lol.trq.alts.store.HostSecrets;

/**
 * How the runtime opens and closes its stores without either operation being public on the store types.
 * The store package installs the one {@link Bridge} when its types initialize; nothing else does. Not
 * part of the library's API: a host gets its stores from {@code AltsRuntime#store()} and
 * {@code AltsRuntime#secrets()}, and closes them by closing the runtime.
 *
 * @author trq
 * @since 1.0.0
 */
public final class StoreAccess {

    private static volatile Bridge bridge;

    private StoreAccess() {}

    /**
     * Installs the bridge. Called once, by the store package.
     *
     * @param value the bridge
     * @throws IllegalStateException if a bridge is already installed
     * @since 1.0.0
     */
    public static synchronized void install(Bridge value) {
        Objects.requireNonNull(value, "bridge");
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
        Bridge installed = bridge;
        if (installed == null) {
            try {
                Class.forName(AccountStore.class.getName(), true, AccountStore.class.getClassLoader());
            } catch (ClassNotFoundException impossible) {
                throw new IllegalStateException("store package unavailable", impossible);
            }
            installed = bridge;
        }
        return Objects.requireNonNull(installed, "store bridge not installed");
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
         * @throws IllegalStateException when the file is in use by another owner or cannot be locked
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
         * @throws IllegalStateException when the file is in use by another owner or cannot be locked
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

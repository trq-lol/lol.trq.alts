package lol.trq.alts.store;

import java.nio.file.Path;
import java.util.Optional;
import java.util.function.UnaryOperator;
import lol.trq.alts.internal.store.StoreAccess;
import lol.trq.alts.internal.store.StoreFile;
import lol.trq.alts.model.AltAccount;
import lol.trq.alts.spi.StoreKeyProvider;

/**
 * The store package's side of {@link StoreAccess}: the runtime opens and closes stores through it, so
 * the factories and {@code close()} stay package-private. Installed exactly once, when this class
 * initializes, which either store type triggers from its own initializer.
 *
 * @author trq
 * @since 1.0.0
 */
final class StoreBridge implements StoreAccess.Bridge {

    static {
        StoreAccess.install(new StoreBridge());
    }

    private StoreBridge() {}

    /** Initializes this class, and with it the bridge; repeat calls do nothing. */
    static void install() {
        // The static initializer above does the work.
    }

    @Override
    public AccountStore openAccounts(
            Path directory,
            String fileName,
            String keyBinding,
            StoreKeyProvider keyProvider,
            boolean migrateFromMachineKey) {
        return AccountStore.open(
                directory, fileName, keyBinding, keyProvider, migrateFromMachineKey, StoreFile.DEFAULT_WRITE_DELAY);
    }

    @Override
    public HostSecrets openSecrets(
            Path directory,
            String fileName,
            String keyBinding,
            StoreKeyProvider keyProvider,
            boolean migrateFromMachineKey) {
        return HostSecrets.open(
                directory, fileName, keyBinding, keyProvider, migrateFromMachineKey, StoreFile.DEFAULT_WRITE_DELAY);
    }

    @Override
    public Optional<AltAccount> update(AccountStore store, String uuid, UnaryOperator<AltAccount> change) {
        return store.update(uuid, change);
    }

    @Override
    public void close(AccountStore store) {
        store.close();
    }

    @Override
    public void close(HostSecrets secrets) {
        secrets.close();
    }
}

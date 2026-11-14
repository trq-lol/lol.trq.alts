package lol.trq.alts.vault;

import java.net.URI;
import java.util.function.Function;
import lol.trq.alts.internal.vault.VaultAccess;
import lol.trq.alts.net.HttpTransport;

/**
 * The vault package's side of {@link VaultAccess}: the runtime builds and closes its {@link VaultHosts}
 * through it, so the type needs no public constructor. Installed exactly once, when {@link VaultHosts}
 * initializes.
 *
 * @author trq
 * @since 1.0.0
 */
final class VaultBridge implements VaultAccess.Bridge {

    static {
        VaultAccess.install(new VaultBridge());
    }

    private VaultBridge() {}

    /** Initializes this class, and with it the bridge; repeat calls do nothing. */
    static void install() {
        // The static initializer above does the work.
    }

    @Override
    public VaultHosts hosts(HttpTransport transport, Function<String, URI> addresses) {
        return new VaultHosts(transport, addresses, System::currentTimeMillis);
    }

    @Override
    public void close(VaultHosts hosts) {
        hosts.close();
    }
}

package lol.trq.alts.vault;

import java.util.Objects;
import java.util.function.LongSupplier;
import lol.trq.alts.internal.avp.AvpBytes;
import lol.trq.alts.internal.vault.HostClient;

/**
 * A connection to one AVP host, matched by its host key (AVP SPEC 3.3, 11.7), on the runtime's transport. A
 * member device syncs through one such host, its home host. Built only by {@link VaultHosts}, which a
 * runtime hands out as {@code alts.vault()}.
 *
 * <p>Every request goes through the runtime's transport, so its proxy, timeouts and header rules apply, under
 * the {@code VAULT} purpose. Bearer tokens are minted by the challenge of SPEC 3.3, signed over the
 * transcript for this host's key, and cached by the runtime under that key and this host's address, so a
 * token is never sent to another host. The connection holds no secret of its own.
 *
 * @author trq
 * @since 1.0.0
 */
public final class VaultHost {

    private final HostClient client;
    private final LongSupplier clock;

    VaultHost(HostClient client, LongSupplier clock) {
        this.client = Objects.requireNonNull(client, "client");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * The key this host was matched by, base64.
     *
     * @return the host key
     * @since 1.0.0
     */
    public String hostKey() {
        return AvpBytes.base64(client.key());
    }

    /**
     * Where this host is reached, {@code host} or {@code host:port}: the hint that travels beside the key in
     * a manifest's hosts and in tokens.
     *
     * @return the locator
     * @since 1.0.0
     */
    public String locator() {
        return client.locator();
    }

    /**
     * This host as a manifest names it.
     *
     * @return the host's key and locator
     * @since 1.0.0
     */
    public HostRef ref() {
        return new HostRef(hostKey(), locator());
    }

    HostClient client() {
        return client;
    }

    LongSupplier clock() {
        return clock;
    }

    /**
     * The locator and the key.
     *
     * @return a description
     */
    @Override
    public String toString() {
        return "VaultHost[" + locator() + ", " + hostKey() + "]";
    }
}

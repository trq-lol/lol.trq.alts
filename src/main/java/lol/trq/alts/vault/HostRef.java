package lol.trq.alts.vault;

import java.util.Objects;
import lol.trq.alts.internal.avp.AvpBytes;
import lol.trq.alts.internal.avp.Manifest;

/**
 * One host of a repository as the latest verified manifest state lists it (AVP SPEC 4.2): its key, the
 * host's identity, and its locator, where it is reached. Connect to it by key with {@link
 * VaultHosts#connect(HostRef)}.
 *
 * @author trq
 * @since 1.0.0
 */
public final class HostRef {

    private final String hostKey;
    private final String locator;

    HostRef(String hostKey, String locator) {
        this.hostKey = hostKey;
        this.locator = locator;
    }

    static HostRef of(Manifest.HostRef ref) {
        return new HostRef(AvpBytes.base64(ref.hostKey()), ref.locator());
    }

    /**
     * The host key, base64.
     *
     * @return the key
     * @since 1.0.0
     */
    public String hostKey() {
        return hostKey;
    }

    /**
     * Where the host is reached, {@code host} or {@code host:port}.
     *
     * @return the locator
     * @since 1.0.0
     */
    public String locator() {
        return locator;
    }

    /**
     * Whether {@code o} names the same key at the same locator.
     *
     * @param o the other object
     * @return whether they are equal
     * @since 1.0.0
     */
    @Override
    public boolean equals(Object o) {
        return o instanceof HostRef h && hostKey.equals(h.hostKey) && locator.equals(h.locator);
    }

    /**
     * Hashes what {@link #equals(Object)} compares.
     *
     * @return the hash
     * @since 1.0.0
     */
    @Override
    public int hashCode() {
        return Objects.hash(hostKey, locator);
    }

    /**
     * The locator and the key.
     *
     * @return a description
     * @since 1.0.0
     */
    @Override
    public String toString() {
        return "HostRef[" + locator + ", " + hostKey + "]";
    }
}

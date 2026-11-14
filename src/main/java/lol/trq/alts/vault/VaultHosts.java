package lol.trq.alts.vault;

import java.net.URI;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;
import java.util.function.LongSupplier;
import java.util.regex.Pattern;
import lol.trq.alts.AltsException;
import lol.trq.alts.internal.avp.AvpBytes;
import lol.trq.alts.internal.net.HttpTransport;
import lol.trq.alts.internal.vault.HostClient;
import lol.trq.alts.internal.vault.TokenCache;

/**
 * The runtime's way to AVP hosts: {@code alts.vault()}. Each {@code connect} reaches a host by its locator,
 * learns its key from discovery ({@code GET /.well-known/avp}, SPEC 11.7) and, whenever the key is known
 * beforehand, refuses a host that serves another one. Pass the known key every time there is one: discovery is
 * unauthenticated, so a host reached by its locator alone is whoever answers there, and the key is what
 * identifies a host (SPEC 3.3). The forms that take a {@link RepoLocator}, a {@link HostRef}, a {@link
 * VaultSnapshot} or an explicit key all pass it; {@link #connectFirstContact(String)} is the first contact
 * with a host whose key nobody vouched for yet. A vault opened through any connection still requires the verified
 * manifest state to list that host's key, and the member's home host to be that key.
 *
 * <p>A locator ({@code host} or {@code host:port}) is reached at {@code https://<locator>} unless the host
 * set another mapping with {@code AltsRuntime.Builder#vaultHostAddress}. Every connection shares the
 * runtime's transport and its token cache, which {@code AltsRuntime#close()} clears.
 *
 * <p>Every future fails only with an {@link AltsException}: {@code PROTOCOL} for a host that serves no key
 * or another key than expected, {@code INVALID_INPUT} for a locator that is not {@code host} or {@code
 * host:port} or a mapping that gives no {@code http} or {@code https} URL, {@code NETWORK} for a host that
 * cannot be reached, and {@code CANCELLED} once the runtime is closed.
 *
 * @author trq
 * @since 1.0.0
 */
public final class VaultHosts {

    static {
        VaultBridge.install();
    }

    /** {@code host} or {@code host:port}: a DNS name, an IPv4 address or a bracketed IPv6 address. */
    private static final Pattern LOCATOR = Pattern.compile("(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
            + "(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*|\\[[0-9A-Fa-f:.]+\\])(?::[0-9]{1,5})?");

    private final HttpTransport transport;
    private final Function<String, URI> addresses;
    private final LongSupplier clock;
    private final TokenCache tokens = new TokenCache();

    VaultHosts(HttpTransport transport, Function<String, URI> addresses, LongSupplier clock) {
        this.transport = Objects.requireNonNull(transport, "transport");
        this.addresses = addresses != null ? addresses : VaultHosts::https;
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * The default mapping: {@code https://<locator>}.
     *
     * @param locator the locator
     * @return the base URL
     */
    static URI https(String locator) {
        return URI.create("https://" + locator);
    }

    /**
     * Connects to the owner's home host named by a repo locator, by the key it carries.
     *
     * @param locator the owner's repo locator
     * @return the connection
     * @since 1.0.0
     */
    public CompletableFuture<VaultHost> connect(RepoLocator locator) {
        Objects.requireNonNull(locator, "locator");
        return connect(locator.hostLocator(), locator.token().hostKey());
    }

    /**
     * Connects to a host of a repository, by its key.
     *
     * @param host a host from {@link SharedVault#hosts()}
     * @return the connection
     * @since 1.0.0
     */
    public CompletableFuture<VaultHost> connect(HostRef host) {
        Objects.requireNonNull(host, "host");
        return connect(host.locator(), host.hostKey());
    }

    /**
     * Connects to the home host a snapshot names, by its key: the connection {@link SharedVault#resume} needs.
     *
     * @param snapshot the persisted snapshot
     * @return the connection
     * @since 1.0.0
     */
    public CompletableFuture<VaultHost> connect(VaultSnapshot snapshot) {
        Objects.requireNonNull(snapshot, "snapshot");
        return connect(snapshot.homeHost());
    }

    /**
     * Connects to a host whose key is known from elsewhere, for example from the host's own published key.
     *
     * @param locator {@code host} or {@code host:port}
     * @param hostKey the host key the host must serve, base64
     * @return the connection
     * @since 1.0.0
     */
    public CompletableFuture<VaultHost> connect(String locator, String hostKey) {
        Objects.requireNonNull(locator, "locator");
        Objects.requireNonNull(hostKey, "hostKey");
        byte[] key;
        try {
            key = AvpBytes.fromBase64(hostKey.strip(), 32, "the host key");
        } catch (AltsException malformed) {
            return VaultFutures.failed(VaultFutures.invalid("a host key is 32 bytes of base64"));
        }
        return connect(locator, key);
    }

    /**
     * Connects to a host by its locator alone, taking whatever key its discovery serves: the first contact
     * with a host nobody vouched for, such as the home host an owner creates a repository on or the one a
     * joiner picks for itself. Discovery is unauthenticated, so the resulting {@link VaultHost#hostKey()} is
     * unverified: show it to the user or compare it out of band with the key the host publishes before
     * trusting it. Persist {@link VaultHost#ref()} and reconnect later with {@link #connect(HostRef)} or
     * {@link #connect(String, String)}, which pin that key; prefer a form that passes a known key whenever one
     * exists.
     *
     * @param locator {@code host} or {@code host:port}
     * @return the connection
     * @since 1.0.0
     */
    public CompletableFuture<VaultHost> connectFirstContact(String locator) {
        Objects.requireNonNull(locator, "locator");
        return connect(locator, (byte[]) null);
    }

    private CompletableFuture<VaultHost> connect(String locator, byte[] expectedKey) {
        String where = locator.strip();
        if (!LOCATOR.matcher(where).matches()) {
            return VaultFutures.failed(VaultFutures.invalid("a host locator is host or host:port"));
        }
        URI base;
        try {
            base = addresses.apply(where);
        } catch (RuntimeException unmappable) {
            return VaultFutures.failed(VaultFutures.invalid("the host locator has no address"));
        }
        if (base == null) {
            return VaultFutures.failed(VaultFutures.invalid("the host locator has no address"));
        }
        return VaultFutures.async(
                transport.executor(),
                () -> new VaultHost(HostClient.connect(transport, base, where, expectedKey, tokens, clock), clock));
    }

    /** Drops every cached token; the runtime calls it as it closes. */
    void close() {
        tokens.clear();
    }

    /**
     * Counts only.
     *
     * @return a description
     */
    @Override
    public String toString() {
        return "VaultHosts[" + tokens + "]";
    }
}

package lol.trq.alts;

import java.net.URI;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;
import lol.trq.alts.account.AccountEndpoints;
import lol.trq.alts.account.AccountServices;
import lol.trq.alts.account.ProfileLookupService;
import lol.trq.alts.auth.AltAccountService;
import lol.trq.alts.auth.AltLoginService;
import lol.trq.alts.auth.AltLoginServiceImpl;
import lol.trq.alts.auth.MicrosoftAuthConfig;
import lol.trq.alts.bulk.BulkOperations;
import lol.trq.alts.bulk.BulkOperationsImpl;
import lol.trq.alts.cache.AsyncCache;
import lol.trq.alts.internal.account.AccountAccess;
import lol.trq.alts.internal.skin.MojangAvatarSource;
import lol.trq.alts.internal.skin.SkinAccess;
import lol.trq.alts.internal.skin.UrlTemplateAvatarSource;
import lol.trq.alts.internal.store.StoreAccess;
import lol.trq.alts.internal.vault.VaultAccess;
import lol.trq.alts.model.AltAccount;
import lol.trq.alts.model.GameStats;
import lol.trq.alts.net.HttpTransport;
import lol.trq.alts.skin.SkinAvatarCache;
import lol.trq.alts.spi.AvatarSource;
import lol.trq.alts.spi.GameStatsSource;
import lol.trq.alts.spi.MainThreadExecutor;
import lol.trq.alts.spi.ProxyProvider;
import lol.trq.alts.spi.SessionInjector;
import lol.trq.alts.spi.StoreKeyProvider;
import lol.trq.alts.spi.TextureUploader;
import lol.trq.alts.spi.ToastSink;
import lol.trq.alts.spi.VaultDirectoryProvider;
import lol.trq.alts.spi.VaultTransportResolver;
import lol.trq.alts.store.AccountStore;
import lol.trq.alts.store.HostSecrets;
import lol.trq.alts.vault.VaultHosts;

/**
 * Central wiring object for the consumer-agnostic account library. The host supplies its platform
 * seams through {@link Builder}; the library exposes an {@link AltLoginService}, a generic
 * {@link SkinAvatarCache}, and the runtime's own {@link AccountStore} and {@link HostSecrets}.
 *
 * <p>Build it during host initialization, before any alt screen opens. Each runtime owns its stores:
 * two runtimes in one process, on two directories, never see each other's accounts or secrets. Two
 * runtimes cannot share a store file; the second one's {@link Builder#build()} fails.
 *
 * <p>A runtime holds a lock on each store file for as long as it is open, so a host closes it when done
 * with it, ideally with try-with-resources. {@link #close()} writes what is still waiting and releases
 * the files. A host that never closes it loses nothing on a normal exit: a shutdown hook flushes the
 * stores.
 *
 * @param <H> the host's opaque texture-handle type (for example a NanoVG image handle)
 * @author trq
 * @since 0.1.0
 */
public final class AltsRuntime<H> implements AutoCloseable {

    /** How long a fetched game-stats snapshot stays fresh before a background refresh. */
    private static final long STATS_TTL_MILLIS = 5 * 60 * 1000L;

    private final AltLoginServiceImpl loginService;
    private final BulkOperations bulk;
    private final AccountEndpoints accountEndpoints;
    private final AccountAccess.Bridge accountAccess;
    private final ProfileLookupService profileLookup;
    private final SkinAvatarCache<H> skinCache;
    private final Map<String, AsyncCache<String, GameStats>> gameStatsCaches;
    private final AsyncCache<String, GameStats> emptyStatsCache;
    private final ToastSink toasts;
    private final VaultTransportResolver vaultResolver;
    private final VaultAccess.Bridge vaultAccess;
    private final VaultHosts vault;
    private final StoreAccess.Bridge stores;
    private final AccountStore store;
    private final HostSecrets secrets;
    private final HttpTransport transport;
    private final ExecutorService ownedExecutor;
    private final AtomicBoolean closed = new AtomicBoolean();

    private AltsRuntime(Builder<H> builder) {
        Objects.requireNonNull(builder.sessionInjector, "SessionInjector required");
        Objects.requireNonNull(builder.vaultDirectory, "VaultDirectoryProvider required");
        Objects.requireNonNull(builder.mainThread, "MainThreadExecutor required");
        Objects.requireNonNull(builder.toastSink, "ToastSink required");

        // The stores come first: opening one is the step that can be refused (another runtime holds the
        // file), and a refused build must leave nothing of its own behind: no lock, no executor.
        //
        // Each store is opened with its key, its directory and its lock in one step, so nothing can be
        // written under another key, and a second runtime on the same files fails here rather than
        // corrupting them later. When the second lock is refused, the first is released again: a build
        // that fails holds nothing. Coalescing keeps a burst of logins from writing the file once each.
        Path directory = Objects.requireNonNull(builder.vaultDirectory.vaultDirectory(), "vaultDirectory");
        this.stores = StoreAccess.bridge();
        this.store = stores.openAccounts(
                directory,
                builder.storeFileName,
                builder.storeKeyBinding,
                builder.storeKeyProvider,
                builder.migrateFromMachineKey);
        try {
            this.secrets = stores.openSecrets(
                    directory,
                    builder.secretsFileName,
                    builder.secretsKeyBinding,
                    builder.storeKeyProvider,
                    builder.migrateFromMachineKey);
        } catch (RuntimeException | Error refused) {
            stores.close(store);
            throw refused;
        }

        // The executor and the transport are this runtime's own. A host's executor is used and left alone;
        // one the library creates here is the runtime's to shut down.
        this.ownedExecutor = builder.executor == null
                ? Executors.newThreadPerTaskExecutor(
                        Thread.ofVirtual().name("alts-io-", 0).factory())
                : null;
        Executor executor = builder.executor != null ? builder.executor : ownedExecutor;
        this.transport = new HttpTransport(builder.proxyProvider, executor);

        try {
            // Read what is already on disk here, so a host never has to know that opening and loading
            // are two steps. Both are safe to repeat: each clears its in-memory state before refilling it.
            store.load();
            secrets.load();
            if (builder.afterStoresOpen != null) {
                builder.afterStoresOpen.run();
            }

            this.toasts = builder.toastSink;
            this.vaultResolver = builder.vaultTransportResolver;
            this.vaultAccess = VaultAccess.bridge();
            this.vault = vaultAccess.hosts(transport, builder.vaultHostAddress);
            this.loginService =
                    new AltLoginServiceImpl(store, builder.sessionInjector, builder.microsoftAuth, transport);

            // The account services talk to the same host the auth chain validates against, so a host that
            // fronts Minecraft services with a proxy — overriding the profile URL — reaches them through the
            // same origin rather than needing a second override.
            this.accountEndpoints = builder.accountEndpoints != null
                    ? builder.accountEndpoints
                    : accountEndpointsFrom(builder.microsoftAuth);
            this.accountAccess = AccountAccess.bridge();
            this.profileLookup = accountAccess.profileLookup(transport, accountEndpoints);

            // The import runs resolve and store through a login service whose injector does nothing, which
            // is what keeps importing fifty credentials from switching session fifty times.
            this.bulk = new BulkOperationsImpl(
                    store,
                    new AltLoginServiceImpl(store, session -> {}, builder.microsoftAuth, transport),
                    loginService.accountService(),
                    account -> accountServices(account).entitlements(),
                    transport);
            this.skinCache = SkinAccess.bridge()
                    .cache(avatarSourceFrom(builder, transport), builder.textureUploader, builder.mainThread, executor);

            // Game stats are optional and per-server: one cache per registered source. A request for a
            // server with no source returns the shared empty cache, whose loader always yields null, so
            // callers degrade gracefully.
            Map<String, AsyncCache<String, GameStats>> caches = new LinkedHashMap<>();
            for (Map.Entry<String, GameStatsSource> entry : builder.gameStatsSources.entrySet()) {
                GameStatsSource source = entry.getValue();
                caches.put(
                        entry.getKey(),
                        new AsyncCache<>(
                                executor,
                                uuid -> {
                                    try {
                                        return source.fetch(uuid);
                                    } catch (Exception e) {
                                        return null;
                                    }
                                },
                                STATS_TTL_MILLIS));
            }
            this.gameStatsCaches = Map.copyOf(caches);
            this.emptyStatsCache = new AsyncCache<>(executor, uuid -> null, STATS_TTL_MILLIS);
        } catch (RuntimeException | Error failed) {
            transport.close();
            if (ownedExecutor != null) {
                ownedExecutor.shutdown();
            }
            stores.close(secrets);
            stores.close(store);
            throw failed;
        }
    }

    /**
     * Chooses the avatar source: the host's own, else the URL template the host opted into, else the
     * default that crops the face from Mojang's skin.
     *
     * @param builder the builder
     * @param transport the runtime's transport, which the library's own sources fetch through
     * @return the avatar source
     * @throws IllegalStateException if both a source and a template were set
     * @throws IllegalArgumentException if the template has no {@code {uuid}} placeholder
     */
    private static AvatarSource avatarSourceFrom(Builder<?> builder, HttpTransport transport) {
        if (builder.avatarSource != null && builder.avatarUrlTemplate != null) {
            throw new IllegalStateException("set an avatar source or an avatar URL template, not both");
        }
        if (builder.avatarSource != null) {
            return builder.avatarSource;
        }
        if (builder.avatarUrlTemplate != null) {
            return new UrlTemplateAvatarSource(transport, builder.avatarUrlTemplate);
        }
        return new MojangAvatarSource(transport);
    }

    /**
     * Derives the account-services base from the configured profile URL, so the two reach the same
     * origin. The profile URL ends {@code /minecraft/profile}; stripping that leaves the base. When
     * Microsoft login is unconfigured, the public default is used.
     *
     * @param config the Microsoft auth config, or null
     * @return the account endpoints
     */
    private static AccountEndpoints accountEndpointsFrom(MicrosoftAuthConfig config) {
        String profileUrl =
                config != null ? config.minecraftProfileUrl() : MicrosoftAuthConfig.DEFAULT_MINECRAFT_PROFILE_URL;
        String suffix = "/minecraft/profile";
        String base = profileUrl.endsWith(suffix)
                ? profileUrl.substring(0, profileUrl.length() - suffix.length())
                : profileUrl;
        return new AccountEndpoints(base);
    }

    /**
     * Returns this runtime's account store: the saved accounts, the current account, and the encrypted
     * file behind them. It was loaded from disk by {@link Builder#build()}.
     *
     * @return the account store
     * @since 1.0.0
     */
    public AccountStore store() {
        return store;
    }

    /**
     * Returns this runtime's host secrets: the per-user key/value secrets kept apart from the accounts.
     * They were loaded from disk by {@link Builder#build()}.
     *
     * @return the host secrets
     * @since 1.0.0
     */
    public HostSecrets secrets() {
        return secrets;
    }

    /**
     * Closes the runtime: writes both stores' pending changes, releases their file locks, and stops
     * their background writers and the shutdown hooks that would otherwise flush them at exit; closes the
     * transport's pooled proxy tunnels; and shuts down the executor if the library created it. An
     * executor the host passed to {@link Builder#executor(Executor)} is left running. Idempotent; a
     * second call does nothing. Once this returns, another runtime may open the same directory.
     *
     * <p>Afterwards the stores write nothing. Their contents stay readable; a mutator still changes the
     * store in memory but records "the store is closed" on {@code saveError()} instead of writing, and
     * {@code load()} reads nothing. The transport refuses every request made from then on, and a
     * library-created executor refuses new tasks while letting running ones finish, so a sign-in still in
     * flight when the runtime closes resolves, as a failure if it still had a request to make, and what
     * it would have saved is not saved.
     *
     * <p>Whatever was waiting on the runtime ends here too: a bulk run paced between entries, a
     * device-code sign-in between polls, a scheduled name claim, a browser sign-in waiting for its
     * callback. Each such wait fails on the thread that calls {@code close()}, and so do the callbacks
     * chained onto it: a bulk run's {@code BulkProgress.finished} and the completion of its report, and
     * whatever a sign-in's future runs as it fails, including continuations the host attached to it. A
     * host that calls {@code close()} from its main thread should expect that work there, and must not
     * block in such a callback on something only {@code close()} would release.
     *
     * <p>The vault's cached host tokens are dropped, and a vault operation still in flight fails with
     * {@link AltsFailure.Kind#CANCELLED} at its next request.
     *
     * <p>A wait that was due far in the future, such as a claim scheduled hours ahead, is failed at
     * once, but the JDK keeps the small task that would have woken it queued in its own delay scheduler
     * until its original time; that task then does nothing.
     *
     * @since 1.0.0
     */
    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        try {
            stores.close(store);
        } finally {
            try {
                stores.close(secrets);
            } finally {
                try {
                    vaultAccess.close(vault);
                    transport.close();
                } finally {
                    if (ownedExecutor != null) {
                        ownedExecutor.shutdown();
                    }
                }
            }
        }
    }

    /**
     * Returns the login service callers use to authenticate accounts.
     *
     * @return the login service
     */
    public AltLoginService loginService() {
        return loginService;
    }

    /**
     * Returns the account service, for validating or renewing a stored account without installing it as
     * the live session. A host sweeping every alt it holds wants this rather than
     * {@link AltLoginService#loginAccount}, which would switch session once per account.
     *
     * @return the account service
     * @since 0.8.0
     */
    public AltAccountService accountService() {
        return loginService.accountService();
    }

    /**
     * Returns the full account-management surface for one account — profile, entitlements, name, skin,
     * cape — built over its access token. For operating on an account you hold a live token for; nothing
     * here installs a session.
     *
     * @param account the account to operate on
     * @return the account services
     * @since 1.0.0
     */
    public AccountServices accountServices(AltAccount account) {
        return accountAccess.services(transport, account.accessToken(), account.uuid(), accountEndpoints);
    }

    /**
     * Returns the account-management surface for a bare access token, when the caller holds a token
     * rather than a stored {@link AltAccount}.
     *
     * @param accessToken the Minecraft access token
     * @param accountUuid the account UUID for request routing, or null
     * @return the account services
     * @since 1.0.0
     */
    public AccountServices accountServices(String accessToken, String accountUuid) {
        return accountAccess.services(transport, accessToken, accountUuid, accountEndpoints);
    }

    /**
     * Returns the public profile lookup — a player's name and UUID, by either — which needs no account
     * and sends no token.
     *
     * @return the profile lookup service
     * @since 0.12.0
     */
    public ProfileLookupService profileLookup() {
        return profileLookup;
    }

    /**
     * Returns the bulk surface, for running one operation over many accounts at a pace the service will
     * tolerate. Nothing it does installs a session.
     *
     * @return the bulk operations
     * @since 0.9.0
     */
    public BulkOperations bulk() {
        return bulk;
    }

    /**
     * Returns the avatar cache, generic over this host's texture-handle type. Keyed by UUID, so a
     * renamed account keeps its head.
     *
     * @return the skin avatar cache
     */
    public SkinAvatarCache<H> skinCache() {
        return skinCache;
    }

    /**
     * Returns the lazy, cached game-stats lookup for one server, keyed by player UUID. If no source was
     * registered for {@code serverId}, returns an empty cache that always yields {@code null}; a failed
     * fetch likewise surfaces as {@code null} from {@link AsyncCache#get(Object)}, so callers degrade
     * cleanly.
     *
     * @param serverId the server whose stats to look up (matches a registered source's id)
     * @return the per-server game-stats cache
     */
    public AsyncCache<String, GameStats> gameStats(String serverId) {
        AsyncCache<String, GameStats> cache = gameStatsCaches.get(serverId);
        return cache != null ? cache : emptyStatsCache;
    }

    /**
     * Returns the toast sink the host supplied, the one route for raising a notification. The library
     * keeps no static sink of its own.
     *
     * @return the toast sink
     */
    public ToastSink toasts() {
        return toasts;
    }

    /**
     * Returns the shared vault's way to AVP 0.5 hosts: it connects to a host on this runtime's transport (its
     * proxy provider, timeouts and executor), by the host's key, and caches the hosts' bearer tokens for this
     * runtime alone. Open a repository on a connection with {@link lol.trq.alts.vault.SharedVault}.
     *
     * @return the vault entry
     * @since 1.0.0
     */
    public VaultHosts vault() {
        return vault;
    }

    /**
     * Returns the host's vault transport resolver, or {@code null} when the host did not wire one (the
     * shared-vault feature is then unavailable). Maps an {@code avp://host} authority to a
     * {@link lol.trq.alts.vault.transport.VaultTransport} the host implements over its own network stack.
     *
     * @return the vault transport resolver, or null when unset
     * @since 0.6.1
     */
    public VaultTransportResolver vaultTransportResolver() {
        return vaultResolver;
    }

    /**
     * Accumulating builder that injects the host seams. Required seams are validated in {@link #build()},
     * never in the setters; setters use bare names (no {@code withX} prefixes).
     *
     * @param <H> the host's opaque texture-handle type
     * @author trq
     * @since 0.1.0
     */
    public static final class Builder<H> {

        private SessionInjector sessionInjector;
        private VaultDirectoryProvider vaultDirectory;
        private TextureUploader<H> textureUploader;
        private MainThreadExecutor mainThread;
        private ToastSink toastSink;
        private final Map<String, GameStatsSource> gameStatsSources = new LinkedHashMap<>();
        private MicrosoftAuthConfig microsoftAuth;
        private VaultTransportResolver vaultTransportResolver;
        private Function<String, URI> vaultHostAddress;
        private ProxyProvider proxyProvider;
        private AvatarSource avatarSource;
        private String avatarUrlTemplate;
        private AccountEndpoints accountEndpoints;
        private Executor executor;
        private String storeFileName;
        private String storeKeyBinding;
        private String secretsFileName;
        private String secretsKeyBinding;
        private StoreKeyProvider storeKeyProvider;
        private boolean migrateFromMachineKey;

        // A test seam: runs inside build() once both stores are open and loaded, so a test can make the
        // rest of construction fail and see that the stores are released. Package-private on purpose.
        private Runnable afterStoresOpen;

        /**
         * Sets a task that runs inside {@link #build()} once both stores are open. For tests only.
         *
         * @param task the task, or null for none
         * @return this builder
         */
        Builder<H> afterStoresOpenForTests(Runnable task) {
            this.afterStoresOpen = task;
            return this;
        }

        /** Creates an empty builder; populate it with the host seams, then call {@link #build()}. */
        public Builder() {}

        /**
         * Sets the session injector (required).
         *
         * @param value the host session injector
         * @return this builder
         */
        public Builder<H> sessionInjector(SessionInjector value) {
            this.sessionInjector = value;
            return this;
        }

        /**
         * Sets the vault directory provider (required). It is asked once, by {@link #build()}, and the
         * runtime's two store files live in that directory for the runtime's lifetime.
         *
         * @param value the host vault directory provider
         * @return this builder
         */
        public Builder<H> vaultDirectory(VaultDirectoryProvider value) {
            this.vaultDirectory = value;
            return this;
        }

        /**
         * Sets the texture uploader (optional; avatars degrade to the initial-letter fallback if absent).
         *
         * @param value the host texture uploader
         * @return this builder
         */
        public Builder<H> textureUploader(TextureUploader<H> value) {
            this.textureUploader = value;
            return this;
        }

        /**
         * Sets the main-thread executor (required).
         *
         * @param value the host main-thread executor
         * @return this builder
         */
        public Builder<H> mainThread(MainThreadExecutor value) {
            this.mainThread = value;
            return this;
        }

        /**
         * Sets the toast sink (required).
         *
         * @param value the host toast sink
         * @return this builder
         */
        public Builder<H> toastSink(ToastSink value) {
            this.toastSink = value;
            return this;
        }

        /**
         * Registers a game-stats source for one server (optional; callable once per server). Without any
         * source, {@link AltsRuntime#gameStats(String)} always returns null. The source's
         * {@link GameStatsSource#serverId()} is the key consumers pass to {@code gameStats(serverId)}.
         *
         * @param value the host game-stats source
         * @return this builder
         * @throws IllegalStateException if a source for the same server id was already registered
         */
        public Builder<H> gameStatsSource(GameStatsSource value) {
            Objects.requireNonNull(value, "gameStatsSource");
            String serverId = Objects.requireNonNull(value.serverId(), "serverId");
            if (gameStatsSources.putIfAbsent(serverId, value) != null) {
                throw new IllegalStateException("duplicate game-stats serverId: " + serverId);
            }
            return this;
        }

        /**
         * Sets the Microsoft authentication configuration (optional; without it Microsoft login fails
         * cleanly while offline / cookie / session login stay available). The {@code clientId} inside is
         * the host's own Azure app id — the library ships no default.
         *
         * @param value the host Microsoft authentication configuration
         * @return this builder
         */
        public Builder<H> microsoftAuth(MicrosoftAuthConfig value) {
            this.microsoftAuth = value;
            return this;
        }

        /**
         * Sets the vault transport resolver (optional; without it the shared-vault feature is
         * unavailable but every other surface works). The host maps an {@code avp://host} authority to a
         * {@link lol.trq.alts.vault.transport.VaultTransport} it implements over its own network stack
         * (HTTP, a gRPC tunnel, a test double).
         *
         * @param value the host vault transport resolver
         * @return this builder
         */
        public Builder<H> vaultTransportResolver(VaultTransportResolver value) {
            this.vaultTransportResolver = value;
            return this;
        }

        /**
         * Maps an AVP host locator ({@code host} or {@code host:port}, as tokens and manifests name a host) to
         * the base URL {@link AltsRuntime#vault()} reaches it at (optional; by default {@code
         * https://<locator>}). For a host that reaches vault hosts through a gateway, or a development host
         * served over plain {@code http} on a trusted network. The mapping never changes which host is
         * accepted: a host is matched by its key wherever it is reached, and a token is kept per host key and
         * address. A mapping that throws or returns null fails that connection with {@link
         * AltsFailure.Kind#INVALID_INPUT}.
         *
         * @param value the mapping, or null for the default
         * @return this builder
         * @since 1.0.0
         */
        public Builder<H> vaultHostAddress(Function<String, URI> value) {
            this.vaultHostAddress = value;
            return this;
        }

        /**
         * Sets the avatar source (optional; defaults to one that resolves the face from Mojang's session
         * server and crops it locally). A host that wants a head-render service instead can set
         * {@link #avatarUrlTemplate(String)} rather than implement this. Setting both fails
         * {@link #build()}.
         *
         * @param value the host avatar source
         * @return this builder
         * @since 0.10.0
         */
        public Builder<H> avatarSource(AvatarSource value) {
            this.avatarSource = value;
            return this;
        }

        /**
         * Fetches avatars from a head-render service by filling a URL template (optional; off by
         * default). The template holds a {@code {uuid}} placeholder and optionally {@code {size}}, for
         * example {@code https://example.net/avatar/{uuid}/{size}.png}; the UUID is passed as the caller
         * gave it. This is a deliberate trade: it discloses each account's UUID to that service on every
         * cache miss, which the default source exists to avoid. The fetch goes through the runtime's
         * transport, so the proxy provider sees it with purpose {@code AVATAR}. {@link #build()} fails
         * when the template has no {@code {uuid}} placeholder, or when an {@link #avatarSource} is also
         * set.
         *
         * @param value the URL template, or null for none
         * @return this builder
         * @since 1.0.0
         */
        public Builder<H> avatarUrlTemplate(String value) {
            this.avatarUrlTemplate = value;
            return this;
        }

        /**
         * Points the account services and the profile lookup at another base (optional; by default they
         * reach the origin of the configured {@link MicrosoftAuthConfig#minecraftProfileUrl()}, or the
         * public Minecraft services when Microsoft login is not configured). For a host that fronts the
         * Minecraft services with its own gateway, or a test pointing them at a loopback server.
         *
         * @param value the endpoints, or null for the default
         * @return this builder
         * @since 1.0.0
         */
        public Builder<H> accountEndpoints(AccountEndpoints value) {
            this.accountEndpoints = value;
            return this;
        }

        /**
         * Sets the proxy provider (optional; without one every request connects directly, as in every
         * release before this seam existed). The library asks it per request, so any rotation policy —
         * per-account pinning, round-robin, a health-checked pool — lives behind the host's
         * implementation.
         *
         * <p>Note that resolution fails closed when a provider is set: see {@link ProxyProvider}. The
         * provider belongs to this runtime and is fixed for its lifetime: every request this runtime makes
         * asks it, and no request of another runtime ever does. A runtime built without one connects
         * directly, whatever another runtime in the process was given.
         *
         * @param value the host proxy provider, or null for direct connections
         * @return this builder
         * @since 0.8.0
         */
        public Builder<H> proxyProvider(ProxyProvider value) {
            this.proxyProvider = value;
            return this;
        }

        /**
         * Sets the executor this runtime runs its blocking work on (optional; by default the runtime
         * creates one that starts a virtual thread per task, named {@code alts-io-<n>}, so a request
         * parked on a slow endpoint holds no platform thread). Install one to bound concurrency or to
         * propagate the host's own context. Every request, cache load, avatar download and bulk entry of
         * this runtime runs on it, and nothing of another runtime's does. The runtime never shuts a host's
         * executor down; one it created itself is shut down by {@link AltsRuntime#close()}.
         *
         * @param value the host executor, or null for one the runtime creates and owns
         * @return this builder
         * @since 0.12.0
         */
        public Builder<H> executor(Executor value) {
            this.executor = value;
            return this;
        }

        /**
         * Overrides the on-disk store filename (optional; defaults to a neutral name). Hosts migrating
         * from an earlier filename pass it here so existing files keep loading.
         *
         * @param value the store filename, or null/blank to keep the default
         * @return this builder
         */
        public Builder<H> storeFileName(String value) {
            this.storeFileName = value;
            return this;
        }

        /**
         * Overrides the key-binding constant mixed into the storage encryption key (optional; defaults
         * to a neutral constant). Hosts migrating from an earlier constant pass it here so existing
         * files keep decrypting. Changing it for an existing store renders prior files undecryptable.
         *
         * @param value the key-binding constant, or null/blank to keep the default
         * @return this builder
         */
        public Builder<H> storeKeyBinding(String value) {
            this.storeKeyBinding = value;
            return this;
        }

        /**
         * Overrides the on-disk secret-store filename (optional; defaults to a neutral name). The secret
         * store holds per-user secrets separately from the shareable account store.
         *
         * @param value the secret-store filename, or null/blank to keep the default
         * @return this builder
         */
        public Builder<H> secretsFileName(String value) {
            this.secretsFileName = value;
            return this;
        }

        /**
         * Overrides the key-binding constant mixed into the secret-store encryption key (optional;
         * defaults to a neutral constant). Changing it for an existing store renders prior secret files
         * undecryptable.
         *
         * @param value the secret-store key-binding constant, or null/blank to keep the default
         * @return this builder
         */
        public Builder<H> secretsKeyBinding(String value) {
            this.secretsKeyBinding = value;
            return this;
        }

        /**
         * Sets the store key provider (optional; without one both encrypted stores are sealed under a
         * key derived from machine properties, as in every release before this seam existed). A host
         * that can reach a real secret, such as an operating-system keystore entry, supplies it here.
         * A file written under a host key does not open without it, and a file written before the
         * provider was installed does not open under it either unless
         * {@link #migrateFromMachineKey(boolean)} is on for that launch.
         *
         * <p>Note that resolution fails closed once a provider is installed: see {@link StoreKeyProvider}.
         * The provider belongs to this runtime's stores alone and is fixed for their lifetime; another
         * runtime's provider never reaches them.
         *
         * @param value the host store key provider, or null for the machine-derived key
         * @return this builder
         * @since 0.12.0
         */
        public Builder<H> storeKeyProvider(StoreKeyProvider value) {
            this.storeKeyProvider = value;
            return this;
        }

        /**
         * Sets whether stores written before a {@link #storeKeyProvider} was installed are migrated to
         * it (optional; off by default). While on, a store that does not open under the host's key but
         * does under the machine-derived default is loaded and rewritten under the host's key, and
         * every kept copy of it, the rolling backup included, is resealed or removed, so that no file
         * left in the directory opens under the old key.
         *
         * <p>Enable it for the upgrade launch only — the one that first installs the key provider over
         * existing files — and leave it off from then on. While it is on, the machine-derived key is
         * still accepted, so anyone able to write the store directory can plant a store sealed under
         * that guessable key, or restore a copy from before the migration, and have it load. While it
         * is off, a file that does not open under the host's key is reported on
         * {@link AccountStore#loadError()} and left as it is. Has no effect without a key provider.
         *
         * @param value true to accept and reseal stores sealed under the machine-derived key
         * @return this builder
         * @since 0.12.0
         */
        public Builder<H> migrateFromMachineKey(boolean value) {
            this.migrateFromMachineKey = value;
            return this;
        }

        /**
         * Validates the required seams, constructs the runtime, opens and locks its two store files in
         * the directory the {@link #vaultDirectory} provider names (asked once, here), and loads them —
         * so {@link AltsRuntime#store()} is populated as soon as this returns. A file that exists but
         * cannot be read leaves the list alone and is reported on {@link AccountStore#loadError()}.
         * Whatever the reason (the {@link #storeKeyProvider} could not supply its key, the file is sealed
         * under another key, or it is damaged), nothing is written over that file until a later
         * {@link AccountStore#load()} succeeds or the host calls {@link AccountStore#discardUnreadable()}
         * (and the same on {@link HostSecrets}).
         *
         * <p>Each store file is locked for the runtime's lifetime. When another runtime, in this process
         * or another, holds either file, this fails with an {@link AltsException} of kind
         * {@link AltsFailure.Kind#CONFLICT} saying the store file is in use (the message names the file,
         * not its path) and holds no lock afterwards; a directory that cannot be created or locked fails
         * it with kind {@link AltsFailure.Kind#STORAGE}.
         *
         * @return the constructed runtime, which the host closes when done with it
         * @throws NullPointerException if a required seam is missing
         * @throws AltsException of kind {@link AltsFailure.Kind#CONFLICT} if a store file is in use by another
         *     runtime, or {@link AltsFailure.Kind#STORAGE} if one cannot be locked
         */
        public AltsRuntime<H> build() {
            return new AltsRuntime<>(this);
        }
    }
}

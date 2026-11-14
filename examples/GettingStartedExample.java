import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure;
import lol.trq.alts.AltsRuntime;
import lol.trq.alts.account.AccountServices;
import lol.trq.alts.account.ClaimOptions;
import lol.trq.alts.account.Entitlements;
import lol.trq.alts.account.NameAvailability;
import lol.trq.alts.account.NameChangeResult;
import lol.trq.alts.account.PlayerAttributes;
import lol.trq.alts.account.PlayerProfile;
import lol.trq.alts.account.PublicProfile;
import lol.trq.alts.auth.MicrosoftAuthConfig;
import lol.trq.alts.bulk.BulkEntryResult;
import lol.trq.alts.bulk.BulkHandle;
import lol.trq.alts.bulk.BulkOptions;
import lol.trq.alts.bulk.BulkProgress;
import lol.trq.alts.bulk.BulkReport;
import lol.trq.alts.model.AltAccount;
import lol.trq.alts.model.GameStats;
import lol.trq.alts.model.LoginMode;
import lol.trq.alts.model.SessionData;
import lol.trq.alts.net.NetworkScope;
import lol.trq.alts.net.ProxyRoute;
import lol.trq.alts.spi.DeviceCodePrompt;
import lol.trq.alts.spi.ProxyProvider;
import lol.trq.alts.spi.StoreKeyProvider;
import lol.trq.alts.spi.ToastSink;
import lol.trq.alts.store.AccountStore;
import lol.trq.alts.vault.LegacyVaultReader;
import lol.trq.alts.vault.SharedVault;
import lol.trq.alts.vault.VaultIdentity;

/**
 * The compiled companion to {@code docs/GETTING_STARTED.md}. Every snippet that guide shows is a method
 * here, so an API change breaks the build instead of quietly rotting the guide: this file is the
 * authoritative copy and the guide inlines from it.
 *
 * <p>Each method maps to one section of the guide and is illustrative only — nothing here is executed.
 * The {@code renderCard} / {@code showError} style helpers at the bottom stand in for the host's own UI.
 *
 * <p>This file is compiled by the {@code examples} source set (see build.gradle) and is not part of the
 * published jar.
 */
public final class GettingStartedExample {

    /**
     * Stand-in for the host renderer's opaque texture-handle type, written {@code MyHandle} throughout
     * the guide. The library never inspects it.
     *
     * @param id the host's texture id
     */
    public record MyHandle(int id) {}

    private GettingStartedExample() {}

    /**
     * Section 3: constructs the one runtime, wiring every host seam.
     *
     * @param dataDir the directory the encrypted account file lives in
     * @param azureClientId the host's own Azure application id; the library ships no default
     * @return the constructed runtime
     */
    public static AltsRuntime<MyHandle> buildRuntime(Path dataDir, String azureClientId) {
        return new AltsRuntime.Builder<MyHandle>()
                .sessionInjector(GettingStartedExample::installSession)
                .vaultDirectory(() -> dataDir)
                .textureUploader(imageBytes -> new MyHandle(0))
                .mainThread(Runnable::run)
                .toastSink((level, title, description, durationMs) -> show(level, title, description))
                .gameStatsSource(new ExampleNetGameStatsSource()) // optional, one per server
                // Required only for Microsoft login. Without it, Microsoft login fails cleanly and
                // offline / cookie / session login still work.
                .microsoftAuth(MicrosoftAuthConfig.of(azureClientId))
                // Optional: only if migrating an existing store written under a different filename /
                // key-binding, pass the legacy values so old files keep loading.
                .storeFileName("accounts.dat")
                .storeKeyBinding("your.mod.id")
                .build();
    }

    /**
     * Section 4: logs in interactively, then reads the stored list, an avatar, and per-server stats.
     *
     * @param alts the runtime built by {@link #buildRuntime}
     */
    public static void logInAndRead(AltsRuntime<MyHandle> alts) {
        // Log in (adds to the stored list and switches session).
        alts.loginService().loginMicrosoft(LoginMode.ADD).thenAccept(result -> {
            if (result.success()) {
                // result.account() is now the current account.
                render(result.account().username());
            }
        });

        // Stored accounts.
        List<AltAccount> saved = alts.store().accounts();

        for (AltAccount account : saved) {
            // Lazy, cached avatar. Keyed by UUID, so a renamed account keeps its head; null until the
            // background fetch lands.
            MyHandle head = alts.skinCache().get(account.uuid());

            // Lazy, cached per-server game stats (null if no source for that server, or fetch pending).
            GameStats stats = alts.gameStats("example.net").get(account.uuid());

            renderCard(head, stats);
        }
    }

    /**
     * Section 3: telling the user their accounts did not load, rather than showing them an empty list.
     * The store's key is derived from machine properties, so an ordinary environment change can make a
     * good file unreadable — and that is not the same thing as having no accounts.
     *
     * @param alts the runtime built by {@link #buildRuntime}
     */
    public static void warnIfTheStoreDidNotLoad(AltsRuntime<MyHandle> alts) {
        alts.store()
                .loadError()
                .ifPresent(failure -> alts.toasts()
                        .toast(
                                ToastSink.Level.ERROR,
                                "Accounts not loaded",
                                "The saved file could not be read: " + failure.message(),
                                8000));
    }

    /**
     * Section 3: starting a new store when the user says the old file will never open again, for example
     * after the OS user was renamed or the host key was lost. Until then the store refuses every write, so
     * an unreadable file is never replaced by an empty one.
     *
     * @param alts the runtime built by {@link #buildRuntime}
     */
    public static void startOverWithoutTheOldFile(AltsRuntime<MyHandle> alts) {
        // Only on the user's word. The old file is copied aside first, and the next write starts a new store.
        if (alts.store().loadError().isPresent() && !alts.store().discardUnreadable()) {
            // The copy aside failed, so the refusal stands; saveError() says why.
            alts.store().saveError().ifPresent(failure -> showError(failure.message()));
        }
    }

    /**
     * Section "Threads and shutdown": a runtime holds a lock on its two store files until it is closed, so
     * a host closes it when it is done with it. Closing writes what is still waiting, releases the files,
     * closes the proxy tunnels and shuts down the executor the runtime created; a host's own executor is
     * left running.
     *
     * @param dataDir the directory the encrypted account file lives in
     * @param azureClientId the host's own Azure application id
     */
    public static void runUntilShutdown(Path dataDir, String azureClientId) {
        try (AltsRuntime<MyHandle> alts = buildRuntime(dataDir, azureClientId)) {
            // Open for as long as the host runs. Whatever still waits on the runtime when it closes (a
            // sign-in, a bulk run, a scheduled claim) ends as a failure.
            runHostUntilExit(alts);
        }
        // The files are released: another runtime may now open the same directory.
    }

    /**
     * Section "Routing requests": one proxy per account, so a sweep over fifty alts does not arrive at
     * the service as one machine. The provider is asked per request; anything it cannot answer fails the
     * request rather than falling back to the real address.
     *
     * @param poolByUuid the host's own mapping of account to proxy
     * @return the provider to install on the builder
     */
    public static ProxyProvider proxyPerAccount(Map<String, ProxyRoute> poolByUuid) {
        return scope -> {
            // Avatars are not worth a proxy slot, and they carry no credential.
            if (scope.purpose() == NetworkScope.Purpose.AVATAR) {
                return ProxyRoute.direct();
            }
            ProxyRoute route = scope.accountUuid() == null ? null : poolByUuid.get(scope.accountUuid());
            // Returning null would fail the request. Say so explicitly when direct is what you meant.
            return route != null ? route : ProxyRoute.direct();
        };
    }

    /**
     * Section "Checking accounts without logging in": a sweep over everything the store holds. The live
     * session never moves, which is the whole reason this is not a loop over {@code loginAccount}.
     *
     * @param alts the runtime built by {@link #buildRuntime}
     */
    public static void sweepStoredAccounts(AltsRuntime<MyHandle> alts) {
        for (AltAccount account : alts.store().accounts()) {
            alts.accountService().refresh(account).thenAccept(status -> {
                switch (status.state()) {
                    // Nothing to do; the account is good, and RENEWED already persisted its new token.
                    case VALID, RENEWED -> render(status.account().username());
                    // The stored token is spent but recoverable — only a read-only check reports this.
                    case EXPIRED -> render(status.account().username() + " needs refreshing");
                    // The credential is gone for good. Only a fresh interactive login fixes it.
                    case REAUTH_REQUIRED -> promptMicrosoftLogin(status.account());
                    // Authenticated fine, but there is no Minecraft profile behind it.
                    case NOT_ENTITLED -> showError(status.account().username() + " does not own Minecraft");
                    // Try again later. Nothing was spent. A rate limit lands here too, and says how long
                    // to wait when the service named a wait.
                    case UNREACHABLE ->
                        showRetry(status.failure()
                                .flatMap(AltsFailure::retryAfter)
                                .map(wait -> "Rate limited for " + wait)
                                .orElse(status.message()));
                    default -> showError(status.message());
                }
            });
        }
    }

    /**
     * Section "Doing it to every account at once": a paced sweep with progress and a cancel handle. The
     * report separates a run that was stopped from one that merely had failures, because those need
     * different things said to the user.
     *
     * @param alts the runtime built by {@link #buildRuntime}
     * @return the handle, so the caller can cancel it
     */
    public static BulkHandle refreshEverything(AltsRuntime<MyHandle> alts) {
        BulkHandle handle = alts.bulk().refreshAll(alts.store().accounts(), BulkOptions.defaults(), new BulkProgress() {
            @Override
            public void started(int index, int total, String label) {
                render("checking " + label + " (" + (index + 1) + "/" + total + ")");
            }

            @Override
            public void completed(int index, int total, BulkEntryResult result) {
                if (!result.success()) {
                    showError(result.label() + ": " + result.message());
                }
            }

            @Override
            public void finished(BulkReport report) {
                if (report.stoppedEarly()) {
                    showRetry("Stopped early — the service asked us to slow down.");
                }
                render(report.succeeded() + " of " + report.results().size() + " refreshed");
            }
        });
        // handle.cancel() stops it starting anything further; whatever is in flight still finishes.
        return handle;
    }

    /**
     * Section "Doing it to every account at once": importing a pasted list. Each line is classified and
     * sent to the route that fits it; nothing is logged into.
     *
     * @param alts the runtime built by {@link #buildRuntime}
     * @param pastedLines one credential per line, as the user pasted them
     */
    public static void importPastedCredentials(AltsRuntime<MyHandle> alts, List<String> pastedLines) {
        alts.bulk()
                .importCredentials(pastedLines, LoginMode.ADD, BulkOptions.defaults(), BulkProgress.NONE)
                .report()
                .thenAccept(report -> {
                    render(report.succeeded() + " imported");
                    for (BulkEntryResult failure : report.failures()) {
                        // The label is a username or "entry 4" — never the line, which is a credential.
                        showError(failure.label() + ": " + failure.message());
                    }
                });
    }

    /**
     * Section "Logging in with a device code": a sign-in for a host that cannot open a browser or
     * listen on a port. The library fetches a short code; the host shows it, and the user enters it on
     * the identity provider's own page from any device.
     *
     * @param alts the runtime built by {@link #buildRuntime}
     */
    public static void logInWithDeviceCode(AltsRuntime<MyHandle> alts) {
        // Called once, off the render thread. Show the address exactly as given: the user has to be
        // able to see that they are typing the code into the identity provider's page and nowhere else.
        DeviceCodePrompt prompt = (userCode, verificationUri, expiresAt) ->
                render("Open " + verificationUri + " and enter " + userCode + " before " + expiresAt);

        // Start this only on the user's own action. A device code signs in whoever started the flow,
        // so a code shown to someone else is a phishing lure.
        alts.loginService().loginDeviceCode(prompt, LoginMode.ADD).thenAccept(result -> {
            if (result.success()) {
                render(result.account().username());
                return;
            }
            AltsFailure failure = result.failure().orElseThrow();
            switch (failure.kind()) {
                // The user said no. Nothing to retry until they ask again.
                case DECLINED -> render("Sign-in cancelled");
                // The code ran out before it was entered; starting again issues a fresh one.
                case TIMED_OUT -> showRetry("The code expired");
                // The service asked to be left alone. Wait before starting another.
                case RATE_LIMITED -> showRetry("Too many attempts; try again shortly");
                // Signed in, but Xbox Live will not authorize the account; xstsError() says why.
                case XBOX_DENIED ->
                    showError("Xbox Live refused this account: "
                            + failure.xstsError().orElseThrow());
                default -> showError(result.message());
            }
        });
    }

    /**
     * Section "Protecting the stored file": sealing the stores under a secret the host holds, instead
     * of under a key derived from machine properties any local process can read.
     *
     * @param dataDir the directory the encrypted account file lives in
     * @param keystore wherever the host keeps a real secret: an OS keystore entry, a hardware-backed key
     * @param upgradeLaunch true on the one launch that first installs the key over existing files
     * @return the constructed runtime
     */
    public static AltsRuntime<MyHandle> buildRuntimeWithHostKey(
            Path dataDir, HostKeystore keystore, boolean upgradeLaunch) {
        // The same bytes every time, and at least StoreKeyProvider.MIN_LENGTH of them. A provider that
        // throws leaves the stores unreadable and unwritable rather than falling back to the weaker key.
        StoreKeyProvider storeKey = () -> keystore.loadOrCreate("alts-store-key", 32);

        return new AltsRuntime.Builder<MyHandle>()
                .sessionInjector(GettingStartedExample::installSession)
                .vaultDirectory(() -> dataDir)
                .mainThread(Runnable::run)
                .toastSink((level, title, description, durationMs) -> show(level, title, description))
                .storeKeyProvider(storeKey)
                // Off by default, and on for the upgrade launch only: it lets files written before the
                // provider was installed load once and be resealed under it. Left on, it would keep
                // accepting the machine-derived key, which is the key the provider exists to replace.
                .migrateFromMachineKey(upgradeLaunch)
                .build();
    }

    /**
     * Section "Logging in from a cookie file": handing the library a path the user picked. The read runs
     * off the calling thread, so this is safe to call straight from a file-picker callback on the render
     * thread, and an unreadable file comes back as a failed result rather than as a thrown exception.
     *
     * @param alts the runtime built by {@link #buildRuntime}
     * @param chosen the cookie file the user picked
     */
    public static void logInFromCookieFile(AltsRuntime<MyHandle> alts, Path chosen) {
        alts.loginService().loginCookieFile(chosen, LoginMode.ADD).thenAccept(result -> {
            if (result.success()) {
                render(result.account().username());
            } else {
                showError(result.message());
            }
        });
    }

    /**
     * Section "Refresh tokens and silent renewal": logging into a stored account renews it silently, so
     * the caller drives nothing.
     *
     * @param alts the runtime built by {@link #buildRuntime}
     * @param account a stored account, for example one out of {@link AccountStore#accounts()}
     */
    public static void logInStoredAccount(AltsRuntime<MyHandle> alts, AltAccount account) {
        // Reuses the stored session if it is still live; otherwise renews from the refresh token,
        // persists the rotated credential, and installs the session — all without a browser.
        alts.loginService().loginAccount(account).thenAccept(result -> {
            if (result.success()) {
                render(result.account().username());
            }
        });
    }

    /**
     * Section "Refresh tokens and silent renewal": importing a refresh token the host already holds. The
     * token endpoint rotates the credential, so the rotated value is read back off the result.
     *
     * @param alts the runtime built by {@link #buildRuntime}
     * @param refreshToken the OAuth refresh token to redeem
     */
    public static void importRefreshToken(AltsRuntime<MyHandle> alts, String refreshToken) {
        alts.loginService().loginRefreshToken(refreshToken, LoginMode.ADD).thenAccept(result -> {
            if (result.success()) {
                // Always the rotated value; persist it for any account the store does not hold.
                persist(result.account().refreshToken());
            } else if (result.failure().orElseThrow().kind() == AltsFailure.Kind.NOT_CONFIGURED) {
                // Only the routes that talk to Microsoft can report this one.
                showError("Microsoft login is not configured");
            }
        });
    }

    /**
     * Section "Branching on the failure reason": picking the right prompt from the typed reason instead
     * of matching on a message string, which survives neither obfuscation nor localization.
     *
     * @param alts the runtime built by {@link #buildRuntime}
     * @param account the stored account being logged into
     */
    public static void logInStoredAccountWithBranching(AltsRuntime<MyHandle> alts, AltAccount account) {
        alts.loginService().loginAccount(account).thenAccept(result -> {
            if (result.success()) {
                return;
            }
            switch (result.failure().orElseThrow().kind()) {
                // The credential is permanently spent and has been discarded. Send the user
                // through a fresh interactive login.
                case REAUTH_REQUIRED -> promptMicrosoftLogin(account);
                // Transient: the service was unreachable or failed. The stored refresh token is
                // untouched, so offer a retry.
                case NETWORK -> showRetry(result.message());
                // Also transient, but the remedy is to wait rather than to try again at once.
                case RATE_LIMITED -> showRetry("Too many requests; try again shortly");
                default -> showError(result.message());
            }
        });
    }

    /**
     * Section "Shared vault": reading the accounts of a repository of the 0.4 vault, which 1.0 no longer
     * speaks, so the owner can carry them into a new AVP 0.5 repository. The importer only reads: it takes
     * the two documents the 0.4 host served and this member's identity, and talks to nothing.
     *
     * @param identity this member's identity, unlocked from its stored form
     * @param manifestJson the 0.4 manifest, as the 0.4 host served it
     * @param envelopeJson the 0.4 envelope, as the 0.4 host served it
     * @return the accounts, for the owner to review before writing them anywhere
     */
    public static List<AltAccount> importLegacyRepository(
            VaultIdentity identity, String manifestJson, String envelopeJson) {
        try {
            return LegacyVaultReader.read(manifestJson, envelopeJson, identity);
        } catch (AltsException e) {
            switch (e.kind()) {
                // The text the host saved is not strict JSON: fetch or export it again.
                case INVALID_INPUT -> showError("That is not a saved 0.4 repository");
                // Not this member's repository, a manifest and envelope that do not belong together, or
                // not a 0.4 document at all.
                case PROTOCOL -> showError("This identity cannot read that repository");
                // The key did not unwrap or the payload did not authenticate: wrong identity, or tampered.
                case CRYPTO -> showError("The repository could not be decrypted");
                default -> showError(e.getMessage());
            }
            return List.of();
        }
    }

    /**
     * Section "Sharing policy": a repository withholds refresh tokens until its owner turns sharing on, in
     * a new owner-signed state that every member verifies.
     *
     * @param vault the owner's copy of the repository
     */
    public static void shareRefreshTokens(SharedVault vault) {
        // Withholding is the default for a new repository.
        render(vault.sharesRefreshTokens() ? "sharing" : "withholding");

        // Owner only. What has been shared stays shared: turning it off later stops future sharing only.
        vault.setShareRefreshTokens(true).join();
    }

    /**
     * Section "Game stats": reading one server's chips back off the runtime. The source itself is
     * {@link ExampleNetGameStatsSource}.
     *
     * @param alts the runtime built by {@link #buildRuntime}
     * @param playerUuid the dashed UUID to look up
     */
    public static void readGameStats(AltsRuntime<MyHandle> alts, String playerUuid) {
        GameStats stats = alts.gameStats("example.net").get(playerUuid);
        if (stats != null) {
            for (GameStats.Stat chip : stats.stats()) {
                render(chip.label() + " " + chip.value());
            }
        }
    }

    /**
     * Section "Managing an account": everything you can do to an account after logging in — read its
     * full profile, check what it owns, and change its name. All of it runs over the account's token and
     * touches neither the store nor the live session.
     *
     * @param alts the runtime built by {@link #buildRuntime}
     * @param account the account to operate on
     * @throws AltsException if a call was refused or the service failed; switch on its kind
     */
    public static void manageAccount(AltsRuntime<MyHandle> alts, AltAccount account) {
        AccountServices services = alts.accountServices(account);

        // What it looks like: name, skins, capes, and any pending moderation action.
        PlayerProfile profile = services.profile().fetch();
        render(profile.name() + (profile.hasPendingActions() ? " (flagged)" : ""));

        // What it owns — the product set, not a boolean, so a lapsing Game Pass is told from ownership.
        Entitlements owned = services.entitlements().fetch();
        if (owned.viaGamePass() && !owned.ownsJavaOutright()) {
            showError(profile.name() + " plays Java through Game Pass, which can lapse");
        }

        // Change its name, if a name you want is free.
        if (services.name().checkAvailability("DesiredName") == NameAvailability.AVAILABLE) {
            NameChangeResult change = services.name().change("DesiredName");
            if (!change.success()) {
                showError("Name change: " + change.message());
            }
        }
    }

    /**
     * Section "Player attributes and bans": what the account is allowed to do, and whether the platform
     * has banned it. This is the platform's own verdict, read over the account's token — distinct from
     * the per-server bans a host records on the account itself.
     *
     * @param alts the runtime built by {@link #buildRuntime}
     * @param account the account to read
     * @throws AltsException if the call was refused or the service failed; switch on its kind
     */
    public static void readAttributes(AltsRuntime<MyHandle> alts, AltAccount account) {
        PlayerAttributes attributes = alts.accountServices(account).attributes().fetch();

        if (!attributes.canPlayMultiplayer()) {
            showError(account.username() + " cannot join servers");
        }
        if (!attributes.canChat()) {
            render(account.username() + " has chat disabled");
        }

        // A ban is per scope. A null expiry is a permanent one.
        PlayerAttributes.Ban ban = attributes.ban(PlayerAttributes.SCOPE_MULTIPLAYER);
        if (ban != null && ban.activeAt(java.time.Instant.now())) {
            showError(account.username() + " is banned from multiplayer "
                    + (ban.permanent() ? "permanently" : "until " + ban.expires()) + ": " + ban.reason());
        }
    }

    /**
     * Section "Looking a player up": resolving names to identities without any account. The lookup is
     * anonymous, so it works before anyone has logged in.
     *
     * @param alts the runtime built by {@link #buildRuntime}
     * @param names the usernames to resolve
     * @throws AltsException if the service refused or could not be reached; switch on its kind
     */
    public static void lookUpPlayers(AltsRuntime<MyHandle> alts, List<String> names) {
        // One name: empty when nobody holds it, which is an answer rather than an error.
        alts.profileLookup().byName("DesiredName").ifPresent(player -> render(player.name() + " " + player.uuid()));

        try {
            // Many names: sent ten per request. A name nobody holds is simply absent from the result.
            for (PublicProfile player : alts.profileLookup().byNames(names)) {
                render(player.name() + " " + player.uuid());
            }
        } catch (AltsException failure) {
            if (failure.kind() != AltsFailure.Kind.RATE_LIMITED) {
                throw failure;
            }
            // Not "those players do not exist": come back after the wait, when the service named one.
            showRetry("Lookup rate limited"
                    + failure.failure().retryAfter().map(wait -> " for " + wait).orElse(""));
        }
    }

    /**
     * Section "Claiming a name at a drop": fire a bounded burst of change attempts around the instant a
     * name frees up, stopping on the first success. The drop time is one you read off wherever names are
     * listed; the library claims at the time you give it, it does not monitor for one.
     *
     * @param alts the runtime built by {@link #buildRuntime}
     * @param account the account to claim onto
     * @param name the name to claim
     * @param dropsAt when the name becomes available
     */
    public static void claimAtDrop(
            AltsRuntime<MyHandle> alts, AltAccount account, String name, java.time.Instant dropsAt) {
        alts.accountServices(account)
                .name()
                .claimAt(name, dropsAt, ClaimOptions.defaults())
                .thenAccept(result -> {
                    if (result.claimed()) {
                        render("claimed " + name + " in " + result.attempts() + " attempts");
                    } else {
                        // Why the run ended; a terminal failure says what kind it was.
                        showError("did not get " + name + ": " + result.stopReason()
                                + result.failure()
                                        .map(f -> " (" + f.kind() + ")")
                                        .orElse(""));
                    }
                });
    }

    /** Stands in for wherever the host keeps a real secret, such as an operating-system keystore. */
    public interface HostKeystore {

        /**
         * Returns the named secret, creating it on first use.
         *
         * @param alias the entry's name
         * @param length how many random bytes to create when the entry does not exist yet
         * @return the secret bytes, the same on every call
         * @throws Exception if the keystore cannot be reached
         */
        byte[] loadOrCreate(String alias, int length) throws Exception;
    }

    /** Stands in for the host translating a {@link SessionData} into its platform's live session. */
    private static void installSession(SessionData session) {}

    /** Stands in for the host doing its work until it shuts down. */
    private static void runHostUntilExit(AltsRuntime<MyHandle> alts) {}

    /** Stands in for the host's notification UI. */
    private static void show(ToastSink.Level level, String title, String description) {}

    /** Stands in for the host drawing a line of text. */
    private static void render(String text) {}

    /** Stands in for the host drawing one account card. */
    private static void renderCard(MyHandle head, GameStats stats) {}

    /** Stands in for the host writing a credential wherever that account actually lives. */
    private static void persist(String refreshToken) {}

    /** Stands in for the host opening a fresh interactive Microsoft login. */
    private static void promptMicrosoftLogin(AltAccount account) {}

    /** Stands in for the host offering a retry. */
    private static void showRetry(String message) {}

    /** Stands in for the host reporting an error. */
    private static void showError(String message) {}
}

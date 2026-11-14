package lol.trq.alts.internal.auth;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.auth.AltAccountService;
import lol.trq.alts.auth.AltLoginService;
import lol.trq.alts.auth.CookieFile;
import lol.trq.alts.auth.LoginResult;
import lol.trq.alts.auth.MicrosoftAuthConfig;
import lol.trq.alts.internal.auth.MicrosoftAuthUtil.DeviceCodeTiming;
import lol.trq.alts.internal.net.FailureText;
import lol.trq.alts.internal.net.HttpTransport;
import lol.trq.alts.model.AccountType;
import lol.trq.alts.model.AltAccount;
import lol.trq.alts.model.LoginMode;
import lol.trq.alts.model.SessionData;
import lol.trq.alts.net.NetworkScope;
import lol.trq.alts.spi.DeviceCodePrompt;
import lol.trq.alts.spi.SessionInjector;
import lol.trq.alts.store.AccountStore;

/**
 * Concrete {@link AltLoginService} implementing authentication across protocols (JWT fast-path, Mojang
 * lookups, OAuth2, and browser cookie injection). On success it hands a {@link SessionData} to the
 * host-provided {@link SessionInjector} and updates the runtime's {@link AccountStore}; it holds no Minecraft
 * types itself.
 *
 * @author trq
 * @since 0.1.0
 */
public class AltLoginServiceImpl implements AltLoginService {

    private static final Pattern JWT_UUID_CLAIM = Pattern.compile("\"(?:id|mc)\"\\s*:\\s*\"([a-fA-F0-9\\-]+)\"");
    private static final Pattern JWT_NAME_CLAIM = Pattern.compile("\"name\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern NOT_USERNAME = Pattern.compile("[^a-zA-Z0-9_]");

    private final AccountStore store;
    private final SessionInjector sessionInjector;
    private final MicrosoftAuthConfig microsoftAuth;
    private final Clock clock;
    private final HttpTransport http;
    private final AltAccountService accounts;
    private final AccountNetworkUtil profiles;
    private final MicrosoftAuthUtil microsoft;
    private final CookieAuthUtil cookies;

    /**
     * Whether this is the runtime's import service: it resolves and stores, but installs no session,
     * never makes an account current, and never stamps one as used.
     */
    private final boolean importing;

    // Replaced in tests so a device-code login's polling does not wait out real intervals.
    DeviceCodeTiming deviceCodeTiming = DeviceCodeTiming.STANDARD;

    // Replaced in tests so the browser login can be driven without launching a real browser.
    Consumer<String> browser = MicrosoftAuthUtil::openBrowser;

    /**
     * Creates a login service that installs resolved sessions through the given injector and records
     * them in the given store.
     *
     * @param store the runtime's account store, which an {@code ADD} login adds to and every login marks
     *     as current
     * @param sessionInjector the host hook that makes a resolved account the active session
     * @param microsoftAuth the host's Microsoft authentication configuration, or {@code null} to disable
     *     Microsoft login (offline / cookie / session login stay available)
     * @param http the runtime's transport, which every request goes through and whose executor every
     *     blocking step runs on
     * @since 1.0.0
     */
    public AltLoginServiceImpl(
            AccountStore store,
            SessionInjector sessionInjector,
            MicrosoftAuthConfig microsoftAuth,
            HttpTransport http) {
        this(store, sessionInjector, microsoftAuth, http, Clock.systemUTC());
    }

    // Exists so expiry-sensitive behaviour can be exercised against a fixed clock in tests.
    AltLoginServiceImpl(
            AccountStore store,
            SessionInjector sessionInjector,
            MicrosoftAuthConfig microsoftAuth,
            HttpTransport http,
            Clock clock) {
        this(store, sessionInjector, microsoftAuth, http, clock, false);
    }

    private AltLoginServiceImpl(
            AccountStore store,
            SessionInjector sessionInjector,
            MicrosoftAuthConfig microsoftAuth,
            HttpTransport http,
            Clock clock,
            boolean importing) {
        this.importing = importing;
        this.store = Objects.requireNonNull(store, "store");
        this.sessionInjector = Objects.requireNonNull(sessionInjector, "sessionInjector");
        this.microsoftAuth = microsoftAuth;
        this.http = Objects.requireNonNull(http, "http");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.accounts = new AltAccountServiceImpl(store, microsoftAuth, http, this.clock);
        this.profiles = new AccountNetworkUtil(http);
        this.microsoft = new MicrosoftAuthUtil(http);
        this.cookies = new CookieAuthUtil(http);
    }

    /**
     * Creates the login service a bulk import signs in through. It resolves each credential and, in
     * {@link LoginMode#ADD}, stores it, merged onto a record the store already holds, exactly as an
     * ordinary sign-in does; but it installs no session, never makes an account the store's current
     * one, and never stamps an account as used, since nobody played on it. The current account stays
     * whatever the host's own sign-ins made it, one the user makes while the import runs included.
     *
     * @param store the runtime's account store
     * @param microsoftAuth the host's Microsoft authentication configuration, or {@code null}
     * @param http the runtime's transport
     * @return the import service
     * @since 1.0.0
     */
    public static AltLoginServiceImpl forImport(
            AccountStore store, MicrosoftAuthConfig microsoftAuth, HttpTransport http) {
        return new AltLoginServiceImpl(store, session -> {}, microsoftAuth, http, Clock.systemUTC(), true);
    }

    /**
     * Returns a view whose every request carries {@code tag}; see {@link AltLoginService#routed(String)}.
     * The view shares this service's store, session injector, configuration and clock, and its account
     * service is tagged too, so the renewal behind {@code loginAccount} carries the tag on every hop.
     *
     * @param tag the host's route tag
     * @return the tagged view
     * @since 1.0.0
     */
    @Override
    public AltLoginServiceImpl routed(String tag) {
        AltLoginServiceImpl view =
                new AltLoginServiceImpl(store, sessionInjector, microsoftAuth, http.routed(tag), clock, importing);
        view.deviceCodeTiming = deviceCodeTiming;
        view.browser = browser;
        return view;
    }

    /**
     * Returns the account service this login service is built on, for a caller that wants to validate or
     * renew without installing a session.
     *
     * @return the account service
     * @since 0.8.0
     */
    public AltAccountService accountService() {
        return accounts;
    }

    /**
     * Authenticates a player using a Minecraft access token or session string. Tries to decode the
     * token as a JWT for speed, falling back to a network lookup if the format is unknown.
     *
     * @param sessionToken the raw access token or session string
     * @param mode the login mode (whether to save the account or just log in)
     * @return a future containing the result of the login attempt
     */
    @Override
    public CompletableFuture<LoginResult> loginSession(String sessionToken, LoginMode mode) {
        return async("Session", () -> {
            if (sessionToken == null || sessionToken.isBlank()) {
                return LoginResult.failure(Kind.UNAUTHORIZED, "Token empty");
            }

            String cleanToken = cleanToken(sessionToken);

            // Optimization: try to extract identity from the JWT payload without a network request.
            // Only when nothing is being saved: the payload is unsigned text anyone can write, so it is
            // good enough to try a session with but not to store an identity on, and in ADD mode it
            // would be merged over whatever account the store already holds under the UUID it claims.
            // Saving therefore always goes through the profile lookup below, which asks the service who
            // the token really belongs to.
            if (mode != LoginMode.ADD && cleanToken.startsWith("eyJ")) {
                Optional<LoginResult> fastResult = attemptFastJwtLogin(cleanToken, mode);
                if (fastResult.isPresent()) return fastResult.get();
            }

            // Fallback: perform an API request to validate the token and get profile data. A refusal, an
            // account with no Minecraft profile, and an unreachable service are three different answers
            // with three different remedies, so they are classified apart rather than collapsed.
            AccountNetworkUtil.ProfileLookup profile;
            try {
                profile =
                        profiles.fetchProfile(cleanToken, profileUrl(), NetworkScope.of(NetworkScope.Purpose.PROFILE));
            } catch (Exception unreachable) {
                return LoginResult.failure(FailureText.toFailure("Login failed", unreachable));
            }
            if (profile.found()) {
                return finalizeLogin(profile.username(), profile.uuid(), cleanToken, AccountType.SESSION, mode);
            }
            return LoginResult.failure(AltAccountServiceImpl.failureFor(profile));
        });
    }

    /**
     * Authenticates a player for offline play using a simple username, generating an offline-mode UUID.
     *
     * @param name the desired username
     * @param mode the login mode
     * @return a future containing the result of the login attempt
     */
    @Override
    public CompletableFuture<LoginResult> loginOffline(String name, LoginMode mode) {
        return async("Offline", () -> {
            String cleanName =
                    name == null ? "" : NOT_USERNAME.matcher(name.trim()).replaceAll("");
            if (cleanName.isEmpty() || cleanName.length() > 16) {
                return LoginResult.failure(Kind.INVALID_INPUT, "Invalid username length (1-16 chars)");
            }

            UUID uuid = UUID.nameUUIDFromBytes(("OfflinePlayer:" + cleanName).getBytes(StandardCharsets.UTF_8));
            return finalizeLogin(cleanName, uuid.toString(), "", AccountType.OFFLINE, mode);
        });
    }

    /**
     * Initiates the Microsoft OAuth2 authentication flow via a local callback server. Cancelling the
     * returned future shuts the callback server down and releases its port.
     *
     * @param mode the login mode
     * @return a future containing the result of the login attempt
     */
    @Override
    public CompletableFuture<LoginResult> loginMicrosoft(LoginMode mode) {
        if (microsoftAuth == null) {
            return CompletableFuture.completedFuture(
                    LoginResult.failure(Kind.NOT_CONFIGURED, "Microsoft login not configured"));
        }
        return started(
                "Microsoft Auth",
                () -> interactive(microsoft.authenticate(microsoftAuth, browser), "Microsoft Auth", mode));
    }

    /**
     * Initiates the device-code sign-in: the host shows the code through {@code prompt} and the library
     * polls until the user approves it, declines it, or it expires. Cancelling the returned future stops
     * the polling.
     *
     * <p>Start this only on an explicit user action and always display the real verification address;
     * see {@link DeviceCodePrompt} for why.
     *
     * @param prompt the host seam that shows the user the code and the verification address
     * @param mode the login mode
     * @return a future containing the result of the login attempt
     * @since 0.12.0
     */
    @Override
    public CompletableFuture<LoginResult> loginDeviceCode(DeviceCodePrompt prompt, LoginMode mode) {
        if (microsoftAuth == null) {
            return CompletableFuture.completedFuture(
                    LoginResult.failure(Kind.NOT_CONFIGURED, "Microsoft login not configured"));
        }
        if (prompt == null) {
            return CompletableFuture.completedFuture(
                    LoginResult.failure(Kind.INVALID_INPUT, "No device code prompt given"));
        }
        return started(
                "Device code",
                () -> interactive(
                        microsoft.authenticateWithDeviceCode(microsoftAuth, prompt, deviceCodeTiming),
                        "Device code",
                        mode));
    }

    /**
     * Finishes an interactive Microsoft sign-in: stores and installs the account on success, classifies
     * the failure otherwise, and passes a cancellation of the returned future back to the sign-in so
     * that whatever it started (a callback server, a polling loop) stops.
     *
     * @param authentication the running sign-in
     * @param label the route's name, prefixed to a failure message
     * @param mode the login mode
     * @return a future containing the result of the login attempt
     */
    private CompletableFuture<LoginResult> interactive(
            CompletableFuture<MinecraftProfile> authentication, String label, LoginMode mode) {
        CompletableFuture<LoginResult> result = authentication
                .thenApply(profile -> finalizeLogin(profile, AccountType.MICROSOFT, mode))
                .exceptionally(failure -> classifiedFailure(label, failure));
        return MicrosoftAuthUtil.cancelling(result, authentication);
    }

    /**
     * Maps a failed sign-in onto a result whose failure says what kind it was. An unreachable service, a
     * throttled one, a refused credential, and an Xbox Live refusal each have a different remedy, so none
     * of them may be reported as another. A failure a step already classified keeps its kind, wait and
     * Xbox Live reason, with the route's name put in front of its message.
     *
     * @param label the route's name, prefixed to the message
     * @param failure the throwable the flow failed with
     * @return the classified failure result
     */
    static LoginResult classifiedFailure(String label, Throwable failure) {
        Throwable cause = failure;
        while (cause instanceof CompletionException && cause.getCause() != null) {
            cause = cause.getCause();
        }
        if (cause instanceof AltsException classified) {
            return LoginResult.failure(classified.failure().withMessage(label + ": " + classified.getMessage()));
        }
        if (cause instanceof TimeoutException) {
            return LoginResult.failure(Kind.TIMED_OUT, label + ": sign-in timed out");
        }
        // From here on the failure is one the library did not write, so its message is not repeated: the
        // JDK quotes the input that offended it, and here that input is a cookie, a token, or an address
        // carrying one.
        if (cause instanceof IllegalArgumentException) {
            // The credential text itself could not be read.
            return LoginResult.failure(Kind.UNAUTHORIZED, label + ": unreadable credential");
        }
        return LoginResult.failure(FailureText.toFailure(label, cause));
    }

    /**
     * Runs a sign-in step on the library executor. A failure it throws, and the executor refusing it
     * (the runtime closed), become a classified result rather than an exception at the caller or a
     * future completed exceptionally.
     *
     * @param label the route's name, prefixed to a failure message
     * @param step the step, which returns the result
     * @return a future holding the result
     */
    private CompletableFuture<LoginResult> async(String label, Supplier<LoginResult> step) {
        return started(label, () -> CompletableFuture.supplyAsync(step, http.executor()));
    }

    /**
     * Starts a sign-in whose future must hold a result whatever happens: a start that throws (an
     * executor that refuses the task once the runtime is closed) and a future that fails both become a
     * classified failure result.
     *
     * @param label the route's name, prefixed to a failure message
     * @param start what starts the sign-in
     * @return a future that always completes with a result
     */
    private CompletableFuture<LoginResult> started(String label, Supplier<CompletableFuture<LoginResult>> start) {
        if (http.isClosed()) {
            // Nothing a closed runtime starts can finish: say so before parsing, prompting or binding.
            return CompletableFuture.completedFuture(
                    LoginResult.failure(Kind.CANCELLED, label + ": the runtime is closed"));
        }
        CompletableFuture<LoginResult> running;
        try {
            running = start.get();
        } catch (RuntimeException refused) {
            return CompletableFuture.completedFuture(classifiedFailure(label, refused));
        }
        CompletableFuture<LoginResult> result = running.exceptionally(failure -> classifiedFailure(label, failure));
        // A cancellation of the result is passed back so a callback server or a polling loop stops.
        return MicrosoftAuthUtil.cancelling(result, running);
    }

    /**
     * Authenticates a player using raw browser cookie data.
     *
     * @param cookieData the cookie string (Netscape or mangled format)
     * @param mode the login mode
     * @return a future containing the result of the login attempt
     */
    @Override
    public CompletableFuture<LoginResult> loginCookie(String cookieData, LoginMode mode) {
        return async("Cookie Auth", () -> {
            if (cookieData == null || cookieData.isBlank()) {
                return LoginResult.failure(Kind.UNAUTHORIZED, "Cookie data empty");
            }
            MinecraftProfile profile;
            try {
                profile = cookies.authenticate(cookieData, microsoftAuth, null);
            } catch (Exception e) {
                return classifiedFailure("Cookie Auth", e);
            }
            return finalizeLogin(profile.username(), profile.uuid(), profile.accessToken(), AccountType.COOKIE, mode);
        });
    }

    /**
     * Authenticates using cookies read from a file. The read runs off the calling thread so a host can
     * hand over a path straight from a file picker on its render thread, and a file that cannot be read
     * fails the same way bad cookie text does rather than throwing at the caller.
     *
     * @param file the exported cookie file
     * @param mode the login mode
     * @return a future containing the result of the login attempt
     * @since 0.7.0
     */
    @Override
    public CompletableFuture<LoginResult> loginCookieFile(Path file, LoginMode mode) {
        if (file == null) {
            return CompletableFuture.completedFuture(LoginResult.failure(Kind.UNAUTHORIZED, "No cookie file given"));
        }
        return started(
                "Cookie file",
                () -> CompletableFuture.supplyAsync(
                                () -> {
                                    try {
                                        return CookieFile.read(file);
                                    } catch (AltsException unreadable) {
                                        // Not a network failure: the file is the credential, and it could not
                                        // be read, which a sign-in reports as a credential it cannot use.
                                        // CookieFile's message is a file name and a fixed phrase.
                                        throw new AltsException(
                                                AltsFailure.of(Kind.UNAUTHORIZED, unreadable.getMessage()));
                                    }
                                },
                                http.executor())
                        .thenCompose(cookieData -> loginCookie(cookieData, mode)));
    }

    /**
     * Authenticates using a stored OAuth refresh token, skipping the interactive browser step.
     *
     * @param refreshToken the OAuth refresh token to redeem
     * @param mode the login mode
     * @return a future containing the result of the login attempt
     * @since 0.6.0
     */
    @Override
    public CompletableFuture<LoginResult> loginRefreshToken(String refreshToken, LoginMode mode) {
        if (microsoftAuth == null) {
            return CompletableFuture.completedFuture(
                    LoginResult.failure(Kind.NOT_CONFIGURED, "Microsoft login not configured"));
        }
        if (refreshToken == null || refreshToken.isBlank()) {
            return CompletableFuture.completedFuture(LoginResult.failure(Kind.UNAUTHORIZED, "Refresh token empty"));
        }
        String cleaned = cleanRefreshToken(refreshToken);
        if (cleaned.isBlank()) {
            return CompletableFuture.completedFuture(LoginResult.failure(Kind.UNAUTHORIZED, "Refresh token empty"));
        }
        // Nothing is discarded on failure: the token came from the caller rather than from the store, so
        // there is no stored credential this failure could cost. Renewing a stored account is
        // AltAccountServiceImpl's job, and it does clear a permanently spent one.
        return started(
                "Refresh",
                () -> microsoft
                        .authenticateWithRefreshToken(microsoftAuth, cleaned)
                        .thenApply(profile -> finalizeLogin(profile, AccountType.MICROSOFT, mode)));
    }

    /**
     * Authenticates into a pre-existing {@link AltAccount}, renewing the session first when its access
     * token is spent and once more if the stored token turns out to be refused.
     *
     * <p>This is {@link AltAccountService#refresh(AltAccount)} plus one step. Making the account usable
     * and installing it as the live session are separate concerns, and separating them is what lets a
     * host validate or renew a hundred accounts without the session moving.
     *
     * @param account the account model to log into
     * @return a future containing the result of the login attempt
     */
    @Override
    public CompletableFuture<LoginResult> loginAccount(AltAccount account) {
        if (account == null) {
            return CompletableFuture.completedFuture(LoginResult.failure(Kind.INVALID_INPUT, "No account given"));
        }
        if (account.type() == AccountType.OFFLINE) {
            return loginOffline(account.username(), LoginMode.DIRECT);
        }
        return started(
                "Account",
                () -> accounts.refresh(account)
                        .thenApply(status -> status.usable()
                                ? inject(status.account())
                                : LoginResult.failure(status.failure().orElseThrow())));
    }

    /**
     * Installs an already-resolved account as the live session without rebuilding it.
     *
     * @param account the account to install
     * @return the login result
     */
    private LoginResult inject(AltAccount account) {
        if (importing) {
            // An import resolves and stores; the live session and the current account are the host's.
            return LoginResult.success(account);
        }
        try {
            sessionInjector.inject(
                    new SessionData(account.username(), account.uuid(), account.accessToken(), account.type()));
            store.useAccount(account);
            return LoginResult.success(account);
        } catch (Exception e) {
            // The host's injector wrote that message, and it may quote the session it was handed.
            return LoginResult.failure(Kind.UNKNOWN, "Session Injection: the host's session injector failed");
        }
    }

    /**
     * Returns the profile endpoint to validate against — the configured one when Microsoft login is
     * wired up, and the public default otherwise.
     *
     * @return the Minecraft services profile endpoint
     */
    private String profileUrl() {
        return microsoftAuth != null
                ? microsoftAuth.minecraftProfileUrl()
                : MicrosoftAuthConfig.DEFAULT_MINECRAFT_PROFILE_URL;
    }

    /**
     * Finalizes a flow that produced a freshly authenticated account, carrying the issued credentials
     * onto it. When the account is being saved and the store already holds the same alt, the issued
     * credentials are merged onto the stored record, so importing a credential for an alt the user
     * already has refreshes it instead of resetting its bans, provenance, and attribution.
     *
     * @param profile the resolved profile
     * @param type the type of account used
     * @param mode the login mode
     * @return the login result
     */
    private LoginResult finalizeLogin(MinecraftProfile profile, AccountType type, LoginMode mode) {
        AltAccount account = AltAccount.of(
                        AuthFormats.dashedUuid(profile.uuid()), profile.username(), profile.accessToken(), type)
                .withTokens(profile.accessToken(), profile.refreshToken(), profile.expiresAt());

        if (mode == LoginMode.ADD) {
            account = merged(account);
            store.addAccount(account);
        }
        return inject(account);
    }

    /**
     * Merges a freshly authenticated account onto the record the store holds for it, if any. An import
     * keeps the stored record's last-used time: resolving a credential again is not playing on it.
     *
     * @param account the freshly authenticated account
     * @return the account to store
     */
    private AltAccount merged(AltAccount account) {
        AltAccount existing = storedRecord(account.uuid());
        AltAccount merged = account.mergedOnto(existing);
        if (!importing || existing == null) {
            return merged;
        }
        return new AltAccount(
                merged.uuid(),
                merged.username(),
                merged.accessToken(),
                merged.type(),
                existing.lastUsed(),
                merged.lastUsedBy(),
                merged.bans(),
                merged.sourceClient(),
                merged.sourceUser(),
                merged.refreshToken(),
                merged.expiresAt());
    }

    /**
     * Returns the record the store holds for {@code uuid}, so a login can be merged onto it instead of
     * replacing it.
     *
     * @param uuid the dashed UUID to look up
     * @return the stored account, or {@code null} when the store holds none for that UUID
     */
    private AltAccount storedRecord(String uuid) {
        return store.accounts().stream()
                .filter(a -> a.uuid().equals(uuid))
                .findFirst()
                .orElse(null);
    }

    /**
     * Finalizes the login process by installing the resolved session through the host injector and
     * updating local storage. As with the profile-based overload, saving merges onto the stored record
     * for the same alt rather than replacing it.
     *
     * @param username the player's username
     * @param uuid the player's UUID string
     * @param token the authentication token
     * @param type the type of account used
     * @param mode the login mode
     * @return a result object containing success status and the account data
     */
    private LoginResult finalizeLogin(String username, String uuid, String token, AccountType type, LoginMode mode) {
        try {
            String fmtUuid = AuthFormats.dashedUuid(uuid);
            AltAccount account = AltAccount.of(fmtUuid, username, token, type);
            if (mode == LoginMode.ADD) {
                account = merged(account);
            }

            if (!importing) {
                sessionInjector.inject(
                        new SessionData(account.username(), account.uuid(), account.accessToken(), account.type()));
            }

            if (mode == LoginMode.ADD) store.addAccount(account);
            if (!importing) store.useAccount(account);

            return LoginResult.success(account);
        } catch (Exception e) {
            // The host's injector wrote that message, and it may quote the session it was handed.
            return LoginResult.failure(Kind.UNKNOWN, "Session Injection: the host's session injector failed");
        }
    }

    /**
     * Attempts to extract a username and UUID from a token without network calls by parsing the JWT
     * payload if applicable.
     *
     * <p>The payload is unverified, so this is only ever used for a login that saves nothing, and only
     * for a token that states its own expiry: one with no {@code exp} gives no way to tell a live token
     * from a long-dead one, and is sent to the profile lookup instead.
     *
     * @param token the JWT string
     * @param mode the login mode
     * @return an optional result if the JWT was valid and contained profile data
     */
    private Optional<LoginResult> attemptFastJwtLogin(String token, LoginMode mode) {
        try {
            long expiry = TokenExpiry.jwtExpiryMillis(token);
            if (expiry <= 0 || clock.millis() >= expiry - TokenExpiry.SKEW_MILLIS) {
                return Optional.empty();
            }

            String payload = AuthFormats.jwtPayload(token);
            String uuid = firstGroup(JWT_UUID_CLAIM, payload);
            String username = firstGroup(JWT_NAME_CLAIM, payload);

            if (uuid != null && username != null) {
                return Optional.of(finalizeLogin(username, uuid, token, AccountType.SESSION, mode));
            }
        } catch (Exception ignored) {
        }
        return Optional.empty();
    }

    /**
     * Finds the first capture group of {@code pattern} within {@code text}.
     *
     * @param pattern the compiled pattern
     * @param text the source text
     * @return the first capture group value, or null if not found
     */
    private static String firstGroup(Pattern pattern, String text) {
        Matcher m = pattern.matcher(text);
        return m.find() ? m.group(1) : null;
    }

    /**
     * Sanitizes a pasted refresh token. Tokens are routinely copied out of account lists that prefix
     * them with a name (`user:token`) or out of an HTTP header, and the surrounding text is invisible
     * in a password-style input. Left in place it is sent to the token endpoint as part of the
     * credential, which the service rejects as an invalid grant — a failure that reads to the user as
     * "my token is bad" rather than "my paste was bad".
     *
     * <p>Kept separate from {@link #cleanToken(String)}, which selects the {@code eyJ}-prefixed segment
     * of a JWT and so cannot recognise a refresh token at all.
     *
     * @param raw the pasted token, possibly wrapped in surrounding text
     * @return the token with any name prefix, bearer prefix, quoting, and whitespace removed
     */
    private String cleanRefreshToken(String raw) {
        String t = raw.trim();
        if (t.length() >= 2 && ((t.startsWith("\"") && t.endsWith("\"")) || (t.startsWith("'") && t.endsWith("'")))) {
            t = t.substring(1, t.length() - 1).trim();
        }
        if (t.toLowerCase(Locale.ROOT).startsWith("bearer ")) {
            t = t.substring(7).trim();
        }
        if (t.contains(":")) {
            for (String part : t.split(":")) {
                if (part.strip().startsWith("M.")) {
                    return withoutBreaks(part);
                }
            }
        }
        return withoutBreaks(t);
    }

    /**
     * Removes every whitespace and control character from a token. No token has one, but a pasted token
     * often does: a long value wraps in an email or a terminal and is copied with the line break in it.
     * Left in, the break makes the request header illegal, and the token would never have worked
     * anyway; taken out, the paste is what the user meant.
     *
     * @param token the token text
     * @return the token with no whitespace or control characters anywhere in it
     */
    static String withoutBreaks(String token) {
        StringBuilder kept = new StringBuilder(token.length());
        for (int index = 0; index < token.length(); index++) {
            char character = token.charAt(index);
            if (!Character.isWhitespace(character) && !Character.isISOControl(character)) {
                kept.append(character);
            }
        }
        return kept.toString();
    }

    /**
     * Sanitizes a pasted session token by selecting the JWT out of any surrounding text and dropping a
     * bearer prefix.
     *
     * @param t the raw token
     * @return the sanitized token, with no whitespace or control characters anywhere in it
     */
    private String cleanToken(String t) {
        t = t.trim();
        if (t.contains(":")) {
            for (String p : t.split(":")) {
                if (p.strip().startsWith("eyJ")) {
                    return withoutBreaks(p);
                }
            }
        }
        return withoutBreaks(t.toLowerCase(Locale.ROOT).startsWith("bearer ") ? t.substring(7) : t);
    }
}

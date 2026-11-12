package lol.trq.alts.auth;

import java.io.IOException;
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import lol.trq.alts.auth.AltLoginCallback.FailureReason;
import lol.trq.alts.auth.MicrosoftAuthUtil.AuthFlowException;
import lol.trq.alts.auth.MicrosoftAuthUtil.DeviceCodeTiming;
import lol.trq.alts.model.AccountType;
import lol.trq.alts.model.AltAccount;
import lol.trq.alts.model.LoginMode;
import lol.trq.alts.model.SessionData;
import lol.trq.alts.net.NetworkScope;
import lol.trq.alts.spi.DeviceCodePrompt;
import lol.trq.alts.spi.SessionInjector;
import lol.trq.alts.store.AltStore;

/**
 * Concrete {@link AltLoginService} implementing authentication across protocols (JWT fast-path, Mojang
 * lookups, OAuth2, and browser cookie injection). On success it hands a {@link SessionData} to the
 * host-provided {@link SessionInjector} and updates the local {@link AltStore}; it holds no Minecraft
 * types itself.
 *
 * @author trq
 * @since 0.1.0
 */
public class AltLoginServiceImpl implements AltLoginService {

    private static final Pattern JWT_UUID_CLAIM = Pattern.compile("\"(?:id|mc)\"\\s*:\\s*\"([a-fA-F0-9\\-]+)\"");
    private static final Pattern JWT_NAME_CLAIM = Pattern.compile("\"name\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern NOT_USERNAME = Pattern.compile("[^a-zA-Z0-9_]");

    private final SessionInjector sessionInjector;
    private final MicrosoftAuthConfig microsoftAuth;
    private final Clock clock;
    private final AltAccountService accounts;

    // Replaced in tests so a device-code login's polling does not wait out real intervals.
    DeviceCodeTiming deviceCodeTiming = DeviceCodeTiming.STANDARD;

    // Replaced in tests so the browser login can be driven without launching a real browser.
    Consumer<String> browser = MicrosoftAuthUtil::openBrowser;

    /**
     * Creates a login service that installs resolved sessions through the given injector.
     *
     * @param sessionInjector the host hook that makes a resolved account the active session
     * @param microsoftAuth the host's Microsoft authentication configuration, or {@code null} to disable
     *     Microsoft login (offline / cookie / session login stay available)
     */
    public AltLoginServiceImpl(SessionInjector sessionInjector, MicrosoftAuthConfig microsoftAuth) {
        this(sessionInjector, microsoftAuth, Clock.systemUTC());
    }

    // Exists so expiry-sensitive behaviour can be exercised against a fixed clock in tests.
    AltLoginServiceImpl(SessionInjector sessionInjector, MicrosoftAuthConfig microsoftAuth, Clock clock) {
        this.sessionInjector = Objects.requireNonNull(sessionInjector, "sessionInjector");
        this.microsoftAuth = microsoftAuth;
        this.clock = Objects.requireNonNull(clock, "clock");
        this.accounts = new AltAccountServiceImpl(microsoftAuth, this.clock);
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
    public CompletableFuture<AltLoginCallback.LoginResult> loginSession(String sessionToken, LoginMode mode) {
        return CompletableFuture.supplyAsync(() -> {
            if (sessionToken == null || sessionToken.isBlank()) {
                return AltLoginCallback.LoginResult.failure("Token empty", FailureReason.INVALID_TOKEN);
            }

            String cleanToken = cleanToken(sessionToken);

            // Optimization: try to extract identity from the JWT payload without a network request.
            // Only when nothing is being saved: the payload is unsigned text anyone can write, so it is
            // good enough to try a session with but not to store an identity on, and in ADD mode it
            // would be merged over whatever account the store already holds under the UUID it claims.
            // Saving therefore always goes through the profile lookup below, which asks the service who
            // the token really belongs to.
            if (mode != LoginMode.ADD && cleanToken.startsWith("eyJ")) {
                Optional<AltLoginCallback.LoginResult> fastResult = attemptFastJwtLogin(cleanToken, mode);
                if (fastResult.isPresent()) return fastResult.get();
            }

            // Fallback: perform an API request to validate the token and get profile data. A refusal, an
            // account with no Minecraft profile, and an unreachable service are three different answers
            // with three different remedies, so they are classified apart rather than collapsed.
            AccountNetworkUtil.ProfileLookup profile;
            try {
                profile = AccountNetworkUtil.fetchProfile(
                        cleanToken, profileUrl(), NetworkScope.of(NetworkScope.Purpose.PROFILE));
            } catch (Exception unreachable) {
                return AltLoginCallback.LoginResult.failure(
                        "Login failed: " + unreachable.getMessage(), FailureReason.NETWORK);
            }
            if (profile.found()) {
                return finalizeLogin(profile.username(), profile.uuid(), cleanToken, AccountType.SESSION, mode);
            }
            return AltLoginCallback.LoginResult.failure(
                    AltAccountServiceImpl.messageFor(profile), AltAccountServiceImpl.reasonFor(profile));
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
    public CompletableFuture<AltLoginCallback.LoginResult> loginOffline(String name, LoginMode mode) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                String cleanName =
                        name == null ? "" : NOT_USERNAME.matcher(name.trim()).replaceAll("");
                if (cleanName.isEmpty() || cleanName.length() > 16) {
                    return AltLoginCallback.LoginResult.failure(
                            "Invalid username length (1-16 chars)", FailureReason.INVALID_TOKEN);
                }

                UUID uuid = UUID.nameUUIDFromBytes(("OfflinePlayer:" + cleanName).getBytes(StandardCharsets.UTF_8));
                return finalizeLogin(cleanName, uuid.toString(), "", AccountType.OFFLINE, mode);
            } catch (Exception e) {
                return AltLoginCallback.LoginResult.failure("Error: " + e.getMessage(), FailureReason.UNKNOWN);
            }
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
    public CompletableFuture<AltLoginCallback.LoginResult> loginMicrosoft(LoginMode mode) {
        if (microsoftAuth == null) {
            return CompletableFuture.completedFuture(AltLoginCallback.LoginResult.failure(
                    "Microsoft login not configured", FailureReason.NOT_CONFIGURED));
        }
        return interactive(MicrosoftAuthUtil.authenticate(microsoftAuth, browser), "Microsoft Auth", mode);
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
    public CompletableFuture<AltLoginCallback.LoginResult> loginDeviceCode(DeviceCodePrompt prompt, LoginMode mode) {
        if (microsoftAuth == null) {
            return CompletableFuture.completedFuture(AltLoginCallback.LoginResult.failure(
                    "Microsoft login not configured", FailureReason.NOT_CONFIGURED));
        }
        if (prompt == null) {
            return CompletableFuture.completedFuture(
                    AltLoginCallback.LoginResult.failure("No device code prompt given", FailureReason.NOT_CONFIGURED));
        }
        return interactive(
                MicrosoftAuthUtil.authenticateWithDeviceCode(microsoftAuth, prompt, deviceCodeTiming),
                "Device code",
                mode);
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
    private CompletableFuture<AltLoginCallback.LoginResult> interactive(
            CompletableFuture<MinecraftProfile> authentication, String label, LoginMode mode) {
        CompletableFuture<AltLoginCallback.LoginResult> result = authentication
                .thenApply(profile -> finalizeLogin(profile, AccountType.MICROSOFT, mode))
                .exceptionally(failure -> classifiedFailure(label, failure));
        return MicrosoftAuthUtil.cancelling(result, authentication);
    }

    /**
     * Maps a failed sign-in onto a result whose reason says what kind of failure it was. An unreachable
     * service, a throttled one, a refused credential, and an Xbox Live refusal each have a different
     * remedy, so none of them may be reported as another.
     *
     * @param label the route's name, prefixed to the message
     * @param failure the throwable the flow failed with
     * @return the classified failure result
     */
    private static AltLoginCallback.LoginResult classifiedFailure(String label, Throwable failure) {
        AuthFlowException classified = MicrosoftAuthUtil.classified(failure);
        if (classified != null) {
            XstsError xstsError = classified instanceof MicrosoftAuthUtil.XstsAuthException xsts ? xsts.error() : null;
            return AltLoginCallback.LoginResult.failure(
                    label + ": " + classified.getMessage(), classified.reason(), xstsError);
        }

        Throwable cause = failure;
        while (cause instanceof CompletionException && cause.getCause() != null) {
            cause = cause.getCause();
        }
        if (cause instanceof TimeoutException) {
            return AltLoginCallback.LoginResult.failure(label + ": sign-in timed out", FailureReason.TIMED_OUT);
        }
        if (cause instanceof IllegalArgumentException) {
            // The credential text itself could not be read.
            return AltLoginCallback.LoginResult.failure(
                    label + ": " + describe(cause, "unreadable credential"), FailureReason.INVALID_TOKEN);
        }
        if (cause instanceof IOException) {
            return AltLoginCallback.LoginResult.failure(
                    label + ": " + describe(cause, "connection failed"), FailureReason.NETWORK);
        }
        return AltLoginCallback.LoginResult.failure(
                label + ": " + describe(cause, "unknown error"), FailureReason.UNKNOWN);
    }

    private static String describe(Throwable cause, String fallback) {
        return cause.getMessage() != null ? cause.getMessage() : fallback;
    }

    /**
     * Authenticates a player using raw browser cookie data.
     *
     * @param cookieData the cookie string (Netscape or mangled format)
     * @param mode the login mode
     * @return a future containing the result of the login attempt
     */
    @Override
    public CompletableFuture<AltLoginCallback.LoginResult> loginCookie(String cookieData, LoginMode mode) {
        return CompletableFuture.supplyAsync(() -> {
            if (cookieData == null || cookieData.isBlank()) {
                return AltLoginCallback.LoginResult.failure("Cookie data empty", FailureReason.INVALID_TOKEN);
            }
            MinecraftProfile profile;
            try {
                profile = CookieAuthUtil.authenticate(cookieData, microsoftAuth, null);
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
    public CompletableFuture<AltLoginCallback.LoginResult> loginCookieFile(Path file, LoginMode mode) {
        if (file == null) {
            return CompletableFuture.completedFuture(
                    AltLoginCallback.LoginResult.failure("No cookie file given", FailureReason.INVALID_TOKEN));
        }
        return CompletableFuture.supplyAsync(() -> {
                    try {
                        return CookieFile.read(file);
                    } catch (IOException e) {
                        // Not a network failure: the file is the credential, and it could not be read.
                        throw new AuthFlowException(describe(e, "could not be read"), FailureReason.INVALID_TOKEN, e);
                    }
                })
                .thenCompose(cookieData -> loginCookie(cookieData, mode))
                .exceptionally(failure -> classifiedFailure("Cookie file", failure));
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
    public CompletableFuture<AltLoginCallback.LoginResult> loginRefreshToken(String refreshToken, LoginMode mode) {
        if (microsoftAuth == null) {
            return CompletableFuture.completedFuture(AltLoginCallback.LoginResult.failure(
                    "Microsoft login not configured", FailureReason.NOT_CONFIGURED));
        }
        if (refreshToken == null || refreshToken.isBlank()) {
            return CompletableFuture.completedFuture(
                    AltLoginCallback.LoginResult.failure("Refresh token empty", FailureReason.INVALID_TOKEN));
        }
        String cleaned = cleanRefreshToken(refreshToken);
        if (cleaned.isBlank()) {
            return CompletableFuture.completedFuture(
                    AltLoginCallback.LoginResult.failure("Refresh token empty", FailureReason.INVALID_TOKEN));
        }
        return MicrosoftAuthUtil.authenticateWithRefreshToken(microsoftAuth, cleaned)
                .thenApply(profile -> finalizeLogin(profile, AccountType.MICROSOFT, mode))
                .exceptionally(AltLoginServiceImpl::importFailure);
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
    public CompletableFuture<AltLoginCallback.LoginResult> loginAccount(AltAccount account) {
        if (account == null) {
            return CompletableFuture.completedFuture(
                    AltLoginCallback.LoginResult.failure("No account given", FailureReason.UNKNOWN));
        }
        if (account.type() == AccountType.OFFLINE) {
            return loginOffline(account.username(), LoginMode.DIRECT);
        }
        return accounts.refresh(account)
                .thenApply(status -> status.usable()
                        ? inject(status.account())
                        : AltLoginCallback.LoginResult.failure(status.message(), status.reason()));
    }

    /**
     * Installs an already-resolved account as the live session without rebuilding it.
     *
     * @param account the account to install
     * @return the login result
     */
    private AltLoginCallback.LoginResult inject(AltAccount account) {
        try {
            sessionInjector.inject(
                    new SessionData(account.username(), account.uuid(), account.accessToken(), account.type()));
            AltStore.useAccount(account);
            return AltLoginCallback.LoginResult.success(account);
        } catch (Exception e) {
            return AltLoginCallback.LoginResult.failure("Session Injection: " + e.getMessage(), FailureReason.UNKNOWN);
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
     * Maps a failed refresh-token <em>import</em> onto a classified result. Nothing is discarded here:
     * the token came from the caller rather than from the store, so there is no stored credential this
     * failure could cost. Renewing a stored account is {@link AltAccountServiceImpl}'s job, and it does
     * clear a permanently spent one.
     *
     * @param ex the failure the redemption completed with
     * @return the classified failure result
     */
    private static AltLoginCallback.LoginResult importFailure(Throwable ex) {
        Throwable cause = ex.getCause() != null ? ex.getCause() : ex;
        boolean permanent =
                cause instanceof MicrosoftAuthUtil.RefreshRejectedException rejection && rejection.permanent();

        return AltLoginCallback.LoginResult.failure(
                "Refresh: " + (cause.getMessage() != null ? cause.getMessage() : "unknown error"),
                permanent ? FailureReason.REAUTH_REQUIRED : FailureReason.NETWORK);
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
    private AltLoginCallback.LoginResult finalizeLogin(MinecraftProfile profile, AccountType type, LoginMode mode) {
        AltAccount account = AltAccount.of(
                        AuthFormats.dashedUuid(profile.uuid()), profile.username(), profile.accessToken(), type)
                .withTokens(profile.accessToken(), profile.refreshToken(), profile.expiresAt());

        if (mode == LoginMode.ADD) {
            account = account.mergedOnto(storedRecord(account.uuid()));
            AltStore.addAccount(account);
        }
        return inject(account);
    }

    /**
     * Returns the record the store holds for {@code uuid}, so a login can be merged onto it instead of
     * replacing it.
     *
     * @param uuid the dashed UUID to look up
     * @return the stored account, or {@code null} when the store holds none for that UUID
     */
    private static AltAccount storedRecord(String uuid) {
        return AltStore.accounts().stream()
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
    private AltLoginCallback.LoginResult finalizeLogin(
            String username, String uuid, String token, AccountType type, LoginMode mode) {
        try {
            String fmtUuid = AuthFormats.dashedUuid(uuid);
            AltAccount account = AltAccount.of(fmtUuid, username, token, type);
            if (mode == LoginMode.ADD) {
                account = account.mergedOnto(storedRecord(fmtUuid));
            }

            sessionInjector.inject(
                    new SessionData(account.username(), account.uuid(), account.accessToken(), account.type()));

            if (mode == LoginMode.ADD) AltStore.addAccount(account);
            AltStore.useAccount(account);

            return AltLoginCallback.LoginResult.success(account);
        } catch (Exception e) {
            return AltLoginCallback.LoginResult.failure("Session Injection: " + e.getMessage(), FailureReason.UNKNOWN);
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
    private Optional<AltLoginCallback.LoginResult> attemptFastJwtLogin(String token, LoginMode mode) {
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
                if (part.startsWith("M.")) {
                    return part.trim();
                }
            }
        }
        return t;
    }

    /**
     * Sanitizes a pasted session token by selecting the JWT out of any surrounding text and dropping a
     * bearer prefix.
     *
     * @param t the raw token
     * @return the sanitized token
     */
    private String cleanToken(String t) {
        t = t.trim();
        if (t.contains(":")) {
            for (String p : t.split(":")) if (p.startsWith("eyJ")) return p;
        }
        return t.toLowerCase(Locale.ROOT).startsWith("bearer ") ? t.substring(7).trim() : t;
    }
}

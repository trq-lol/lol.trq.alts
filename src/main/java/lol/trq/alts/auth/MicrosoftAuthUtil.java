package lol.trq.alts.auth;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.annotations.SerializedName;
import java.awt.Desktop;
import java.io.Serial;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.function.Supplier;
import lol.trq.alts.auth.AltLoginCallback.FailureReason;
import lol.trq.alts.net.FailureText;
import lol.trq.alts.net.HttpUtil;
import lol.trq.alts.net.IoExecutor;
import lol.trq.alts.net.MicrosoftCallbackServer;
import lol.trq.alts.net.NetworkScope;
import lol.trq.alts.spi.DeviceCodePrompt;

/**
 * Orchestrates the multi-step OAuth 2.0 and Xbox Live authentication flow, exchanging an
 * authorization code for a Minecraft-compatible session token. The client id, scope, and every service
 * endpoint come from a host-supplied {@link MicrosoftAuthConfig} — nothing is hardcoded.
 *
 * @author trq
 * @since 0.1.0
 */
public final class MicrosoftAuthUtil {

    private static final String STATE_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_";

    /** The scope for a flow that has no account yet: a fresh interactive login or a credential import. */
    private static final NetworkScope NO_ACCOUNT = NetworkScope.of(NetworkScope.Purpose.AUTH);

    /** The grant type a device code is redeemed with. */
    private static final String DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";

    /** How many polls in a row may fail to get an answer before the device-code login gives up. */
    private static final int MAX_UNANSWERED_POLLS = 3;

    private static final Gson GSON = new Gson();

    private MicrosoftAuthUtil() {}

    /**
     * Initiates the full asynchronous authentication flow. Starts a local callback server, opens the
     * browser, and chains the authentication steps. The authorization-code grant is protected with PKCE
     * ({@code S256}), so a code intercepted on its way to the loopback redirect cannot be redeemed by
     * anything that does not also hold the verifier generated here.
     *
     * <p>Cancelling the returned future shuts the callback server down and releases its port.
     *
     * @param config the host's Microsoft authentication configuration (client id, scope, endpoints)
     * @return a future containing the final {@link MinecraftProfile} on success
     */
    public static CompletableFuture<MinecraftProfile> authenticate(MicrosoftAuthConfig config) {
        return authenticate(config, MicrosoftAuthUtil::openBrowser);
    }

    // Exists so the interactive flow can be driven in tests without launching a real browser.
    static CompletableFuture<MinecraftProfile> authenticate(MicrosoftAuthConfig config, Consumer<String> browser) {
        Objects.requireNonNull(config, "config");
        String state = generateState();
        String verifier = generateCodeVerifier();
        MicrosoftCallbackServer server = new MicrosoftCallbackServer(state, config, codeChallenge(verifier), browser);

        CompletableFuture<String> code = server.start();
        CompletableFuture<MinecraftProfile> chain = code.thenCompose(
                        received -> exchangeCodeForToken(config, received, server.redirectUri(), verifier))
                .thenCompose(tokens -> completeFrom(config, tokens, NO_ACCOUNT));
        return cancelling(chain, code);
    }

    /**
     * Renews a session from a stored OAuth refresh token, skipping the interactive browser step. The
     * token endpoint issues a rotated refresh token on success; the returned profile carries it, and
     * callers must persist it or the next renewal will fail.
     *
     * <p>Every request is made with an account-less scope. Prefer
     * {@link #authenticateWithRefreshToken(MicrosoftAuthConfig, String, NetworkScope)} when the token
     * belongs to a known account, so a host's proxy provider can route the renewal for that account.
     *
     * @param config the host's Microsoft authentication configuration (client id, scope, endpoints)
     * @param refreshToken the stored refresh token to redeem
     * @return a future containing the renewed {@link MinecraftProfile}
     * @throws NullPointerException if {@code config} is null
     * @since 0.6.0
     */
    public static CompletableFuture<MinecraftProfile> authenticateWithRefreshToken(
            MicrosoftAuthConfig config, String refreshToken) {
        return authenticateWithRefreshToken(config, refreshToken, NO_ACCOUNT);
    }

    /**
     * Renews a session from a stored OAuth refresh token on one account's behalf. Every hop of the
     * chain (the token redemption, Xbox Live, XSTS, the Minecraft services login, and the profile
     * lookup) carries the account named by {@code account}, so a host's
     * {@link lol.trq.alts.spi.ProxyProvider} can give each account its own route. Without that, a
     * renewal sweep over many accounts sends all of its rate-limited requests from one address.
     *
     * @param config the host's Microsoft authentication configuration (client id, scope, endpoints)
     * @param refreshToken the stored refresh token to redeem
     * @param account a scope naming the account the token belongs to; only its account fields are read,
     *     and {@code null} means no account
     * @return a future containing the renewed {@link MinecraftProfile}
     * @throws NullPointerException if {@code config} is null
     * @since 0.12.0
     */
    public static CompletableFuture<MinecraftProfile> authenticateWithRefreshToken(
            MicrosoftAuthConfig config, String refreshToken, NetworkScope account) {
        Objects.requireNonNull(config, "config");
        if (refreshToken == null || refreshToken.isBlank()) {
            return CompletableFuture.failedFuture(new RefreshRejectedException("refresh token is blank", true));
        }
        return exchangeRefreshForToken(config, refreshToken, account)
                .thenCompose(tokens -> completeFrom(config, tokens, account));
    }

    /**
     * Signs in with the OAuth device-authorization grant: the host shows the user a short code and an
     * address, the user enters the code in any browser on any device, and the library polls until the
     * sign-in is approved, declined, or expires. No loopback port and no local browser are involved, so
     * it works on a headless or locked-down machine.
     *
     * <p>The library never opens a browser for this flow and never prints the code; presenting it is
     * entirely the {@link DeviceCodePrompt}'s job. Polling honours the interval the service advertises
     * and lengthens it by five seconds each time the service answers {@code slow_down}.
     *
     * <p>Cancelling the returned future stops the polling.
     *
     * <p><strong>Phishing.</strong> A device code signs in whoever started the flow. Start it only on an
     * explicit action by the user, and always show the real verification address; see
     * {@link DeviceCodePrompt}.
     *
     * @param config the host's Microsoft authentication configuration (client id, scope, endpoints)
     * @param prompt the host seam that shows the user the code and the verification address
     * @return a future containing the final {@link MinecraftProfile} on success
     * @throws NullPointerException if {@code config} or {@code prompt} is null
     * @since 0.12.0
     */
    public static CompletableFuture<MinecraftProfile> authenticateWithDeviceCode(
            MicrosoftAuthConfig config, DeviceCodePrompt prompt) {
        return authenticateWithDeviceCode(config, prompt, DeviceCodeTiming.STANDARD);
    }

    // Exists so the polling can be exercised in tests without waiting out real five-second intervals.
    static CompletableFuture<MinecraftProfile> authenticateWithDeviceCode(
            MicrosoftAuthConfig config, DeviceCodePrompt prompt, DeviceCodeTiming timing) {
        Objects.requireNonNull(config, "config");
        Objects.requireNonNull(prompt, "prompt");
        Objects.requireNonNull(timing, "timing");

        CompletableFuture<MsTokens> tokens = new CompletableFuture<>();
        CompletableFuture.runAsync(
                () -> {
                    try {
                        startDeviceCode(config, prompt, timing, tokens);
                    } catch (Throwable failure) {
                        tokens.completeExceptionally(failure);
                    }
                },
                IoExecutor.executor());
        return cancelling(tokens.thenCompose(issued -> completeFrom(config, issued, NO_ACCOUNT)), tokens);
    }

    /**
     * Requests a device code, hands it to the host, and schedules the first poll.
     *
     * @param config the host's Microsoft authentication configuration
     * @param prompt the host seam that shows the challenge
     * @param timing how advertised seconds map onto real delays
     * @param tokens the future the polling completes
     */
    private static void startDeviceCode(
            MicrosoftAuthConfig config,
            DeviceCodePrompt prompt,
            DeviceCodeTiming timing,
            CompletableFuture<MsTokens> tokens) {
        String body = "client_id=" + encode(config.clientId()) + "&scope=" + encode(config.scope());
        HttpUtil.HttpResponse response = send(
                "Device code request",
                () -> HttpUtil.postFormForStatus(config.deviceCodeUrl(), null, body, NO_ACCOUNT));

        DeviceAuthorization issued;
        try {
            issued = GSON.fromJson(response.body(), DeviceAuthorization.class);
        } catch (RuntimeException malformed) {
            throw unexpected("Device code request", malformed);
        }
        if (issued == null
                || isBlank(issued.deviceCode())
                || isBlank(issued.userCode())
                || isBlank(issued.verificationUri())) {
            throw unexpected("Device code request", null);
        }

        long lifetimeSeconds = issued.expiresIn() > 0 ? issued.expiresIn() : DeviceCodeTiming.DEFAULT_LIFETIME_SECONDS;
        long intervalSeconds = issued.interval() > 0 ? issued.interval() : DeviceCodeTiming.DEFAULT_INTERVAL_SECONDS;
        long lifetimeMillis = lifetimeSeconds * timing.secondMillis();

        // A cancellation that landed while the request was in flight: do not show a code nobody is
        // waiting on.
        if (tokens.isDone()) {
            return;
        }
        try {
            prompt.show(
                    issued.userCode(), issued.verificationUri(), Instant.now().plusMillis(lifetimeMillis));
        } catch (RuntimeException promptFailure) {
            throw new AuthFlowException("Device code prompt failed", FailureReason.UNKNOWN, promptFailure);
        }

        new DeviceCodePoll(
                        config,
                        issued.deviceCode(),
                        System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(lifetimeMillis),
                        intervalSeconds * timing.secondMillis(),
                        timing.slowDownMillis(),
                        tokens)
                .schedule();
    }

    /**
     * One device-code login's polling loop. Each poll is its own scheduled task, so no thread sleeps
     * between them, and each one first checks whether the login is still wanted, which is what makes a
     * cancelled future stop the polling rather than merely stop listening to it.
     */
    private static final class DeviceCodePoll implements Runnable {

        private final MicrosoftAuthConfig config;
        private final String deviceCode;
        private final long deadlineNanos;
        private final long slowDownMillis;
        private final CompletableFuture<MsTokens> tokens;
        private long intervalMillis;
        private int unanswered;

        DeviceCodePoll(
                MicrosoftAuthConfig config,
                String deviceCode,
                long deadlineNanos,
                long intervalMillis,
                long slowDownMillis,
                CompletableFuture<MsTokens> tokens) {
            this.config = config;
            this.deviceCode = deviceCode;
            this.deadlineNanos = deadlineNanos;
            this.intervalMillis = intervalMillis;
            this.slowDownMillis = slowDownMillis;
            this.tokens = tokens;
        }

        void schedule() {
            CompletableFuture.delayedExecutor(intervalMillis, TimeUnit.MILLISECONDS, IoExecutor.executor())
                    .execute(this);
        }

        @Override
        public void run() {
            if (tokens.isDone()) {
                return;
            }
            try {
                poll();
            } catch (Throwable failure) {
                tokens.completeExceptionally(failure);
            }
        }

        private void poll() {
            if (System.nanoTime() - deadlineNanos >= 0) {
                throw new AuthFlowException("Device code expired before it was used", FailureReason.TIMED_OUT);
            }

            HttpUtil.HttpResponse response;
            try {
                String body = "grant_type=" + encode(DEVICE_CODE_GRANT) + "&client_id=" + encode(config.clientId())
                        + "&device_code=" + encode(deviceCode);
                response = HttpUtil.postFormForStatus(config.deviceTokenUrl(), null, body, NO_ACCOUNT);
            } catch (Exception transportFailure) {
                unanswered(unreachable("Device code poll", transportFailure));
                return;
            }

            JsonObject json = response.body();
            if (response.successful() && json != null && json.has("access_token")) {
                tokens.complete(new MsTokens(stringOrNull(json, "access_token"), stringOrNull(json, "refresh_token")));
                return;
            }

            String error = json == null ? null : stringOrNull(json, "error");
            switch (error == null ? "" : error) {
                case "authorization_pending" -> again();
                case "slow_down" -> slowDown();
                case "authorization_declined", "access_denied" ->
                    throw new AuthFlowException("Device code sign-in was declined", FailureReason.DECLINED);
                case "expired_token" ->
                    throw new AuthFlowException("Device code expired before it was used", FailureReason.TIMED_OUT);
                case "bad_verification_code" ->
                    throw new AuthFlowException("Device code was not recognised", FailureReason.INVALID_TOKEN);
                default -> {
                    if (response.rateLimited()) {
                        slowDown();
                    } else if (response.status() >= 500 || response.status() == 408) {
                        unanswered(stepFailure("Device code poll", response));
                    } else {
                        throw stepFailure("Device code poll", response);
                    }
                }
            }
        }

        private void again() {
            unanswered = 0;
            schedule();
        }

        private void slowDown() {
            intervalMillis += slowDownMillis;
            again();
        }

        // A dropped connection or a 5xx says nothing about the code, and the user may be halfway through
        // typing it, so one bad poll must not end the login. A run of them means the service is gone.
        private void unanswered(AuthFlowException failure) {
            if (++unanswered >= MAX_UNANSWERED_POLLS) {
                throw failure;
            }
            schedule();
        }
    }

    /**
     * How the seconds a device-code response advertises map onto real delays. Production uses
     * {@link #STANDARD}; tests shrink the second so a slow-down can be observed without waiting for one.
     *
     * @param secondMillis how many milliseconds one advertised second lasts
     * @param slowDownMillis how much a {@code slow_down} answer lengthens the polling interval
     */
    record DeviceCodeTiming(long secondMillis, long slowDownMillis) {

        /** Real time: a second is a second, and {@code slow_down} adds the five the grant specifies. */
        static final DeviceCodeTiming STANDARD = new DeviceCodeTiming(1000L, 5000L);

        /** The polling interval assumed when the service advertises none. */
        static final long DEFAULT_INTERVAL_SECONDS = 5L;

        /** The code lifetime assumed when the service advertises none. */
        static final long DEFAULT_LIFETIME_SECONDS = 900L;
    }

    /**
     * The device-authorization response.
     *
     * @param deviceCode the secret the library redeems; never shown to the user
     * @param userCode the short code the user types
     * @param verificationUri the address the user types it at
     * @param expiresIn the code's lifetime in seconds
     * @param interval the minimum number of seconds between polls
     * @param message the service's own instructions for the user, unused
     */
    private record DeviceAuthorization(
            @SerializedName("device_code") String deviceCode,
            @SerializedName("user_code") String userCode,
            @SerializedName("verification_uri") String verificationUri,
            @SerializedName("expires_in") long expiresIn,
            @SerializedName("interval") long interval,
            @SerializedName("message") String message) {

        // The device code is a bearer credential until it expires, and the message embeds the user code.
        @Override
        public String toString() {
            return "DeviceAuthorization[deviceCode=" + redacted(deviceCode) + ", userCode=" + redacted(userCode)
                    + ", verificationUri=" + verificationUri + ", expiresIn=" + expiresIn + ", interval=" + interval
                    + ", message=" + redacted(message) + "]";
        }
    }

    /**
     * Returns a future mirroring {@code chain} whose cancellation also cancels {@code source}. A stage
     * derived with {@code thenCompose} does not pass a cancellation back up to the stage it came from,
     * so without this a caller cancelling a login would stop waiting for it while the callback server or
     * the polling it started carried on.
     *
     * @param chain the stage whose outcome the returned future mirrors
     * @param source the stage to cancel when the returned future is cancelled
     * @param <T> the result type
     * @return the mirroring future
     */
    static <T> CompletableFuture<T> cancelling(CompletableFuture<T> chain, CompletableFuture<?> source) {
        CompletableFuture<T> result = new CompletableFuture<>();
        chain.whenComplete((value, failure) -> {
            if (failure != null) {
                result.completeExceptionally(failure);
            } else {
                result.complete(value);
            }
        });
        result.whenComplete((value, failure) -> {
            if (result.isCancelled()) {
                source.cancel(true);
            }
        });
        return result;
    }

    /**
     * Runs the Xbox Live, XSTS, Minecraft services, and profile steps shared by every entry point.
     *
     * @param config the host's Microsoft authentication configuration
     * @param tokens the Microsoft tokens produced by whichever first step ran
     * @param account a scope naming the account this is for, or one naming none
     * @return a future containing the resolved profile
     */
    private static CompletableFuture<MinecraftProfile> completeFrom(
            MicrosoftAuthConfig config, MsTokens tokens, NetworkScope account) {
        return authenticateWithXboxLive(config, tokens, account)
                .thenCompose(xblToken -> authenticateWithXSTS(config, xblToken, account))
                .thenCompose(xstsData -> authenticateWithMinecraft(config, xstsData, account))
                .thenCompose(session -> getMinecraftProfile(config, session, tokens, account));
    }

    /**
     * Builds the scope for one hop, keeping the account and stating the hop's own purpose.
     *
     * @param purpose what this hop fetches
     * @param account a scope naming the account, or {@code null}
     * @return the hop's scope
     */
    private static NetworkScope scope(NetworkScope.Purpose purpose, NetworkScope account) {
        return account == null
                ? NetworkScope.of(purpose)
                : NetworkScope.forAccount(purpose, account.accountUuid(), account.accountUsername());
    }

    /**
     * Attempts to open the system's default web browser to the specified URL. Falls back to
     * OS-specific terminal commands if the Java Desktop API is unavailable.
     *
     * <p>The fallback passes the URL as a discrete argument rather than as one command line. The string
     * form of {@code exec} splits on whitespace, so a URL carrying any — from a host-supplied endpoint
     * or scope — would be handed to the launcher as several arguments and open the wrong thing.
     *
     * @param authUrl the Microsoft OAuth URL to open
     */
    public static void openBrowser(String authUrl) {
        boolean opened = false;
        try {
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                Desktop.getDesktop().browse(new URI(authUrl));
                opened = true;
            }
        } catch (Exception ignored) {
        }

        if (!opened) {
            try {
                String os = System.getProperty("os.name").toLowerCase(Locale.ROOT);
                Runtime rt = Runtime.getRuntime();
                if (os.contains("win")) {
                    rt.exec(new String[] {"rundll32", "url.dll,FileProtocolHandler", authUrl});
                } else if (os.contains("mac")) {
                    rt.exec(new String[] {"open", authUrl});
                } else if (os.contains("nix") || os.contains("nux")) {
                    rt.exec(new String[] {"xdg-open", authUrl});
                }
            } catch (Exception ignored) {
            }
        }
    }

    /**
     * Generates a cryptographically secure random state string to prevent CSRF.
     *
     * <p>{@link SecureRandom#getInstanceStrong()} is deliberately not used: it maps to a blocking
     * entropy source on some platforms, and its documented failure mode is an exception — which a
     * guessable fallback would answer by defeating the very check the state exists to make. The default
     * {@code SecureRandom} is cryptographically strong, never blocks, and cannot fail to construct.
     *
     * @return a random alphanumeric string
     */
    private static String generateState() {
        SecureRandom random = new SecureRandom();
        int length = random.nextInt(96, 128);
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(STATE_CHARS.charAt(random.nextInt(STATE_CHARS.length())));
        }
        return sb.toString();
    }

    /**
     * Generates a PKCE code verifier: 32 random bytes, which Base64url-encode to the 43 unreserved
     * characters the specification sets as the minimum length.
     *
     * @return the verifier
     */
    private static String generateCodeVerifier() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * Derives the {@code S256} PKCE challenge for a verifier.
     *
     * @param verifier the code verifier
     * @return the Base64url SHA-256 digest of the verifier, unpadded
     */
    static String codeChallenge(String verifier) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException impossible) {
            // SHA-256 is one of the algorithms every Java platform is required to provide.
            throw new IllegalStateException(impossible);
        }
    }

    /**
     * Step 1: exchanges the OAuth2 authorization code for Microsoft access and refresh tokens.
     *
     * @param config the host's Microsoft authentication configuration
     * @param code the authorization code received from the callback server
     * @param redirectUri the URI where the code was received
     * @param codeVerifier the PKCE verifier whose challenge the authorization request carried
     * @return a future containing the raw Microsoft tokens
     */
    static CompletableFuture<MsTokens> exchangeCodeForToken(
            MicrosoftAuthConfig config, String code, String redirectUri, String codeVerifier) {
        return CompletableFuture.supplyAsync(
                () -> {
                    String body = "client_id=" + encode(config.clientId()) + "&code=" + encode(code)
                            + "&grant_type=authorization_code&redirect_uri=" + encode(redirectUri) + "&scope="
                            + encode(config.scope()) + "&code_verifier=" + encode(codeVerifier);
                    JsonObject json = send(
                                    "Token exchange",
                                    () -> HttpUtil.postFormForStatus(config.tokenUrl(), null, body, NO_ACCOUNT))
                            .body();
                    return read(
                            "Token exchange",
                            () -> new MsTokens(
                                    json.get("access_token").getAsString(), stringOrNull(json, "refresh_token")));
                },
                IoExecutor.executor());
    }

    /**
     * Redeems a stored refresh token at the OAuth token endpoint, classifying a rejection as permanent
     * only when the error body states {@code invalid_grant} (see {@link #tokenIsSpent}) so neither an
     * outage, a rate limit, nor a host misconfiguration ever costs a working credential.
     *
     * @param config the host's Microsoft authentication configuration
     * @param refreshToken the stored refresh token to redeem
     * @param account a scope naming the account this is for, or one naming none
     * @return a future containing the freshly issued Microsoft tokens
     */
    private static CompletableFuture<MsTokens> exchangeRefreshForToken(
            MicrosoftAuthConfig config, String refreshToken, NetworkScope account) {
        return CompletableFuture.supplyAsync(
                () -> {
                    HttpUtil.HttpResponse response;
                    try {
                        String body = String.format(
                                "client_id=%s&refresh_token=%s&grant_type=refresh_token&scope=%s",
                                URLEncoder.encode(config.clientId(), StandardCharsets.UTF_8),
                                URLEncoder.encode(refreshToken, StandardCharsets.UTF_8),
                                URLEncoder.encode(config.scope(), StandardCharsets.UTF_8));
                        // A legacy MSA app rejects the grant outright unless it declares the redirect it was
                        // registered with. An OAuth app configures none and must not send one.
                        if (config.redirectUri() != null) {
                            body += "&redirect_uri=" + URLEncoder.encode(config.redirectUri(), StandardCharsets.UTF_8);
                        }
                        response = HttpUtil.postFormForStatus(
                                config.tokenUrl(), null, body, scope(NetworkScope.Purpose.AUTH, account));
                    } catch (Exception transportFailure) {
                        throw new RefreshRejectedException("refresh transport failure", false, transportFailure);
                    }

                    if (response.rateLimited()) {
                        // Said apart from an outage: the remedy is to wait, and a caller working through
                        // many accounts must stop sending rather than retry into the limit.
                        throw RefreshRejectedException.rateLimited(
                                "refresh rate limited with status " + response.status(), response.retryAfter());
                    }
                    if (!response.successful() || response.body() == null) {
                        throw new RefreshRejectedException(
                                "refresh rejected with status " + response.status(), tokenIsSpent(response));
                    }

                    JsonObject json = response.body();
                    String rotated = json.has("refresh_token")
                            ? json.get("refresh_token").getAsString()
                            : refreshToken;
                    return new MsTokens(json.get("access_token").getAsString(), rotated);
                },
                IoExecutor.executor());
    }

    /**
     * Decides whether a rejected redemption proves the refresh token itself is spent. Only the OAuth
     * {@code invalid_grant} error means that. A status alone never does: {@code 429} is the service
     * throttling and {@code 408} is a timed-out request, both of which recur under perfectly normal
     * load, and {@code invalid_client} / {@code invalid_scope} report a misconfigured host rather than a
     * used-up credential. Reading any of those as permanent would delete a working token over a
     * momentary condition, so everything short of a stated {@code invalid_grant} is transient.
     *
     * @param response the token endpoint's rejection
     * @return true only if the token will never be redeemable again
     */
    private static boolean tokenIsSpent(HttpUtil.HttpResponse response) {
        int status = response.status();
        if (status < 400 || status >= 500 || status == 408 || status == 429) {
            return false;
        }
        JsonObject body = response.body();
        if (body == null || !body.has("error") || !body.get("error").isJsonPrimitive()) {
            return false;
        }
        return "invalid_grant".equals(body.get("error").getAsString());
    }

    /**
     * Step 2: authenticates with the Xbox Live user authentication service.
     *
     * @param config the host's Microsoft authentication configuration
     * @param tokens the Microsoft tokens from the previous step
     * @param account a scope naming the account this is for, or one naming none
     * @return a future containing the Xbox Live token
     */
    private static CompletableFuture<String> authenticateWithXboxLive(
            MicrosoftAuthConfig config, MsTokens tokens, NetworkScope account) {
        return CompletableFuture.supplyAsync(
                () -> {
                    JsonObject body = new JsonObject();
                    JsonObject properties = new JsonObject();
                    properties.addProperty("AuthMethod", "RPS");
                    properties.addProperty("SiteName", "user.auth.xboxlive.com");
                    properties.addProperty("RpsTicket", config.rpsTicketPrefix() + tokens.accessToken());
                    body.add("Properties", properties);
                    body.addProperty("RelyingParty", "http://auth.xboxlive.com");
                    body.addProperty("TokenType", "JWT");

                    JsonObject json = send("Xbox Live auth", () -> postJson(config.xboxLiveAuthUrl(), body, account))
                            .body();
                    return read("Xbox Live auth", () -> json.get("Token").getAsString());
                },
                IoExecutor.executor());
    }

    /**
     * Step 3: authorizes with the XSTS (Xbox Security Token Service).
     *
     * @param config the host's Microsoft authentication configuration
     * @param xblToken the Xbox Live token from the previous step
     * @param account a scope naming the account this is for, or one naming none
     * @return a future containing the XSTS token and user hash
     */
    private static CompletableFuture<XstsData> authenticateWithXSTS(
            MicrosoftAuthConfig config, String xblToken, NetworkScope account) {
        return CompletableFuture.supplyAsync(
                () -> {
                    JsonObject body = new JsonObject();
                    JsonObject properties = new JsonObject();
                    JsonArray userTokens = new JsonArray();
                    userTokens.add(xblToken);
                    properties.add("UserTokens", userTokens);
                    properties.addProperty("SandboxId", "RETAIL");
                    body.add("Properties", properties);
                    body.addProperty("RelyingParty", "rp://api.minecraftservices.com/");
                    body.addProperty("TokenType", "JWT");

                    // Read the status so an XSTS refusal's XErr can be decoded: the endpoint answers a
                    // rejection with a code that says exactly what is wrong, which a bare "auth failed"
                    // throws away.
                    HttpUtil.HttpResponse status;
                    try {
                        status = postJson(config.xstsAuthUrl(), body, account);
                    } catch (Exception transportFailure) {
                        throw unreachable("XSTS auth", transportFailure);
                    }
                    if (!status.successful() || status.body() == null) {
                        throw xstsFailure(status);
                    }
                    JsonObject response = status.body();
                    return read(
                            "XSTS auth",
                            () -> new XstsData(
                                    response.get("Token").getAsString(),
                                    response.getAsJsonObject("DisplayClaims")
                                            .getAsJsonArray("xui")
                                            .get(0)
                                            .getAsJsonObject()
                                            .get("uhs")
                                            .getAsString()));
                },
                IoExecutor.executor());
    }

    /**
     * Step 4: finalizes authentication by obtaining a Minecraft services access token.
     *
     * @param config the host's Microsoft authentication configuration
     * @param xstsData the XSTS data from the previous step
     * @param account a scope naming the account this is for, or one naming none
     * @return a future containing the Minecraft services session and its lifetime
     */
    private static CompletableFuture<McSession> authenticateWithMinecraft(
            MicrosoftAuthConfig config, XstsData xstsData, NetworkScope account) {
        return CompletableFuture.supplyAsync(
                () -> {
                    JsonObject body = new JsonObject();
                    body.addProperty("identityToken", "XBL3.0 x=" + xstsData.uhs() + ";" + xstsData.token());
                    JsonObject json = send(
                                    "Minecraft services auth",
                                    () -> postJson(config.minecraftLoginUrl(), body, account))
                            .body();
                    return read("Minecraft services auth", () -> {
                        long expiresIn =
                                json.has("expires_in") ? json.get("expires_in").getAsLong() : 0L;
                        return new McSession(json.get("access_token").getAsString(), expiresIn);
                    });
                },
                IoExecutor.executor());
    }

    /**
     * Step 5: retrieves the Minecraft profile information (username and UUID).
     *
     * @param config the host's Microsoft authentication configuration
     * @param session the final Minecraft services session
     * @param tokens the Microsoft tokens the flow started from
     * @param account a scope naming the account this is for, or one naming none
     * @return a future containing the populated profile
     */
    private static CompletableFuture<MinecraftProfile> getMinecraftProfile(
            MicrosoftAuthConfig config, McSession session, MsTokens tokens, NetworkScope account) {
        return CompletableFuture.supplyAsync(
                () -> {
                    HttpUtil.HttpResponse response;
                    try {
                        response = HttpUtil.getForStatus(
                                config.minecraftProfileUrl(),
                                Map.of("Authorization", "Bearer " + session.accessToken()),
                                scope(NetworkScope.Purpose.PROFILE, account));
                    } catch (Exception transportFailure) {
                        throw unreachable("Profile fetch", transportFailure);
                    }
                    if (response.status() == 404) {
                        // Signed in, but there is no Minecraft profile behind the account.
                        throw new AuthFlowException(
                                "This account has no Minecraft profile", FailureReason.NOT_ENTITLED);
                    }
                    if (!response.successful() || response.body() == null) {
                        throw stepFailure("Profile fetch", response);
                    }
                    JsonObject profile = response.body();
                    return read(
                            "Profile fetch",
                            () -> new MinecraftProfile(
                                    profile.get("name").getAsString(),
                                    AuthFormats.dashedUuid(profile.get("id").getAsString()),
                                    session.accessToken(),
                                    tokens.refreshToken(),
                                    absoluteExpiry(session.expiresIn())));
                },
                IoExecutor.executor());
    }

    /**
     * Posts a JSON body on one account's behalf, returning the status alongside the parsed body.
     *
     * @param url the endpoint
     * @param body the JSON payload
     * @param account a scope naming the account this is for, or one naming none
     * @return the status and parsed body
     * @throws Exception if a network or protocol error occurs
     */
    private static HttpUtil.HttpResponse postJson(String url, JsonObject body, NetworkScope account) throws Exception {
        return HttpUtil.sendForStatus(
                "POST",
                url,
                "application/json",
                null,
                body.toString().getBytes(StandardCharsets.UTF_8),
                scope(NetworkScope.Purpose.AUTH, account));
    }

    /**
     * Sends one step's request and insists on a successful JSON answer, classifying anything else.
     *
     * @param step the step's name, for the failure message
     * @param request the request to send
     * @return the successful response, whose body is never null
     */
    private static HttpUtil.HttpResponse send(String step, Callable<HttpUtil.HttpResponse> request) {
        HttpUtil.HttpResponse response;
        try {
            response = request.call();
        } catch (Exception transportFailure) {
            throw unreachable(step, transportFailure);
        }
        if (!response.successful()) {
            throw stepFailure(step, response);
        }
        if (response.body() == null) {
            throw unexpected(step, null);
        }
        return response;
    }

    /**
     * Reads the fields a step needs out of its response, turning a missing or mistyped one into a
     * classified failure rather than a bare {@code NullPointerException}.
     *
     * @param step the step's name, for the failure message
     * @param reader the extraction to run
     * @param <T> the extracted type
     * @return the extracted value
     */
    private static <T> T read(String step, Supplier<T> reader) {
        try {
            return reader.get();
        } catch (RuntimeException malformed) {
            throw unexpected(step, malformed);
        }
    }

    /**
     * Classifies a step the service answered with a failure status. A throttle and an outage are kept
     * apart from a refusal: the first two say nothing about the credential.
     *
     * @param step the step's name
     * @param response the failing response
     * @return the exception to fail the flow with
     */
    static AuthFlowException stepFailure(String step, HttpUtil.HttpResponse response) {
        AuthFlowException classified = stepFailure(step, response.status());
        return response.retryAfter() == null
                ? classified
                : new AuthFlowException(classified.getMessage(), classified.reason(), response.retryAfter(), null);
    }

    /**
     * Classifies a failure status; see {@link #stepFailure(String, HttpUtil.HttpResponse)}.
     *
     * @param step the step's name
     * @param status the failing HTTP status
     * @return the exception to fail the flow with
     */
    static AuthFlowException stepFailure(String step, int status) {
        FailureReason reason;
        if (status == 429) {
            reason = FailureReason.RATE_LIMITED;
        } else if (status >= 500 || status == 408) {
            reason = FailureReason.NETWORK;
        } else {
            reason = FailureReason.INVALID_TOKEN;
        }
        return new AuthFlowException(step + " failed with status " + status, reason);
    }

    static AuthFlowException unreachable(String step, Exception transportFailure) {
        return new AuthFlowException(step + " could not be reached", FailureReason.NETWORK, transportFailure);
    }

    static AuthFlowException unexpected(String step, RuntimeException malformed) {
        return new AuthFlowException(step + " returned an unexpected response", FailureReason.UNKNOWN, malformed);
    }

    /**
     * Describes a failed sign-in step for a message a host will see. A failure this class classified
     * carries a message written here, from the step's name and a status, and that is used as it is. Any
     * other failure is described by its kind only: its own message was written by the JDK or the
     * transport, and may quote a token.
     *
     * @param failure the failure a step completed with
     * @return a description safe to show and to log
     */
    static String describe(Throwable failure) {
        if ((failure instanceof AuthFlowException || failure instanceof RefreshRejectedException)
                && failure.getMessage() != null) {
            return failure.getMessage();
        }
        return FailureText.of(failure);
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private static String stringOrNull(JsonObject json, String key) {
        return json.has(key) && json.get(key).isJsonPrimitive() ? json.get(key).getAsString() : null;
    }

    private static String redacted(String secret) {
        return secret == null ? "null" : "<redacted>";
    }

    /**
     * Finds the classified failure inside whatever a failed stage completed with. A stage wraps its
     * cause in a {@code CompletionException}, sometimes more than once, so the chain is walked.
     *
     * @param failure the throwable a stage completed with
     * @return the classified failure, or {@code null} when the chain holds none
     * @since 0.12.0
     */
    public static AuthFlowException classified(Throwable failure) {
        int depth = 0;
        for (Throwable current = failure; current != null && depth < 16; current = current.getCause(), depth++) {
            if (current instanceof AuthFlowException classified) {
                return classified;
            }
        }
        return null;
    }

    /**
     * Converts an advertised lifetime in seconds into an absolute epoch-millis expiry.
     *
     * @param expiresInSeconds the lifetime in seconds, or a non-positive value when unknown
     * @return the absolute expiry, or {@code 0} when the lifetime was unknown
     */
    private static long absoluteExpiry(long expiresInSeconds) {
        return expiresInSeconds <= 0 ? 0L : System.currentTimeMillis() + (expiresInSeconds * 1000L);
    }

    /**
     * Signals that a refresh-token redemption failed, distinguishing a token that will never work
     * again from a failure worth retrying.
     *
     * @author trq
     * @since 0.6.0
     */
    public static final class RefreshRejectedException extends RuntimeException {

        @Serial
        private static final long serialVersionUID = 1L;

        /**
         * Whether the refresh token is permanently spent.
         *
         * @serial
         */
        private final boolean permanent;

        /**
         * Whether the redemption was throttled.
         *
         * @serial
         */
        private final boolean rateLimited;

        /**
         * How long the service asked the caller to wait, or null.
         *
         * @serial
         */
        private final Duration retryAfter;

        /**
         * Creates a rejection.
         *
         * @param message the failure description
         * @param permanent whether the refresh token is permanently spent
         * @since 0.6.0
         */
        public RefreshRejectedException(String message, boolean permanent) {
            this(message, permanent, null);
        }

        /**
         * Creates a rejection carrying the underlying failure, so a connection error keeps its
         * diagnostic instead of being reported as a bare message.
         *
         * @param message the failure description
         * @param permanent whether the refresh token is permanently spent
         * @param cause the underlying failure, or {@code null}
         * @since 0.6.0
         */
        public RefreshRejectedException(String message, boolean permanent, Throwable cause) {
            super(message, cause);
            this.permanent = permanent;
            this.rateLimited = false;
            this.retryAfter = null;
        }

        private RefreshRejectedException(String message, Duration retryAfter) {
            super(message);
            this.permanent = false;
            this.rateLimited = true;
            this.retryAfter = retryAfter;
        }

        /**
         * Creates a rejection for a redemption the token endpoint throttled. Never permanent: a rate
         * limit says nothing about the refresh token.
         *
         * @param message the failure description
         * @param retryAfter how long the service asked the caller to wait, or {@code null} when it named
         *     no wait
         * @return the rejection
         * @since 0.12.0
         */
        public static RefreshRejectedException rateLimited(String message, Duration retryAfter) {
            return new RefreshRejectedException(message, retryAfter);
        }

        /**
         * Returns whether the token endpoint answered that the caller is sending too many requests.
         *
         * @return true if the redemption was throttled
         * @since 0.12.0
         */
        public boolean rateLimited() {
            return rateLimited;
        }

        /**
         * Returns how long the service asked the caller to wait before trying again, when it said.
         *
         * @return the stated wait, or {@code null} when none was given
         * @since 0.12.0
         */
        public Duration retryAfter() {
            return retryAfter;
        }

        /**
         * Returns whether the refresh token is permanently spent and must be discarded.
         *
         * @return true if the token will never succeed again
         * @since 0.6.0
         */
        public boolean permanent() {
            return permanent;
        }
    }

    // The Microsoft token's own lifetime is deliberately absent: the expiry that matters downstream is
    // the Minecraft services token's, which lasts far longer and is what the account is stamped with.
    /**
     * Builds a classified failure from an XSTS rejection, reading the {@code XErr} code out of the error
     * body so the reason survives to the caller.
     *
     * @param response the XSTS rejection
     * @return the exception to fail the flow with
     */
    private static AuthFlowException xstsFailure(HttpUtil.HttpResponse response) {
        long xerr = 0L;
        JsonObject body = response.body();
        if (body != null && body.has("XErr") && body.get("XErr").isJsonPrimitive()) {
            try {
                xerr = body.get("XErr").getAsLong();
            } catch (NumberFormatException ignored) {
                // Leave xerr at 0 -> UNKNOWN.
            }
        }
        XstsError error = XstsError.fromCode(xerr);
        int status = response.status();
        if (error == XstsError.UNKNOWN && (status == 429 || status == 408 || status >= 500)) {
            // No stated refusal: the service is throttling or failing, which is no verdict on the account.
            return stepFailure("XSTS auth", response);
        }
        return new XstsAuthException("XSTS auth failed (" + error + ", status " + status + ")", error);
    }

    /**
     * Signals that a step of the Microsoft sign-in chain failed, carrying a {@link FailureReason} so a
     * caller can tell an unreachable service from a throttled one from a refused credential without
     * reading the message. The message names the step and the status and never carries a token or code.
     *
     * @author trq
     * @since 0.12.0
     */
    public static class AuthFlowException extends RuntimeException {

        @Serial
        private static final long serialVersionUID = 1L;

        /**
         * The classified cause.
         *
         * @serial
         */
        private final FailureReason reason;

        /**
         * How long the service asked the caller to wait, or null.
         *
         * @serial
         */
        private final Duration retryAfter;

        /**
         * Creates a classified failure.
         *
         * @param message the failure description
         * @param reason the classified cause
         * @since 0.12.0
         */
        public AuthFlowException(String message, FailureReason reason) {
            this(message, reason, null);
        }

        /**
         * Creates a classified failure carrying the underlying one.
         *
         * @param message the failure description
         * @param reason the classified cause
         * @param cause the underlying failure, or {@code null}
         * @since 0.12.0
         */
        public AuthFlowException(String message, FailureReason reason, Throwable cause) {
            super(message, cause);
            this.reason = reason == null ? FailureReason.UNKNOWN : reason;
            this.retryAfter = null;
        }

        /**
         * Creates a classified failure carrying the wait the service asked for.
         *
         * @param message the failure description
         * @param reason the classified cause
         * @param retryAfter how long the service asked the caller to wait, or {@code null}
         * @param cause the underlying failure, or {@code null}
         * @since 0.12.0
         */
        public AuthFlowException(String message, FailureReason reason, Duration retryAfter, Throwable cause) {
            super(message, cause);
            this.reason = reason == null ? FailureReason.UNKNOWN : reason;
            this.retryAfter = retryAfter;
        }

        /**
         * Returns the classified cause.
         *
         * @return the reason, never {@code null}
         * @since 0.12.0
         */
        public FailureReason reason() {
            return reason;
        }

        /**
         * Returns how long the service asked the caller to wait before trying again, when it said.
         *
         * @return the stated wait, or {@code null} when none was given
         * @since 0.12.0
         */
        public Duration retryAfter() {
            return retryAfter;
        }
    }

    /**
     * Signals an XSTS authorization refusal, carrying the classified {@link XstsError} so a host can tell
     * the user what to fix rather than reporting a bare failure.
     *
     * @author trq
     * @since 1.0.0
     */
    public static final class XstsAuthException extends AuthFlowException {

        @Serial
        private static final long serialVersionUID = 1L;

        /**
         * The classified cause of the refusal.
         *
         * @serial
         */
        private final XstsError error;

        /**
         * Creates an XSTS failure.
         *
         * @param message the failure description
         * @param error the classified cause
         * @since 1.0.0
         */
        public XstsAuthException(String message, XstsError error) {
            super(message, FailureReason.XBOX_DENIED);
            this.error = error;
        }

        /**
         * Returns the classified cause of the refusal.
         *
         * @return the XSTS error
         * @since 1.0.0
         */
        public XstsError error() {
            return error;
        }
    }

    /** Holds the Microsoft OAuth access and refresh tokens. */
    private record MsTokens(String accessToken, String refreshToken) {
        @Override
        public String toString() {
            return "MsTokens[accessToken=" + redacted(accessToken) + ", refreshToken=" + redacted(refreshToken) + "]";
        }
    }

    /** Holds the Minecraft services session token and its advertised lifetime in seconds. */
    private record McSession(String accessToken, long expiresIn) {
        @Override
        public String toString() {
            return "McSession[accessToken=" + redacted(accessToken) + ", expiresIn=" + expiresIn + "]";
        }
    }

    /** Holds XSTS authorization data. */
    private record XstsData(String token, String uhs) {
        @Override
        public String toString() {
            return "XstsData[token=" + redacted(token) + ", uhs=" + redacted(uhs) + "]";
        }
    }
}

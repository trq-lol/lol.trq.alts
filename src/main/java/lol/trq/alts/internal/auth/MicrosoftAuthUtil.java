package lol.trq.alts.internal.auth;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.annotations.SerializedName;
import java.awt.Desktop;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
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
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.auth.MicrosoftAuthConfig;
import lol.trq.alts.auth.XstsError;
import lol.trq.alts.internal.net.FailureText;
import lol.trq.alts.internal.net.HttpTransport;
import lol.trq.alts.internal.net.MicrosoftCallbackServer;
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

    private final HttpTransport http;

    /**
     * Creates the sign-in chain over a transport: every request goes through it, and every blocking
     * step runs on its executor.
     *
     * @param http the runtime's transport
     * @since 1.0.0
     */
    public MicrosoftAuthUtil(HttpTransport http) {
        this.http = Objects.requireNonNull(http, "http");
    }

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
    public CompletableFuture<MinecraftProfile> authenticate(MicrosoftAuthConfig config) {
        return authenticate(config, MicrosoftAuthUtil::openBrowser);
    }

    // Exists so the interactive flow can be driven in tests without launching a real browser.
    CompletableFuture<MinecraftProfile> authenticate(MicrosoftAuthConfig config, Consumer<String> browser) {
        Objects.requireNonNull(config, "config");
        if (http.isClosed()) {
            // Neither bind a port nor open a browser for a sign-in nothing can finish.
            return CompletableFuture.failedFuture(new AltsException(Kind.CANCELLED, "the runtime is closed"));
        }
        String state = generateState();
        String verifier = generateCodeVerifier();
        MicrosoftCallbackServer server =
                new MicrosoftCallbackServer(state, config, codeChallenge(verifier), browser, http.executor());

        CompletableFuture<String> code = server.start();
        // A runtime closed while the user is still in the browser ends the sign-in, which stops the
        // callback listener and releases its port, rather than holding it until the sign-in times out.
        endWhenClosed(code);
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
    public CompletableFuture<MinecraftProfile> authenticateWithRefreshToken(
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
    public CompletableFuture<MinecraftProfile> authenticateWithRefreshToken(
            MicrosoftAuthConfig config, String refreshToken, NetworkScope account) {
        return authenticateWithRefreshToken(config, refreshToken, account, rotated -> {});
    }

    /**
     * Renews a session from a stored refresh token, telling {@code redeemed} the refresh token the token
     * endpoint issued as soon as it is issued, before the rest of the chain runs. The endpoint rotates
     * the token on every redemption and the one redeemed may not work again, so a caller that stores it
     * must keep the rotated one even when a later hop (Xbox Live, XSTS, the Minecraft services login)
     * fails.
     *
     * @param config the host's Microsoft authentication configuration (client id, scope, endpoints)
     * @param refreshToken the stored refresh token to redeem
     * @param account a scope naming the account the token belongs to, or {@code null} for none
     * @param redeemed receives the refresh token to keep from now on (the rotated one, or the redeemed
     *     one when none was issued); runs on the transport's executor, and a failure it throws fails the
     *     renewal
     * @return a future containing the renewed {@link MinecraftProfile}
     * @throws NullPointerException if {@code config} or {@code redeemed} is null
     * @since 1.0.0
     */
    public CompletableFuture<MinecraftProfile> authenticateWithRefreshToken(
            MicrosoftAuthConfig config, String refreshToken, NetworkScope account, Consumer<String> redeemed) {
        Objects.requireNonNull(config, "config");
        Objects.requireNonNull(redeemed, "redeemed");
        if (refreshToken == null || refreshToken.isBlank()) {
            return CompletableFuture.failedFuture(
                    new AltsException(Kind.REAUTH_REQUIRED, "Token refresh: no refresh token"));
        }
        return exchangeRefreshForToken(config, refreshToken, account)
                .thenApply(tokens -> {
                    redeemed.accept(tokens.refreshToken());
                    return tokens;
                })
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
    public CompletableFuture<MinecraftProfile> authenticateWithDeviceCode(
            MicrosoftAuthConfig config, DeviceCodePrompt prompt) {
        return authenticateWithDeviceCode(config, prompt, DeviceCodeTiming.STANDARD);
    }

    // Exists so the polling can be exercised in tests without waiting out real five-second intervals.
    CompletableFuture<MinecraftProfile> authenticateWithDeviceCode(
            MicrosoftAuthConfig config, DeviceCodePrompt prompt, DeviceCodeTiming timing) {
        Objects.requireNonNull(config, "config");
        Objects.requireNonNull(prompt, "prompt");
        Objects.requireNonNull(timing, "timing");

        CompletableFuture<MsTokens> tokens = new CompletableFuture<>();
        // Closing the runtime ends the polling at once, however long the next interval is.
        endWhenClosed(tokens);
        http.schedule(
                0L,
                () -> {
                    try {
                        startDeviceCode(config, prompt, timing, tokens);
                    } catch (Throwable failure) {
                        tokens.completeExceptionally(failure);
                    }
                },
                tokens::completeExceptionally);
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
    private void startDeviceCode(
            MicrosoftAuthConfig config,
            DeviceCodePrompt prompt,
            DeviceCodeTiming timing,
            CompletableFuture<MsTokens> tokens) {
        String body = "client_id=" + encode(config.clientId()) + "&scope=" + encode(config.scope());
        HttpTransport.HttpResponse response = send(
                "Device code request", () -> http.postFormForStatus(config.deviceCodeUrl(), null, body, NO_ACCOUNT));

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

        // Both numbers are the service's to state and neither is taken on trust: unbounded, an interval
        // would park the login for as long as the response cared to say, and either would overflow once
        // multiplied out.
        long lifetimeSeconds = DeviceCodeTiming.lifetimeSeconds(issued.expiresIn());
        long intervalSeconds = DeviceCodeTiming.intervalSeconds(issued.interval());
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
            throw new AltsException(AltsFailure.of(Kind.UNKNOWN, "Device code prompt failed"), promptFailure);
        }

        new DeviceCodePoll(
                        config,
                        issued.deviceCode(),
                        System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(lifetimeMillis),
                        intervalSeconds * timing.secondMillis(),
                        DeviceCodeTiming.MAX_INTERVAL_SECONDS * timing.secondMillis(),
                        timing.slowDownMillis(),
                        tokens)
                .schedule();
    }

    /**
     * One device-code login's polling loop. Each poll is its own scheduled task, so no thread sleeps
     * between them, and each one first checks whether the login is still wanted, which is what makes a
     * cancelled future stop the polling rather than merely stop listening to it.
     */
    private final class DeviceCodePoll implements Runnable {

        private final MicrosoftAuthConfig config;
        private final String deviceCode;
        private final long deadlineNanos;
        private final long maxIntervalMillis;
        private final long slowDownMillis;
        private final CompletableFuture<MsTokens> tokens;
        private long intervalMillis;
        private int unanswered;

        DeviceCodePoll(
                MicrosoftAuthConfig config,
                String deviceCode,
                long deadlineNanos,
                long intervalMillis,
                long maxIntervalMillis,
                long slowDownMillis,
                CompletableFuture<MsTokens> tokens) {
            this.config = config;
            this.deviceCode = deviceCode;
            this.deadlineNanos = deadlineNanos;
            this.intervalMillis = intervalMillis;
            this.maxIntervalMillis = maxIntervalMillis;
            this.slowDownMillis = slowDownMillis;
            this.tokens = tokens;
        }

        void schedule() {
            // A runtime closed between polls ends the login rather than leaving it waiting for good.
            http.schedule(intervalMillis, this, tokens::completeExceptionally);
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
                throw new AltsException(Kind.TIMED_OUT, "Device code expired before it was used");
            }

            HttpTransport.HttpResponse response;
            try {
                String body = "grant_type=" + encode(DEVICE_CODE_GRANT) + "&client_id=" + encode(config.clientId())
                        + "&device_code=" + encode(deviceCode);
                response = http.postFormForStatus(config.deviceTokenUrl(), null, body, NO_ACCOUNT);
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
                    throw new AltsException(Kind.DECLINED, "Device code sign-in was declined");
                case "expired_token" ->
                    throw new AltsException(Kind.TIMED_OUT, "Device code expired before it was used");
                case "bad_verification_code" ->
                    throw new AltsException(Kind.UNAUTHORIZED, "Device code was not recognised");
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
            // Capped like the advertised interval: a service that answers slow_down every time must not
            // be able to stretch the gap between polls without limit.
            intervalMillis = Math.min(maxIntervalMillis, intervalMillis + Math.max(0L, slowDownMillis));
            again();
        }

        // A dropped connection or a 5xx says nothing about the code, and the user may be halfway through
        // typing it, so one bad poll must not end the login. A run of them means the service is gone.
        private void unanswered(AltsException failure) {
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

        /** The shortest gap between polls, whatever the service advertises. */
        static final long MIN_INTERVAL_SECONDS = 1L;

        /** The longest gap between polls, whatever the service advertises or asks for later. */
        static final long MAX_INTERVAL_SECONDS = 60L;

        /** The longest a code is waited on, whatever lifetime the service advertises: thirty minutes. */
        static final long MAX_LIFETIME_SECONDS = 1800L;

        /**
         * Returns the polling interval to use for an advertised one.
         *
         * @param advertised the {@code interval} the service sent, in seconds; zero or less when absent
         * @return the default when none was advertised, otherwise the advertised value held within
         *     {@link #MIN_INTERVAL_SECONDS} and {@link #MAX_INTERVAL_SECONDS}
         */
        static long intervalSeconds(long advertised) {
            if (advertised <= 0) {
                return DEFAULT_INTERVAL_SECONDS;
            }
            return Math.max(MIN_INTERVAL_SECONDS, Math.min(MAX_INTERVAL_SECONDS, advertised));
        }

        /**
         * Returns how long to wait on a code for an advertised lifetime.
         *
         * @param advertised the {@code expires_in} the service sent, in seconds; zero or less when absent
         * @return the default when none was advertised, otherwise the advertised value, at most
         *     {@link #MAX_LIFETIME_SECONDS}
         */
        static long lifetimeSeconds(long advertised) {
            if (advertised <= 0) {
                return DEFAULT_LIFETIME_SECONDS;
            }
            return Math.min(MAX_LIFETIME_SECONDS, advertised);
        }
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
     * Fails {@code waiting} with an {@link AltsException} of kind {@link Kind#CANCELLED} when the
     * transport closes first, and forgets it once it completes some other way.
     *
     * @param waiting the future a sign-in is waiting on
     */
    private void endWhenClosed(CompletableFuture<?> waiting) {
        AutoCloseable registration = http.whenClosed(
                () -> waiting.completeExceptionally(new AltsException(Kind.CANCELLED, "the runtime is closed")));
        waiting.whenComplete((value, failure) -> {
            try {
                registration.close();
            } catch (Exception ignored) {
                // Unregistering removes from a set; it does not fail.
            }
        });
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
    private CompletableFuture<MinecraftProfile> completeFrom(
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
    CompletableFuture<MsTokens> exchangeCodeForToken(
            MicrosoftAuthConfig config, String code, String redirectUri, String codeVerifier) {
        return CompletableFuture.supplyAsync(
                () -> {
                    String body = "client_id=" + encode(config.clientId()) + "&code=" + encode(code)
                            + "&grant_type=authorization_code&redirect_uri=" + encode(redirectUri) + "&scope="
                            + encode(config.scope()) + "&code_verifier=" + encode(codeVerifier);
                    JsonObject json = send(
                                    "Token exchange",
                                    () -> http.postFormForStatus(config.tokenUrl(), null, body, NO_ACCOUNT))
                            .body();
                    return read(
                            "Token exchange",
                            () -> new MsTokens(
                                    json.get("access_token").getAsString(), stringOrNull(json, "refresh_token")));
                },
                http.executor());
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
    private CompletableFuture<MsTokens> exchangeRefreshForToken(
            MicrosoftAuthConfig config, String refreshToken, NetworkScope account) {
        return CompletableFuture.supplyAsync(
                () -> {
                    HttpTransport.HttpResponse response;
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
                        response = http.postFormForStatus(
                                config.tokenUrl(), null, body, scope(NetworkScope.Purpose.AUTH, account));
                    } catch (Exception transportFailure) {
                        throw unreachable("Token refresh", transportFailure);
                    }

                    if (response.rateLimited()) {
                        // Said apart from an outage: the remedy is to wait, and a caller working through
                        // many accounts must stop sending rather than retry into the limit.
                        throw new AltsException(AltsFailure.rateLimited(
                                "Token refresh rate limited with status " + response.status(), response.retryAfter()));
                    }
                    if (!response.successful()) {
                        throw refreshRejected(response);
                    }
                    if (response.body() == null) {
                        throw unexpected("Token refresh", null);
                    }

                    // Read defensively: a 2xx whose body lacks the access token, or names a null refresh
                    // token, is a step that failed, not a reason to throw a bare NullPointerException that
                    // nothing downstream can classify. The token in hand is kept when none was issued.
                    JsonObject json = response.body();
                    String access = stringOrNull(json, "access_token");
                    if (isBlank(access)) {
                        throw unexpected("Token refresh", null);
                    }
                    String rotated = stringOrNull(json, "refresh_token");
                    return new MsTokens(access, isBlank(rotated) ? refreshToken : rotated);
                },
                http.executor());
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
    private static boolean tokenIsSpent(HttpTransport.HttpResponse response) {
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
    private CompletableFuture<String> authenticateWithXboxLive(
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
                http.executor());
    }

    /**
     * Step 3: authorizes with the XSTS (Xbox Security Token Service).
     *
     * @param config the host's Microsoft authentication configuration
     * @param xblToken the Xbox Live token from the previous step
     * @param account a scope naming the account this is for, or one naming none
     * @return a future containing the XSTS token and user hash
     */
    private CompletableFuture<XstsData> authenticateWithXSTS(
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
                    HttpTransport.HttpResponse status;
                    try {
                        status = postJson(config.xstsAuthUrl(), body, account);
                    } catch (Exception transportFailure) {
                        throw unreachable("XSTS auth", transportFailure);
                    }
                    if (!status.successful()) {
                        throw xstsFailure(status);
                    }
                    if (status.body() == null) {
                        // A success that carries no token is no verdict on the account.
                        throw unexpected("XSTS auth", null);
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
                http.executor());
    }

    /**
     * Step 4: finalizes authentication by obtaining a Minecraft services access token.
     *
     * @param config the host's Microsoft authentication configuration
     * @param xstsData the XSTS data from the previous step
     * @param account a scope naming the account this is for, or one naming none
     * @return a future containing the Minecraft services session and its lifetime
     */
    private CompletableFuture<McSession> authenticateWithMinecraft(
            MicrosoftAuthConfig config, XstsData xstsData, NetworkScope account) {
        return CompletableFuture.supplyAsync(
                () -> {
                    JsonObject body = new JsonObject();
                    body.addProperty("identityToken", "XBL3.0 x=" + xstsData.uhs() + ";" + xstsData.token());
                    JsonObject json = send(
                                    "Minecraft services auth",
                                    () -> postJson(config.minecraftLoginUrl(), body, account),
                                    MicrosoftAuthUtil::minecraftLoginFailure)
                            .body();
                    return read("Minecraft services auth", () -> {
                        long expiresIn =
                                json.has("expires_in") ? json.get("expires_in").getAsLong() : 0L;
                        return new McSession(json.get("access_token").getAsString(), expiresIn);
                    });
                },
                http.executor());
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
    private CompletableFuture<MinecraftProfile> getMinecraftProfile(
            MicrosoftAuthConfig config, McSession session, MsTokens tokens, NetworkScope account) {
        return CompletableFuture.supplyAsync(
                () -> {
                    HttpTransport.HttpResponse response;
                    try {
                        response = http.getForStatus(
                                config.minecraftProfileUrl(),
                                Map.of("Authorization", "Bearer " + session.accessToken()),
                                scope(NetworkScope.Purpose.PROFILE, account));
                    } catch (Exception transportFailure) {
                        throw unreachable("Profile fetch", transportFailure);
                    }
                    if (response.status() == 404) {
                        // Signed in, but there is no Minecraft profile behind the account.
                        throw new AltsException(Kind.NOT_ENTITLED, "This account has no Minecraft profile");
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
                http.executor());
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
    private HttpTransport.HttpResponse postJson(String url, JsonObject body, NetworkScope account) throws Exception {
        return http.sendForStatus(
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
    private static HttpTransport.HttpResponse send(String step, Callable<HttpTransport.HttpResponse> request) {
        return send(step, request, response -> stepFailure(step, response));
    }

    /**
     * Sends one step's request and insists on a successful JSON answer, classifying a failure status with
     * {@code onFailure}.
     *
     * @param step the step's name, for the failure message
     * @param request the request to send
     * @param onFailure classifies a failure status
     * @return the successful response, whose body is never null
     */
    private static HttpTransport.HttpResponse send(
            String step,
            Callable<HttpTransport.HttpResponse> request,
            java.util.function.Function<HttpTransport.HttpResponse, AltsException> onFailure) {
        HttpTransport.HttpResponse response;
        try {
            response = request.call();
        } catch (Exception transportFailure) {
            throw unreachable(step, transportFailure);
        }
        if (!response.successful()) {
            throw onFailure.apply(response);
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
    static AltsException stepFailure(String step, HttpTransport.HttpResponse response) {
        return new AltsException(AltsFailure.of(
                clientRefused(response) ? Kind.NOT_CONFIGURED : kindForStatus(response.status()),
                step + " failed with status " + response.status(),
                response.retryAfter()));
    }

    /**
     * Classifies a failed Minecraft services login ({@code login_with_xbox}). A {@code 403} there is the
     * service refusing the host's client registration, which it answers to every account until the
     * registration is approved for it, so it is {@link Kind#NOT_CONFIGURED}: no retry and no fresh
     * sign-in fixes it. Every other status is classified as any step's.
     *
     * @param response the failing response
     * @return the exception to fail the flow with
     */
    private static AltsException minecraftLoginFailure(HttpTransport.HttpResponse response) {
        if (response.status() == 403) {
            return new AltsException(Kind.NOT_CONFIGURED, "Minecraft services auth refused the client registration");
        }
        return stepFailure("Minecraft services auth", response);
    }

    /**
     * Returns whether a token endpoint refused the host's client registration rather than the user's
     * credential: OAuth's {@code invalid_client} or {@code unauthorized_client}. That is a host
     * misconfiguration ({@link Kind#NOT_CONFIGURED}), which no retry and no fresh sign-in fixes.
     *
     * @param response the failing response
     * @return true when the body states one of those two errors
     */
    private static boolean clientRefused(HttpTransport.HttpResponse response) {
        JsonObject body = response.body();
        String error = body == null ? null : stringOrNull(body, "error");
        return "invalid_client".equals(error) || "unauthorized_client".equals(error);
    }

    /**
     * Classifies a failure status; see {@link #stepFailure(String, HttpTransport.HttpResponse)}.
     *
     * @param step the step's name
     * @param status the failing HTTP status
     * @return the exception to fail the flow with
     */
    static AltsException stepFailure(String step, int status) {
        return new AltsException(kindForStatus(status), step + " failed with status " + status);
    }

    /**
     * Returns the kind a sign-in step's failure status is: {@code 429} a throttle, a {@code 5xx} or a
     * {@code 408} an outage, and any other a refusal of the credential.
     *
     * @param status the failing HTTP status
     * @return the kind
     */
    private static Kind kindForStatus(int status) {
        if (status == 429) {
            return Kind.RATE_LIMITED;
        }
        if (status >= 500 || status == 408) {
            return Kind.NETWORK;
        }
        return Kind.UNAUTHORIZED;
    }

    /**
     * Classifies a step whose request never got an answer, by the failure's type; its text is never
     * repeated.
     *
     * @param step the step's name
     * @param transportFailure what the transport threw
     * @return the exception to fail the flow with
     */
    static AltsException unreachable(String step, Exception transportFailure) {
        return FailureText.toException(step, transportFailure);
    }

    /**
     * Classifies a step that answered successfully with a body the flow could not read.
     *
     * @param step the step's name
     * @param malformed what reading it threw, or {@code null} when a field was simply absent
     * @return the exception to fail the flow with
     */
    static AltsException unexpected(String step, RuntimeException malformed) {
        return new AltsException(AltsFailure.of(Kind.PROTOCOL, step + " returned an unexpected response"), malformed);
    }

    /**
     * Classifies a refused refresh-token redemption. Only a stated {@code invalid_grant} (see
     * {@link #tokenIsSpent}) is {@link Kind#REAUTH_REQUIRED}; a refused client registration
     * ({@code invalid_client} or {@code unauthorized_client}) is {@link Kind#NOT_CONFIGURED}; an outage
     * stays {@link Kind#NETWORK}; and any other refusal is {@link Kind#UNAUTHORIZED}. None but the first
     * costs the stored credential anything.
     *
     * @param response the token endpoint's rejection, not a {@code 429}
     * @return the exception to fail the flow with
     */
    private static AltsException refreshRejected(HttpTransport.HttpResponse response) {
        String message = "Token refresh rejected with status " + response.status();
        if (tokenIsSpent(response)) {
            return new AltsException(Kind.REAUTH_REQUIRED, message);
        }
        Kind kind = clientRefused(response) ? Kind.NOT_CONFIGURED : kindForStatus(response.status());
        return new AltsException(AltsFailure.of(kind, message, response.retryAfter()));
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
     * Converts an advertised lifetime in seconds into an absolute epoch-millis expiry.
     *
     * @param expiresInSeconds the lifetime in seconds, or a non-positive value when unknown
     * @return the absolute expiry, or {@code 0} when the lifetime was unknown
     */
    private static long absoluteExpiry(long expiresInSeconds) {
        return expiresInSeconds <= 0 ? 0L : System.currentTimeMillis() + (expiresInSeconds * 1000L);
    }

    // The Microsoft token's own lifetime is deliberately absent: the expiry that matters downstream is
    // the Minecraft services token's, which lasts far longer and is what the account is stamped with.
    /**
     * Builds a classified failure from an XSTS rejection, reading the {@code XErr} code out of the error
     * body so the reason survives to the caller as {@link AltsFailure#xstsError()}.
     *
     * @param response the XSTS rejection
     * @return the exception to fail the flow with
     */
    private static AltsException xstsFailure(HttpTransport.HttpResponse response) {
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
        return new AltsException(
                AltsFailure.xboxDenied("XSTS auth failed (" + error + ", status " + status + ")", error));
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

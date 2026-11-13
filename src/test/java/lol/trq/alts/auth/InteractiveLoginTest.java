package lol.trq.alts.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import lol.trq.alts.AltsFailure;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.model.AltAccount;
import lol.trq.alts.model.LoginMode;
import lol.trq.alts.model.SessionData;
import lol.trq.alts.net.HttpTransport;
import lol.trq.alts.net.NetworkScope;
import lol.trq.alts.net.ProxyRoute;
import lol.trq.alts.net.TestTransports;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The browser route, driven end to end with a stand-in for the browser: something that reads the
 * authorization address the library produced and calls the loopback redirect back, as the identity
 * service would after the user signed in.
 */
@org.junit.jupiter.api.Timeout(value = 60, unit = java.util.concurrent.TimeUnit.SECONDS)
class InteractiveLoginTest {

    @TempDir
    Path vaultDir;

    private AccountStoreTestSupport localStore;

    private AuthChainServer chain;
    private final AtomicReference<SessionData> injected = new AtomicReference<>();
    private final AtomicReference<String> authorizationUrl = new AtomicReference<>();

    @BeforeEach
    void setUp() throws IOException {
        localStore = AccountStoreTestSupport.openIn(vaultDir);
        chain = new AuthChainServer();
    }

    @AfterEach
    void tearDown() {
        localStore.close();
        chain.close();
    }

    /** A service whose "browser" completes the sign-in the moment it is opened. */
    private AltLoginServiceImpl service() {
        AltLoginServiceImpl service =
                new AltLoginServiceImpl(localStore.store(), injected::set, chain.config(), TestTransports.direct());
        service.browser = url -> {
            authorizationUrl.set(url);
            AuthChainServer.completeInBrowser(url);
        };
        return service;
    }

    private LoginResult login() throws Exception {
        return service().loginMicrosoft(LoginMode.DIRECT).get(10, TimeUnit.SECONDS);
    }

    @Test
    void theBrowserRouteLogsInAndKeepsTheRefreshToken() throws Exception {
        LoginResult result = service().loginMicrosoft(LoginMode.ADD).get(10, TimeUnit.SECONDS);

        assertTrue(result.success(), result.message());
        assertEquals("Alex", injected.get().username());
        AltAccount persisted = localStore.reloadFromDiskAndFind(AuthChainServer.UUID);
        assertEquals("ms-refresh", persisted.refreshToken());
    }

    @Test
    void theAuthorizationRequestAndTheTokenExchangeCarryAMatchingPkcePair() throws Exception {
        LoginResult result = login();
        assertTrue(result.success(), result.message());

        Map<String, String> authorize = AuthChainServer.query(authorizationUrl.get());
        Map<String, String> exchange = chain.lastForm("/token");

        assertEquals("S256", authorize.get("code_challenge_method"));
        String verifier = exchange.get("code_verifier");
        assertNotNull(verifier, "the exchange must prove possession of the verifier");
        assertTrue(verifier.length() >= 43, "the verifier is at least the specified minimum length");
        assertTrue(verifier.matches("[A-Za-z0-9\\-._~]+"), "the verifier uses only unreserved characters");

        byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
        assertEquals(
                Base64.getUrlEncoder().withoutPadding().encodeToString(digest),
                authorize.get("code_challenge"),
                "the challenge sent to the authorize endpoint is the S256 digest of the verifier sent later");
        assertEquals("auth-code", exchange.get("code"));
        assertFalse(authorizationUrl.get().contains(verifier), "the verifier itself never goes to the browser");
    }

    @Test
    void everyLoginUsesAFreshVerifier() throws Exception {
        login();
        String first = chain.lastForm("/token").get("code_verifier");
        login();
        String second = chain.lastForm("/token").get("code_verifier");

        assertFalse(first.equals(second));
    }

    @Test
    void cancellingTheLoginReleasesTheCallbackPort() throws Exception {
        AltLoginServiceImpl service =
                new AltLoginServiceImpl(localStore.store(), injected::set, chain.config(), TestTransports.direct());
        service.browser = authorizationUrl::set;

        CompletableFuture<LoginResult> login = service.loginMicrosoft(LoginMode.DIRECT);
        waitUntil(() -> authorizationUrl.get() != null);
        int port = URI.create(AuthChainServer.query(authorizationUrl.get()).get("redirect_uri"))
                .getPort();
        assertFalse(canBind(port), "the callback server is listening while the login is pending");

        assertTrue(login.cancel(true));

        assertThrows(CancellationException.class, login::join);
        waitUntil(() -> canBind(port));
        assertNull(injected.get());
    }

    /**
     * A runtime closed while the user is still in the browser ends the sign-in and releases the port,
     * rather than holding it until the sign-in times out; with the runtime's own executor shut down, the
     * listener is stopped on the thread that ends it.
     */
    @Test
    void closingTheRuntimeEndsTheSignInAndReleasesTheCallbackPort() throws Exception {
        ExecutorService owned =
                Executors.newThreadPerTaskExecutor(Thread.ofVirtual().factory());
        HttpTransport transport = TestTransports.on(null, owned);
        AltLoginServiceImpl service =
                new AltLoginServiceImpl(localStore.store(), injected::set, chain.config(), transport);
        service.browser = authorizationUrl::set;

        CompletableFuture<LoginResult> login = service.loginMicrosoft(LoginMode.DIRECT);
        waitUntil(() -> authorizationUrl.get() != null);
        int port = URI.create(AuthChainServer.query(authorizationUrl.get()).get("redirect_uri"))
                .getPort();
        assertFalse(canBind(port), "the callback server is listening while the login is pending");

        transport.close();
        owned.shutdown();

        assertFalse(login.get(2, TimeUnit.SECONDS).success(), "the sign-in ended with the runtime");
        waitUntil(() -> canBind(port));
        assertNull(injected.get());
    }

    /**
     * The listener is stopped even when its executor is gone before the sign-in ends, as a host's own
     * executor can be: the stop then runs on the thread that ends the sign-in.
     */
    @Test
    void anExecutorShutDownFirstStillLeavesThePortReleased() throws Exception {
        ExecutorService owned =
                Executors.newThreadPerTaskExecutor(Thread.ofVirtual().factory());
        HttpTransport transport = TestTransports.on(null, owned);
        AltLoginServiceImpl service =
                new AltLoginServiceImpl(localStore.store(), injected::set, chain.config(), transport);
        service.browser = authorizationUrl::set;

        CompletableFuture<LoginResult> login = service.loginMicrosoft(LoginMode.DIRECT);
        waitUntil(() -> authorizationUrl.get() != null);
        int port = URI.create(AuthChainServer.query(authorizationUrl.get()).get("redirect_uri"))
                .getPort();

        owned.shutdown();
        transport.close();

        assertFalse(login.get(2, TimeUnit.SECONDS).success());
        waitUntil(() -> canBind(port));
    }

    @Test
    void aRoutedBrowserSignInCarriesItsTagOnTheTokenExchangeAndEveryHopAfter() throws Exception {
        List<NetworkScope> scopes = new CopyOnWriteArrayList<>();
        AltLoginServiceImpl service = new AltLoginServiceImpl(
                localStore.store(), injected::set, chain.config(), TestTransports.through(scope -> {
                    scopes.add(scope);
                    return ProxyRoute.direct();
                }));
        service.browser = AuthChainServer::completeInBrowser;

        LoginResult result =
                service.routed("pool-7").loginMicrosoft(LoginMode.DIRECT).get(10, TimeUnit.SECONDS);

        assertTrue(result.success(), result.message());
        assertEquals(5, scopes.size(), "token exchange, Xbox Live, XSTS, Minecraft login, profile: " + scopes);
        for (NetworkScope scope : scopes) {
            assertEquals(Optional.of("pool-7"), scope.routeTag(), "a hop left without the tag: " + scope);
        }
    }

    @Test
    void anXboxRefusalIsClassifiedAndCarriesItsCause() throws Exception {
        chain.fail("/xsts", 401, "{\"XErr\":2148916233}");

        LoginResult result = login();

        assertFalse(result.success());
        assertEquals(Kind.XBOX_DENIED, result.failure().map(AltsFailure::kind).orElse(null));
        assertEquals(
                XstsError.NO_XBOX_ACCOUNT,
                result.failure().flatMap(AltsFailure::xstsError).orElse(null));
    }

    @Test
    void aThrottledStepIsRateLimitedNotARefusal() throws Exception {
        chain.fail("/xbl", 429);

        LoginResult result = login();

        assertEquals(Kind.RATE_LIMITED, result.failure().map(AltsFailure::kind).orElse(null));
        assertNull(result.failure().flatMap(AltsFailure::xstsError).orElse(null));
    }

    @Test
    void aThrottledXstsStepWithNoStatedCauseIsRateLimitedToo() throws Exception {
        chain.fail("/xsts", 429);

        assertEquals(Kind.RATE_LIMITED, login().failure().map(AltsFailure::kind).orElse(null));
    }

    @Test
    void aFailingServiceIsANetworkFailure() throws Exception {
        chain.fail("/token", 503);

        assertEquals(Kind.NETWORK, login().failure().map(AltsFailure::kind).orElse(null));
    }

    @Test
    void anUnreachableServiceIsANetworkFailure() throws Exception {
        int deadPort;
        try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            deadPort = socket.getLocalPort();
        }
        String dead = "http://" + InetAddress.getLoopbackAddress().getHostAddress() + ":" + deadPort;
        AltLoginServiceImpl service = new AltLoginServiceImpl(
                localStore.store(),
                injected::set,
                chain.config().withEndpoints(null, dead + "/token", null, null, null, null),
                TestTransports.direct());
        service.browser = AuthChainServer::completeInBrowser;

        LoginResult result = service.loginMicrosoft(LoginMode.DIRECT).get(30, TimeUnit.SECONDS);

        assertEquals(Kind.NETWORK, result.failure().map(AltsFailure::kind).orElse(null));
    }

    @Test
    void aRefusedCredentialIsAnInvalidToken() throws Exception {
        chain.fail("/mclogin", 401);

        assertEquals(Kind.UNAUTHORIZED, login().failure().map(AltsFailure::kind).orElse(null));
    }

    @Test
    void anAccountWithNoProfileIsNotEntitled() throws Exception {
        chain.fail("/mcprofile", 404);

        assertEquals(Kind.NOT_ENTITLED, login().failure().map(AltsFailure::kind).orElse(null));
    }

    @Test
    void aFailureMessageNeverCarriesAToken() throws Exception {
        chain.fail("/mclogin", 401);

        String message = login().message();

        for (String secret : new String[] {"ms-access", "ms-refresh", "xbl", "xsts", "auth-code"}) {
            assertFalse(message.contains(secret), message);
        }
    }

    private static boolean canBind(int port) {
        try (ServerSocket socket = new ServerSocket(port, 1, InetAddress.getLoopbackAddress())) {
            return true;
        } catch (IOException inUse) {
            return false;
        }
    }

    private static void waitUntil(java.util.function.BooleanSupplier condition) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError("condition was not met in time");
            }
            Thread.sleep(10);
        }
    }
}

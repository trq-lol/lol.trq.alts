package lol.trq.alts.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.AltsRuntime;
import lol.trq.alts.model.AccountType;
import lol.trq.alts.model.AltAccount;
import lol.trq.alts.model.LoginMode;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Every sign-in route and every check or refresh started after the runtime closed hands back a future,
 * never a throw at the caller, and that future holds a result whose failure is
 * {@link Kind#CANCELLED}: on the runtime's own executor, which refuses the task, and on a host's
 * executor, which runs it into a closed transport.
 */
@org.junit.jupiter.api.Timeout(value = 60, unit = java.util.concurrent.TimeUnit.SECONDS)
class ClosedRuntimeRoutesTest {

    /** Nothing listens here, and nothing must try: a closed transport refuses before connecting. */
    private static final String NOWHERE = "http://127.0.0.1:9";

    private static final AltAccount STORED = AltAccount.of(
                    "069a79f4-44e9-4726-a5be-fca90e38aaf5", "Alex", "eyJstored.access.token", AccountType.MICROSOFT)
            .withTokens("eyJstored.access.token", "M.stored-refresh", 1L);

    @TempDir
    Path dir;

    private ExecutorService host;

    @AfterEach
    void tearDown() {
        if (host != null) {
            host.shutdownNow();
        }
    }

    private AltsRuntime<Object> runtime(ExecutorService executor) {
        AltsRuntime.Builder<Object> builder = new AltsRuntime.Builder<Object>()
                .sessionInjector(session -> {})
                .vaultDirectory(() -> dir)
                .mainThread(Runnable::run)
                .toastSink((level, title, description, durationMs) -> {})
                .microsoftAuth(MicrosoftAuthConfig.of("test-client")
                        .withEndpoints(
                                NOWHERE + "/authorize",
                                NOWHERE + "/token",
                                NOWHERE + "/xbl",
                                NOWHERE + "/xsts",
                                NOWHERE + "/mclogin",
                                NOWHERE + "/mcprofile")
                        .withDeviceCodeEndpoints(NOWHERE + "/devicecode", NOWHERE + "/token"));
        if (executor != null) {
            builder.executor(executor);
        }
        return builder.build();
    }

    private Map<String, Supplier<CompletableFuture<LoginResult>>> routes(AltsRuntime<Object> alts, AtomicBoolean shown)
            throws Exception {
        AltLoginService logins = alts.loginService();
        if (logins instanceof AltLoginServiceImpl impl) {
            // Whatever happens, no browser is opened by a test.
            impl.browser = url -> shown.set(true);
        }
        Path cookieFile = Files.writeString(dir.resolve("cookies.txt"), ".live.com\tTRUE\t/\tTRUE\t0\tMSPAuth\tx\n");
        Map<String, Supplier<CompletableFuture<LoginResult>>> routes = new LinkedHashMap<>();
        routes.put("loginSession", () -> logins.loginSession("eyJhbGciOiJub25lIn0.e30.sig", LoginMode.DIRECT));
        routes.put(
                "loginCookie", () -> logins.loginCookie(".live.com\tTRUE\t/\tTRUE\t0\tMSPAuth\tx", LoginMode.DIRECT));
        routes.put("loginCookieFile", () -> logins.loginCookieFile(cookieFile, LoginMode.DIRECT));
        routes.put("loginRefreshToken", () -> logins.loginRefreshToken("M.refresh-token", LoginMode.DIRECT));
        routes.put("loginMicrosoft", () -> logins.loginMicrosoft(LoginMode.DIRECT));
        routes.put(
                "loginDeviceCode",
                () -> logins.loginDeviceCode((code, uri, expires) -> shown.set(true), LoginMode.DIRECT));
        routes.put("loginAccount", () -> logins.loginAccount(STORED));
        return routes;
    }

    private void assertEveryRouteIsCancelled(AltsRuntime<Object> alts) throws Exception {
        AtomicBoolean shown = new AtomicBoolean();
        for (Map.Entry<String, Supplier<CompletableFuture<LoginResult>>> route :
                routes(alts, shown).entrySet()) {
            LoginResult result = route.getValue().get().get(5, TimeUnit.SECONDS);
            assertFalse(result.success(), route.getKey());
            assertEquals(Kind.CANCELLED, result.failure().orElseThrow().kind(), route.getKey());
        }
        assertFalse(shown.get(), "nothing was shown to the user for a sign-in that cannot finish");

        for (Supplier<CompletableFuture<AccountStatus>> call :
                java.util.List.<Supplier<CompletableFuture<AccountStatus>>>of(
                        () -> alts.accountService().check(STORED),
                        () -> alts.accountService().refresh(STORED))) {
            AccountStatus status = call.get().get(5, TimeUnit.SECONDS);
            assertFalse(status.usable());
            assertEquals(Kind.CANCELLED, status.failure().orElseThrow().kind());
        }
    }

    @Test
    void onTheRuntimesOwnExecutorEveryRouteFailsAsCancelledWithoutThrowing() throws Exception {
        AltsRuntime<Object> alts = runtime(null);
        alts.close();

        assertEveryRouteIsCancelled(alts);
        assertEquals(
                Kind.CANCELLED,
                alts.loginService()
                        .loginOffline("Alex", LoginMode.DIRECT)
                        .get(5, TimeUnit.SECONDS)
                        .failure()
                        .orElseThrow()
                        .kind(),
                "even a route that needs no network is refused by the stopped executor");
    }

    @Test
    void onAHostExecutorThatOutlivesTheRuntimeEveryNetworkRouteFailsAsCancelled() throws Exception {
        host = Executors.newFixedThreadPool(2);
        AltsRuntime<Object> alts = runtime(host);
        alts.close();

        assertEveryRouteIsCancelled(alts);
        assertTrue(!host.isShutdown(), "the host's executor is the host's");
    }

    /** The runtime is open, but the host shut its executor down: the refusal is a result, not a throw. */
    @Test
    void aHostExecutorThatRefusesTheTaskFailsTheRouteAsCancelled() throws Exception {
        host = Executors.newSingleThreadExecutor();
        AltsRuntime<Object> alts = runtime(host);
        host.shutdown();
        try {
            for (Supplier<CompletableFuture<LoginResult>> route :
                    java.util.List.<Supplier<CompletableFuture<LoginResult>>>of(
                            () -> alts.loginService().loginOffline("Alex", LoginMode.DIRECT),
                            () -> alts.loginService().loginSession("eyJhbGciOiJub25lIn0.e30.sig", LoginMode.DIRECT),
                            () -> alts.loginService().loginRefreshToken("M.refresh-token", LoginMode.DIRECT))) {
                assertEquals(
                        Kind.CANCELLED,
                        route.get()
                                .get(5, TimeUnit.SECONDS)
                                .failure()
                                .orElseThrow()
                                .kind());
            }
            assertEquals(
                    Kind.CANCELLED,
                    alts.accountService()
                            .check(STORED)
                            .get(5, TimeUnit.SECONDS)
                            .failure()
                            .orElseThrow()
                            .kind());

            // A failed refresh says it was a refresh, a failed check that it was a check.
            AccountStatus refreshed = alts.accountService().refresh(STORED).get(5, TimeUnit.SECONDS);
            assertEquals(Kind.CANCELLED, refreshed.failure().orElseThrow().kind());
            assertTrue(refreshed.message().startsWith("Refresh"), refreshed.message());
            AccountStatus checked = alts.accountService().check(STORED).get(5, TimeUnit.SECONDS);
            assertTrue(checked.message().startsWith("Check"), checked.message());
        } finally {
            alts.close();
        }
    }
}

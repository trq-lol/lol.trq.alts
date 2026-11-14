package lol.trq.alts.internal.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import lol.trq.alts.auth.AccountStatus;
import lol.trq.alts.auth.AltLoginService;
import lol.trq.alts.auth.LoginResult;
import lol.trq.alts.internal.net.HttpTransport;
import lol.trq.alts.internal.net.TestTransports;
import lol.trq.alts.model.AccountType;
import lol.trq.alts.model.AltAccount;
import lol.trq.alts.model.LoginMode;
import lol.trq.alts.net.NetworkScope;
import lol.trq.alts.net.ProxyRoute;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * A host's proxy provider is asked for a route per request, and it can only give each account its own
 * route if every request says whose it is. A renewal is five requests, four of them to rate-limited
 * identity services; one hop made without the account is one hop leaving from the shared address.
 */
class RefreshScopeRoutingTest {

    private static final long NOW = 1_800_000_000_000L;

    @TempDir
    Path vaultDir;

    private AccountStoreTestSupport localStore;

    private AuthChainServer chain;
    private final List<NetworkScope> scopes = Collections.synchronizedList(new ArrayList<>());
    private HttpTransport transport;

    @BeforeEach
    void setUp() throws IOException {
        localStore = AccountStoreTestSupport.openIn(vaultDir);
        chain = new AuthChainServer();
        transport = TestTransports.through(scope -> {
            scopes.add(scope);
            return ProxyRoute.direct();
        });
    }

    @AfterEach
    void tearDown() {
        localStore.close();
        chain.close();
    }

    private static AltAccount expiredRenewableAccount() {
        return AltAccount.of(AuthChainServer.UUID, "Alex", "stale-access", AccountType.MICROSOFT)
                .withTokens("stale-access", "stored-refresh", NOW - 3_600_000L);
    }

    private Clock clock() {
        return Clock.fixed(Instant.ofEpochMilli(NOW), ZoneOffset.UTC);
    }

    @Test
    void everyHopOfAnAccountRenewalCarriesTheAccount() throws Exception {
        AltAccount account = expiredRenewableAccount();
        localStore.seed(account);

        AccountStatus status = new AltAccountServiceImpl(localStore.store(), chain.config(), transport, clock())
                .refresh(account)
                .get(10, TimeUnit.SECONDS);

        assertTrue(status.usable(), status.message());
        assertEquals(5, scopes.size(), "token, Xbox Live, XSTS, Minecraft login, profile: " + scopes);
        for (NetworkScope scope : scopes) {
            assertEquals(AuthChainServer.UUID, scope.accountUuid(), "a hop left without its account: " + scope);
            assertEquals("Alex", scope.accountUsername());
            assertEquals(Optional.empty(), scope.routeTag(), "an unrouted renewal carries no tag");
        }
        assertEquals(
                List.of(
                        NetworkScope.Purpose.AUTH,
                        NetworkScope.Purpose.AUTH,
                        NetworkScope.Purpose.AUTH,
                        NetworkScope.Purpose.AUTH,
                        NetworkScope.Purpose.PROFILE),
                scopes.stream().map(NetworkScope::purpose).toList());
    }

    @Test
    void loggingIntoAStoredAccountRenewsItUnderThatAccountsScope() throws Exception {
        AltAccount account = expiredRenewableAccount();
        localStore.seed(account);

        LoginResult result = new AltLoginServiceImpl(
                        localStore.store(), session -> {}, chain.config(), transport, clock())
                .loginAccount(account)
                .get(10, TimeUnit.SECONDS);

        assertTrue(result.success(), result.message());
        assertEquals(5, scopes.size());
        for (NetworkScope scope : scopes) {
            assertEquals(AuthChainServer.UUID, scope.accountUuid(), "a hop left without its account: " + scope);
        }
    }

    @Test
    void twoAccountsRenewedTogetherNeverShareAScope() throws Exception {
        String otherUuid = "00000000-0000-4000-8000-000000000002";
        AltAccount first = expiredRenewableAccount();
        AltAccount second = AltAccount.of(otherUuid, "Steve", "stale-access", AccountType.MICROSOFT)
                .withTokens("stale-access", "other-refresh", NOW - 3_600_000L);
        AltAccountServiceImpl service =
                new AltAccountServiceImpl(localStore.store(), chain.config(), transport, clock());

        service.refresh(first).get(10, TimeUnit.SECONDS);
        service.refresh(second).get(10, TimeUnit.SECONDS);

        assertEquals(10, scopes.size());
        assertEquals(
                5,
                scopes.stream()
                        .filter(s -> AuthChainServer.UUID.equals(s.accountUuid()))
                        .count());
        assertEquals(
                5,
                scopes.stream().filter(s -> otherUuid.equals(s.accountUuid())).count());
    }

    @Test
    void importingABareRefreshTokenNamesNoAccount() throws Exception {
        LoginResult result = new AltLoginServiceImpl(
                        localStore.store(), session -> {}, chain.config(), transport, clock())
                .loginRefreshToken("pasted-refresh", LoginMode.DIRECT)
                .get(10, TimeUnit.SECONDS);

        assertTrue(result.success(), result.message());
        assertEquals(5, scopes.size());
        for (NetworkScope scope : scopes) {
            assertNull(scope.accountUuid(), "there is no account yet for a credential being imported");
        }
    }

    @Test
    void theOlderEntryPointStillWorksAndNamesNoAccount() throws Exception {
        MinecraftProfile profile = new MicrosoftAuthUtil(transport)
                .authenticateWithRefreshToken(chain.config(), "stored-refresh")
                .get(10, TimeUnit.SECONDS);

        assertEquals("Alex", profile.username());
        assertEquals(5, scopes.size());
        for (NetworkScope scope : scopes) {
            assertNull(scope.accountUuid());
        }
    }

    @Test
    void aRoutedSignInCarriesItsTagOnEveryHop() throws Exception {
        AltLoginService routed = new AltLoginServiceImpl(
                        localStore.store(), session -> {}, chain.config(), transport, clock())
                .routed("pool-7");

        LoginResult result =
                routed.loginRefreshToken("pasted-refresh", LoginMode.DIRECT).get(10, TimeUnit.SECONDS);

        assertTrue(result.success(), result.message());
        assertEquals(5, scopes.size(), "token, Xbox Live, XSTS, Minecraft login, profile: " + scopes);
        for (NetworkScope scope : scopes) {
            assertEquals(Optional.of("pool-7"), scope.routeTag(), "a hop left without the route tag: " + scope);
            assertNull(scope.accountUuid(), "and there is still no account to route on");
        }
    }

    @Test
    void aRoutedLoginOfAStoredAccountCarriesTheTagThroughItsRenewal() throws Exception {
        AltAccount account = expiredRenewableAccount();
        localStore.seed(account);
        AltLoginServiceImpl logins =
                new AltLoginServiceImpl(localStore.store(), session -> {}, chain.config(), transport, clock());

        LoginResult result = logins.routed("pool-7").loginAccount(account).get(10, TimeUnit.SECONDS);
        assertTrue(result.success(), result.message());
        assertEquals(5, scopes.size());
        for (NetworkScope scope : scopes) {
            assertEquals(Optional.of("pool-7"), scope.routeTag(), "a renewal hop lost the tag: " + scope);
            assertEquals(AuthChainServer.UUID, scope.accountUuid(), "and still names its account");
        }

        // The view leaves the service it came from untagged.
        scopes.clear();
        localStore.seed(expiredRenewableAccount());
        assertTrue(logins.loginAccount(expiredRenewableAccount())
                .get(10, TimeUnit.SECONDS)
                .success());
        assertTrue(scopes.stream().allMatch(scope -> scope.routeTag().isEmpty()), scopes.toString());
    }

    @Test
    void aBlankTagIsRefused() {
        AltLoginServiceImpl logins =
                new AltLoginServiceImpl(localStore.store(), session -> {}, chain.config(), transport, clock());

        assertThrows(IllegalArgumentException.class, () -> logins.routed(" "));
        assertThrows(NullPointerException.class, () -> logins.routed(null));
    }
}

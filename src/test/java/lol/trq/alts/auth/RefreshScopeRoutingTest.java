package lol.trq.alts.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;
import lol.trq.alts.auth.AltLoginCallback.LoginResult;
import lol.trq.alts.model.AccountType;
import lol.trq.alts.model.AltAccount;
import lol.trq.alts.model.LoginMode;
import lol.trq.alts.net.HttpUtil;
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

    private AuthChainServer chain;
    private final List<NetworkScope> scopes = Collections.synchronizedList(new ArrayList<>());

    @BeforeEach
    void setUp() throws IOException {
        AltStoreTestSupport.bindTo(vaultDir);
        chain = new AuthChainServer();
        HttpUtil.bind(scope -> {
            scopes.add(scope);
            return ProxyRoute.direct();
        });
    }

    @AfterEach
    void tearDown() {
        // Static, so leaving it installed would route every later test through this recorder.
        HttpUtil.resetForTests();
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
        AltStoreTestSupport.seed(account);

        AccountStatus status = new AltAccountServiceImpl(chain.config(), clock())
                .refresh(account)
                .get(10, TimeUnit.SECONDS);

        assertTrue(status.usable(), status.message());
        assertEquals(5, scopes.size(), "token, Xbox Live, XSTS, Minecraft login, profile: " + scopes);
        for (NetworkScope scope : scopes) {
            assertEquals(AuthChainServer.UUID, scope.accountUuid(), "a hop left without its account: " + scope);
            assertEquals("Alex", scope.accountUsername());
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
        AltStoreTestSupport.seed(account);

        LoginResult result = new AltLoginServiceImpl(session -> {}, chain.config(), clock())
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
        AltAccountServiceImpl service = new AltAccountServiceImpl(chain.config(), clock());

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
        LoginResult result = new AltLoginServiceImpl(session -> {}, chain.config(), clock())
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
        MinecraftProfile profile = MicrosoftAuthUtil.authenticateWithRefreshToken(chain.config(), "stored-refresh")
                .get(10, TimeUnit.SECONDS);

        assertEquals("Alex", profile.username());
        assertEquals(5, scopes.size());
        for (NetworkScope scope : scopes) {
            assertNull(scope.accountUuid());
        }
    }
}

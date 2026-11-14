package lol.trq.alts.internal.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import lol.trq.alts.AltsFailure;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.auth.LoginResult;
import lol.trq.alts.internal.net.TestTransports;
import lol.trq.alts.model.AccountType;
import lol.trq.alts.model.AltAccount;
import lol.trq.alts.model.LoginMode;
import lol.trq.alts.model.SessionData;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * A session token's payload is unsigned text: anyone can write one that claims any identity. It is good
 * enough to try a session with, but not to store an identity on, and in ADD mode a claimed UUID would be
 * merged over whatever account the store already holds under it.
 */
class SessionTokenIdentityTest {

    private static final long NOW = 1_800_000_000_000L;
    private static final String VICTIM_UUID = "00000000-0000-4000-8000-0000000000aa";

    @TempDir
    Path vaultDir;

    private AccountStoreTestSupport localStore;

    private AuthChainServer chain;
    private final AtomicReference<SessionData> injected = new AtomicReference<>();

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

    private AltLoginServiceImpl service() {
        return new AltLoginServiceImpl(
                localStore.store(),
                injected::set,
                chain.config(),
                TestTransports.direct(),
                Clock.fixed(Instant.ofEpochMilli(NOW), ZoneOffset.UTC));
    }

    /** Builds an unsigned token whose payload claims the given identity. */
    private static String jwt(String claimedUuid, String claimedName, Long expiryMillis) {
        String payload = "{\"name\":\"" + claimedName + "\",\"id\":\"" + claimedUuid.replace("-", "") + "\""
                + (expiryMillis == null ? "" : ",\"exp\":" + (expiryMillis / 1000L)) + "}";
        return "eyJhbGciOiJub25lIn0."
                + Base64.getUrlEncoder().withoutPadding().encodeToString(payload.getBytes(StandardCharsets.UTF_8))
                + ".sig";
    }

    @Test
    void savingATokenStoresTheIdentityTheServiceConfirmsNotTheOneThePayloadClaims() throws Exception {
        AltAccount victim = AltAccount.of(VICTIM_UUID, "Victim", "victim-token", AccountType.MICROSOFT)
                .withTokens("victim-token", "victim-refresh", NOW + 3_600_000L);
        localStore.seed(victim);
        String forged = jwt(VICTIM_UUID, "Victim", NOW + 3_600_000L);

        LoginResult result = service().loginSession(forged, LoginMode.ADD).get(10, TimeUnit.SECONDS);

        assertTrue(result.success(), result.message());
        assertEquals(1, chain.profileCalls(), "saving asks the service who the token belongs to");
        assertEquals(AuthChainServer.UUID, result.account().uuid(), "the stored identity is the confirmed one");
        assertEquals("Alex", result.account().username());

        AltAccount untouched = localStore.find(VICTIM_UUID);
        assertEquals("victim-token", untouched.accessToken(), "the claimed account's record was not merged over");
        assertEquals("victim-refresh", untouched.refreshToken());
    }

    @Test
    void savingATokenTheServiceRefusesStoresNothing() throws Exception {
        chain.fail("/mcprofile", 401);
        String forged = jwt(VICTIM_UUID, "Victim", NOW + 3_600_000L);

        LoginResult result = service().loginSession(forged, LoginMode.ADD).get(10, TimeUnit.SECONDS);

        assertFalse(result.success());
        assertEquals(Kind.UNAUTHORIZED, result.failure().map(AltsFailure::kind).orElse(null));
        assertNull(injected.get());
        assertTrue(localStore.store().accounts().isEmpty(), "nothing was stored for a token the service refused");
    }

    @Test
    void aTokenThatStatesNoExpiryIsValidatedRatherThanTakenAtItsWord() throws Exception {
        String noExpiry = jwt(VICTIM_UUID, "Victim", null);

        LoginResult result = service().loginSession(noExpiry, LoginMode.DIRECT).get(10, TimeUnit.SECONDS);

        assertTrue(result.success(), result.message());
        assertEquals(1, chain.profileCalls(), "with no expiry to judge by, the service is asked");
        assertEquals(AuthChainServer.UUID, result.account().uuid());
    }

    @Test
    void aLiveTokenUsedWithoutSavingStillSkipsTheNetwork() throws Exception {
        String live = jwt(VICTIM_UUID, "Victim", NOW + 3_600_000L);

        LoginResult result = service().loginSession(live, LoginMode.DIRECT).get(10, TimeUnit.SECONDS);

        assertTrue(result.success(), result.message());
        assertEquals(0, chain.profileCalls());
    }
}

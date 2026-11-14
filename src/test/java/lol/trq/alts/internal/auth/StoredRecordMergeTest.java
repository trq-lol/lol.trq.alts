package lol.trq.alts.internal.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.concurrent.TimeUnit;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.auth.AccountStatus;
import lol.trq.alts.auth.AccountStatus.State;
import lol.trq.alts.bulk.BulkEntryResult;
import lol.trq.alts.bulk.BulkOptions;
import lol.trq.alts.bulk.BulkProgress;
import lol.trq.alts.bulk.BulkReport;
import lol.trq.alts.internal.bulk.BulkOperationsImpl;
import lol.trq.alts.internal.net.HttpTransport;
import lol.trq.alts.internal.net.TestTransports;
import lol.trq.alts.model.AccountType;
import lol.trq.alts.model.AltAccount;
import lol.trq.alts.model.BanInfo;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * A check or a renewal writes back only what it learned (the tokens, the expiry, the current name),
 * applied onto whatever the store holds at that moment. The caller's copy may be older than the store:
 * a bulk run works from the list it was handed, and a host may keep an account it read an hour ago.
 * Writing that copy back whole would undo every change made since, a ban among them, and would put a
 * refresh token the service has already rotated past back on disk.
 */
@org.junit.jupiter.api.Timeout(value = 60, unit = TimeUnit.SECONDS)
class StoredRecordMergeTest {

    private static final long NOW = 1_800_000_000_000L;
    private static final String UUID = AuthChainServer.UUID;

    @TempDir
    Path storeDir;

    private AccountStoreTestSupport local;
    private AuthChainServer chain;
    private final HttpTransport http = TestTransports.direct();

    @BeforeEach
    void setUp() throws Exception {
        local = AccountStoreTestSupport.openIn(storeDir);
        chain = new AuthChainServer();
    }

    @AfterEach
    void tearDown() {
        local.close();
        chain.close();
        http.close();
    }

    private AltAccountServiceImpl service() {
        return new AltAccountServiceImpl(
                local.store(), chain.config(), http, Clock.fixed(Instant.ofEpochMilli(NOW), ZoneOffset.UTC));
    }

    /** An account whose access token lapsed, so a refresh renews it. */
    private static AltAccount expired(String refreshToken) {
        return AltAccount.of(UUID, "Alex", "spent-access", AccountType.MICROSOFT)
                .withTokens("spent-access", refreshToken, NOW - 60_000L);
    }

    @Test
    void aBanMarkedWhileAPacedRefreshAllIsUnderwaySurvivesTheRenewal() throws Exception {
        AltAccount snapshot = expired("stored-refresh");
        local.seed(snapshot);
        BulkOperationsImpl bulk = new BulkOperationsImpl(
                local.store(),
                new AltLoginServiceImpl(local.store(), session -> {}, chain.config(), http),
                service(),
                account -> {
                    throw new AssertionError("this run reads no entitlements");
                },
                http);
        BanInfo ban = BanInfo.observed("kick", "banned on example.net");
        BulkProgress banAsItStarts = new BulkProgress() {
            @Override
            public void started(int index, int total, String label) {
                // The host learns of a ban while the run is pacing through the list it was handed.
                local.store().markBanned(UUID, "example.net", ban);
            }

            @Override
            public void completed(int index, int total, BulkEntryResult result) {}
        };

        BulkReport report = bulk.refreshAll(
                        List.of(snapshot),
                        new BulkOptions(1, Duration.ofMillis(50), 2, Duration.ofSeconds(2), true),
                        banAsItStarts)
                .report()
                .get(30, TimeUnit.SECONDS);

        assertEquals(1, report.succeeded(), "the renewal itself worked");
        AltAccount stored = local.reloadFromDiskAndFind(UUID);
        assertEquals("ms-refresh", stored.refreshToken(), "the rotated token was persisted");
        assertTrue(stored.banned("example.net"), "and the ban marked during the run was not written over");
        assertTrue(
                report.results().get(0).account().banned("example.net"),
                "the renewed account handed back is the stored record, ban included");
    }

    @Test
    void aStaleCopyCannotWriteAnOldRefreshTokenBackWhenItsNameIsCorrected() throws Exception {
        AltAccount stale = AltAccount.of(UUID, "OldName", "live-access", AccountType.MICROSOFT)
                .withTokens("live-access", "old-refresh", NOW + 3_600_000L);
        // Since the copy was read, a renewal elsewhere rotated the stored refresh token.
        local.seed(stale.withTokens("newer-access", "newer-refresh", NOW + 7_200_000L));

        AccountStatus status = service().check(stale).get(10, TimeUnit.SECONDS);

        assertEquals(State.VALID, status.state());
        AltAccount stored = local.reloadFromDiskAndFind(UUID);
        assertEquals("Alex", stored.username(), "the corrected name was written");
        assertEquals("newer-refresh", stored.refreshToken(), "and nothing else from the stale copy was");
        assertEquals("newer-access", stored.accessToken());
    }

    @Test
    void aStaleCopyWhoseOldTokenIsSpentDoesNotDiscardTheStoredNewerOne() throws Exception {
        chain.fail("/token", 400, "{\"error\":\"invalid_grant\"}");
        local.seed(expired("newer-refresh"));

        AccountStatus status = service().refresh(expired("old-refresh")).get(10, TimeUnit.SECONDS);

        assertEquals(State.REAUTH_REQUIRED, status.state(), "the token the copy carried is spent");
        assertEquals(
                "newer-refresh",
                local.reloadFromDiskAndFind(UUID).refreshToken(),
                "but the store holds a different one, which nothing said is spent");
    }

    @Test
    void theSpentTokenTheStoreHoldsIsStillDiscarded() throws Exception {
        chain.fail("/token", 400, "{\"error\":\"invalid_grant\"}");
        local.seed(expired("stored-refresh"));

        service().refresh(expired("stored-refresh")).get(10, TimeUnit.SECONDS);

        assertEquals(null, local.reloadFromDiskAndFind(UUID).refreshToken());
    }

    /**
     * The token endpoint rotates the refresh token the moment it redeems one, and the one redeemed may
     * not work again. A later hop failing (here the Minecraft services login throttling) must not lose
     * the rotated token, or the next renewal replays a spent one.
     */
    @Test
    void aRotatedRefreshTokenIsKeptWhenALaterStepIsRateLimited() throws Exception {
        chain.fail("/mclogin", 429);
        local.seed(expired("stored-refresh"));

        AccountStatus status = service().refresh(expired("stored-refresh")).get(10, TimeUnit.SECONDS);

        assertEquals(Kind.RATE_LIMITED, status.failure().orElseThrow().kind());
        assertEquals(
                "ms-refresh",
                local.reloadFromDiskAndFind(UUID).refreshToken(),
                "the token issued by the redemption was persisted as soon as it was issued");
        assertEquals("ms-refresh", status.account().refreshToken(), "and the caller's status carries it too");
    }

    @Test
    void aRotatedRefreshTokenOfAnAccountTheStoreDoesNotHoldReachesOnlyTheCaller() throws Exception {
        chain.fail("/mclogin", 429);

        AccountStatus status = service().refresh(expired("direct-refresh")).get(10, TimeUnit.SECONDS);

        assertEquals(Kind.RATE_LIMITED, status.failure().orElseThrow().kind());
        assertEquals("ms-refresh", status.account().refreshToken());
        assertTrue(local.store().accounts().isEmpty(), "nothing was persisted for it");
    }

    @Test
    void aRenewalOfAnAccountTheStoreDoesNotHoldPersistsNothing() throws Exception {
        AccountStatus status = service().refresh(expired("direct-refresh")).get(10, TimeUnit.SECONDS);

        assertEquals(State.RENEWED, status.state());
        assertEquals("ms-refresh", status.account().refreshToken(), "the caller still gets the rotated token");
        assertTrue(local.store().accounts().isEmpty(), "and the store still holds nothing");
    }
}

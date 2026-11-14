package lol.trq.alts;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.account.ClaimOptions;
import lol.trq.alts.account.Entitlements;
import lol.trq.alts.auth.MicrosoftAuthConfig;
import lol.trq.alts.auth.XstsError;
import lol.trq.alts.bulk.BulkEntryResult;
import lol.trq.alts.bulk.BulkOptions;
import lol.trq.alts.model.AccountType;
import lol.trq.alts.model.AltAccount;
import lol.trq.alts.model.BanInfo;
import lol.trq.alts.net.NetworkScope;
import lol.trq.alts.net.NetworkScope.Purpose;
import lol.trq.alts.time.TimeSource;
import org.junit.jupiter.api.Test;

/**
 * The final classes that stand in for records keep a record's value semantics: two built from the same
 * components are equal and hash alike, and changing any one component, every other kept, makes them
 * unequal. Each variant below differs from its base in exactly one component, and every component of each
 * type has one.
 */
class ValueSemanticsTest {

    private static final String UUID = "00000000-0000-4000-8000-000000000001";

    /** One component changed, named for the message. */
    private record Variant<T>(String component, T value) {}

    private static <T> Variant<T> change(String component, T value) {
        return new Variant<>(component, value);
    }

    @SafeVarargs
    private static <T> void assertValueSemantics(Supplier<T> make, int components, Variant<T>... variants) {
        T one = make.get();
        T other = make.get();
        assertEquals(one, other, "built alike, equal");
        assertEquals(other, one, "built alike, equal both ways");
        assertEquals(one.hashCode(), other.hashCode(), "built alike, the same hash");
        assertNotEquals(null, one);
        assertNotEquals(one, new Object());
        assertEquals(
                components,
                List.of(variants).stream().map(Variant::component).distinct().count(),
                "every component has a variant");
        for (Variant<T> variant : variants) {
            assertNotEquals(one, variant.value(), () -> "a different " + variant.component() + " is unequal");
            assertNotEquals(variant.value(), one, () -> "a different " + variant.component() + " is unequal back");
        }
    }

    @Test
    void claimOptions() {
        TimeSource clock = () -> Instant.EPOCH;
        TimeSource otherClock = () -> Instant.EPOCH;
        Duration lead = Duration.ofMillis(300);
        Duration window = Duration.ofSeconds(5);
        Duration spacing = Duration.ofMillis(8);
        assertValueSemantics(
                () -> ClaimOptions.of(lead, window, spacing, 3, clock),
                5,
                change("leadTime", ClaimOptions.of(Duration.ofMillis(301), window, spacing, 3, clock)),
                change("window", ClaimOptions.of(lead, Duration.ofSeconds(6), spacing, 3, clock)),
                change("attemptSpacing", ClaimOptions.of(lead, window, Duration.ofMillis(9), 3, clock)),
                change("concurrency", ClaimOptions.of(lead, window, spacing, 4, clock)),
                change("timeSource", ClaimOptions.of(lead, window, spacing, 3, otherClock)));
    }

    @Test
    void bulkOptions() {
        Duration spacing = Duration.ofMillis(250);
        Duration delay = Duration.ofSeconds(2);
        assertValueSemantics(
                () -> BulkOptions.of(4, spacing, 2, delay, true).withRouteTag("pool-1"),
                6,
                change("concurrency", BulkOptions.of(5, spacing, 2, delay, true).withRouteTag("pool-1")),
                change(
                        "minSpacing",
                        BulkOptions.of(4, Duration.ofMillis(251), 2, delay, true)
                                .withRouteTag("pool-1")),
                change("maxRetries", BulkOptions.of(4, spacing, 3, delay, true).withRouteTag("pool-1")),
                change(
                        "retryBaseDelay",
                        BulkOptions.of(4, spacing, 2, Duration.ofSeconds(3), true)
                                .withRouteTag("pool-1")),
                change(
                        "stopOnRateLimit",
                        BulkOptions.of(4, spacing, 2, delay, false).withRouteTag("pool-1")),
                change("routeTag", BulkOptions.of(4, spacing, 2, delay, true).withRouteTag("pool-2")),
                change("routeTag", BulkOptions.of(4, spacing, 2, delay, true)));
    }

    @Test
    void networkScope() {
        assertValueSemantics(
                () -> NetworkScope.forAccount(Purpose.PROFILE, UUID, "Alex").withRouteTag("pool-1"),
                4,
                change(
                        "purpose",
                        NetworkScope.forAccount(Purpose.AUTH, UUID, "Alex").withRouteTag("pool-1")),
                change(
                        "accountUuid",
                        NetworkScope.forAccount(Purpose.PROFILE, "00000000-0000-4000-8000-000000000002", "Alex")
                                .withRouteTag("pool-1")),
                change(
                        "accountUsername",
                        NetworkScope.forAccount(Purpose.PROFILE, UUID, "Steve").withRouteTag("pool-1")),
                change(
                        "routeTag",
                        NetworkScope.forAccount(Purpose.PROFILE, UUID, "Alex").withRouteTag("pool-2")),
                change("routeTag", NetworkScope.forAccount(Purpose.PROFILE, UUID, "Alex")));
    }

    @Test
    void microsoftAuthConfig() {
        Supplier<MicrosoftAuthConfig> make = () -> MicrosoftAuthConfig.of("client")
                .withScope("scope")
                .withRedirectPath("/callback")
                .withEndpoints("a", "t", "x", "s", "l", "p")
                .withRedirectUri("https://example.net/redirect")
                .withRpsTicketPrefix("d=")
                .withDeviceCodeEndpoints("dc", "dt");
        assertValueSemantics(
                make,
                13,
                change("clientId", make.get().withClientId("other")),
                change("scope", make.get().withScope("other")),
                change("redirectPath", make.get().withRedirectPath("/other")),
                change("authorizeUrl", make.get().withEndpoints("a2", "t", "x", "s", "l", "p")),
                change("tokenUrl", make.get().withEndpoints("a", "t2", "x", "s", "l", "p")),
                change("xboxLiveAuthUrl", make.get().withEndpoints("a", "t", "x2", "s", "l", "p")),
                change("xstsAuthUrl", make.get().withEndpoints("a", "t", "x", "s2", "l", "p")),
                change("minecraftLoginUrl", make.get().withEndpoints("a", "t", "x", "s", "l2", "p")),
                change("minecraftProfileUrl", make.get().withEndpoints("a", "t", "x", "s", "l", "p2")),
                change("redirectUri", make.get().withRedirectUri("https://example.net/other")),
                change("redirectUri", make.get().withRedirectUri(null)),
                change("rpsTicketPrefix", make.get().withRpsTicketPrefix("t=")),
                change("deviceCodeUrl", make.get().withDeviceCodeEndpoints("dc2", "dt")),
                change("deviceTokenUrl", make.get().withDeviceCodeEndpoints("dc", "dt2")));
    }

    @Test
    void bulkEntryResult() {
        AltAccount account = AltAccount.builder(UUID, "Alex", "access", AccountType.MICROSOFT)
                .lastUsed(1L)
                .build();
        AltAccount sameNameOtherToken = account.toBuilder().accessToken("other").build();
        Entitlements owned = new Entitlements(Set.of("game_minecraft"));
        AltsFailure refused = AltsFailure.of(Kind.UNAUTHORIZED, "refused");
        AltsFailure sameMessageOtherKind = AltsFailure.of(Kind.NETWORK, "refused");

        // A success's label is its account's username and a failure's message is its failure's: each of the
        // two shapes varies the components it can change alone.
        assertValueSemantics(
                () -> BulkEntryResult.success(1, account, owned, "ok", 2),
                5,
                change("index", BulkEntryResult.success(2, account, owned, "ok", 2)),
                change("account", BulkEntryResult.success(1, sameNameOtherToken, owned, "ok", 2)),
                change("message", BulkEntryResult.success(1, account, owned, "fine", 2)),
                change("attempts", BulkEntryResult.success(1, account, owned, "ok", 3)),
                change("entitlements", BulkEntryResult.success(1, account, new Entitlements(Set.of("other")), "ok", 2)),
                change("entitlements", BulkEntryResult.success(1, account, "ok", 2)));
        assertValueSemantics(
                () -> BulkEntryResult.failure(1, "entry 2", refused, 2),
                4,
                change("index", BulkEntryResult.failure(2, "entry 2", refused, 2)),
                change("label", BulkEntryResult.failure(1, "entry 3", refused, 2)),
                change("failure", BulkEntryResult.failure(1, "entry 2", sameMessageOtherKind, 2)),
                change("attempts", BulkEntryResult.failure(1, "entry 2", refused, 3)));
        assertNotEquals(
                BulkEntryResult.success(1, account, "refused", 2),
                BulkEntryResult.failure(1, "Alex", AltsFailure.of(Kind.UNAUTHORIZED, "refused"), 2),
                "a success and a failure differ in account and failure alone, and are unequal");
    }

    @Test
    void altsFailure() {
        Duration wait = Duration.ofSeconds(30);
        Instant end = Instant.parse("2026-01-01T00:00:30Z");
        assertValueSemantics(
                () -> new AltsFailure(
                        Kind.RATE_LIMITED, "slow down", Optional.of(wait), Optional.empty(), Optional.of(end)),
                4,
                change(
                        "kind",
                        new AltsFailure(
                                Kind.NETWORK, "slow down", Optional.of(wait), Optional.empty(), Optional.of(end))),
                change(
                        "message",
                        new AltsFailure(
                                Kind.RATE_LIMITED, "wait", Optional.of(wait), Optional.empty(), Optional.of(end))),
                change(
                        "retryAfter",
                        new AltsFailure(
                                Kind.RATE_LIMITED,
                                "slow down",
                                Optional.of(Duration.ofSeconds(31)),
                                Optional.empty(),
                                Optional.of(end))),
                change(
                        "retryAt",
                        new AltsFailure(
                                Kind.RATE_LIMITED,
                                "slow down",
                                Optional.of(wait),
                                Optional.empty(),
                                Optional.of(end.plusSeconds(1)))));
        // An Xbox Live reason travels with XBOX_DENIED only, so it varies on a failure of that kind.
        assertValueSemantics(
                () -> AltsFailure.xboxDenied("denied", XstsError.NO_XBOX_ACCOUNT),
                1,
                change("xstsError", AltsFailure.xboxDenied("denied", XstsError.REGION_BLOCKED)),
                change(
                        "xstsError",
                        new AltsFailure(
                                Kind.XBOX_DENIED, "denied", Optional.empty(), Optional.empty(), Optional.empty())));
    }

    @Test
    void altAccount() {
        Supplier<AltAccount.Builder> builder = () -> AltAccount.builder(UUID, "Alex", "access", AccountType.MICROSOFT)
                .lastUsed(1L)
                .lastUsedBy("member")
                .bans(Map.of("example.net", new BanInfo(true, 2L, "kick", "banned", "member")))
                .sourceClient("client")
                .sourceUser("user")
                .refreshToken("refresh")
                .expiresAt(3L);
        assertValueSemantics(
                () -> builder.get().build(),
                11,
                change(
                        "uuid",
                        AltAccount.builder(
                                        "00000000-0000-4000-8000-000000000002", "Alex", "access", AccountType.MICROSOFT)
                                .lastUsed(1L)
                                .lastUsedBy("member")
                                .bans(Map.of("example.net", new BanInfo(true, 2L, "kick", "banned", "member")))
                                .sourceClient("client")
                                .sourceUser("user")
                                .refreshToken("refresh")
                                .expiresAt(3L)
                                .build()),
                change("username", builder.get().username("Steve").build()),
                change("accessToken", builder.get().accessToken("other").build()),
                change("type", builder.get().type(AccountType.SESSION).build()),
                change("lastUsed", builder.get().lastUsed(4L).build()),
                change("lastUsedBy", builder.get().lastUsedBy("someone").build()),
                change(
                        "bans",
                        builder.get()
                                .bans(Map.of("example.net", new BanInfo(false, 2L, "kick", "banned", "member")))
                                .build()),
                change("bans", builder.get().bans(null).build()),
                change("sourceClient", builder.get().sourceClient("other").build()),
                change("sourceUser", builder.get().sourceUser("other").build()),
                change("refreshToken", builder.get().refreshToken(null).build()),
                change("expiresAt", builder.get().expiresAt(5L).build()));
    }
}

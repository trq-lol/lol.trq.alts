package lol.trq.alts.account;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.net.TestTransports;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

/**
 * The freeze's per-service classification test for the account services and the profile lookup: every
 * call, driven through each failing answer a service can give, throws an {@link AltsException} of the
 * expected {@link Kind}, with the stated wait where there was one, whose message carries no transport
 * text, no token, nothing the service wrote and no address. The two mutations whose refusals are
 * outcomes, a name change and a profile creation, return {@code FAILED} carrying the same kind.
 */
class AccountServicesFailureKindTest {

    private static final String TOKEN = "secret-bearer-token";
    private static final String HOSTILE_BODY = "{\"errorMessage\":\"echo " + TOKEN
            + " from D:/data/someone/accounts.dat\",\"error\":\"secret-code\",\"details\":\"secret-detail\"}";

    private LoopbackServices server;
    private AccountServices services;
    private ProfileLookupService lookup;

    @BeforeEach
    void setUp() throws Exception {
        server = new LoopbackServices();
        open(server.endpoints());
    }

    @AfterEach
    void tearDown() {
        server.close();
    }

    private void open(AccountEndpoints endpoints) {
        services = AccountServices.create(
                TestTransports.direct(), TOKEN, "11111111-2222-3333-4444-555555555555", endpoints);
        lookup = new ProfileLookupServiceImpl(TestTransports.direct(), endpoints);
    }

    /** Every call that throws on a failure, by name. */
    private Map<String, Executable> throwingCalls() {
        Map<String, Executable> calls = new LinkedHashMap<>();
        calls.put("profile.fetch", () -> services.profile().fetch());
        calls.put("entitlements.fetch", () -> services.entitlements().fetch());
        calls.put("name.eligibility", () -> services.name().eligibility());
        calls.put("name.checkAvailability", () -> services.name().checkAvailability("Wanted"));
        calls.put("attributes.fetch", () -> services.attributes().fetch());
        calls.put("attributes.setProfanityFilter", () -> services.attributes().setProfanityFilter(true));
        calls.put("blocklist.fetch", () -> services.blocklist().fetch());
        calls.put("certificates.fetch", () -> services.certificates().fetch());
        calls.put("cape.setActive", () -> services.cape().setActive("cape-id"));
        calls.put("cape.hideActive", () -> services.cape().hideActive());
        calls.put("skin.setFromUrl", () -> services.skin().setFromUrl("https://textures.example/s", SkinModel.SLIM));
        calls.put("skin.upload", () -> services.skin().upload(SkinUploadTest.png(64, 64), SkinModel.CLASSIC));
        calls.put("skin.resetToDefault", () -> services.skin().resetToDefault());
        return calls;
    }

    private Map<String, Executable> lookupCalls() {
        Map<String, Executable> calls = new LinkedHashMap<>();
        calls.put("lookup.byName", () -> lookup.byName("Alex"));
        calls.put("lookup.byUuid", () -> lookup.byUuid("069a79f4-44e9-4726-a5be-fca90e38aaf5"));
        calls.put("lookup.byNames", () -> lookup.byNames(List.of("Alex", "Steve_1")));
        return calls;
    }

    private static void assertClean(String call, AltsFailure failure) {
        for (String forbidden : new String[] {"secret", "someone", "127.0.0.1", "Exception", "java.", "errorMessage"}) {
            assertFalse(
                    failure.message().contains(forbidden),
                    call + ": the message carries '" + forbidden + "': " + failure.message());
        }
    }

    private static void assertThrown(Map<String, Executable> calls, Kind kind, Optional<Duration> wait) {
        for (Map.Entry<String, Executable> call : calls.entrySet()) {
            AltsException thrown = assertThrows(AltsException.class, call.getValue(), call.getKey());
            assertEquals(kind, thrown.kind(), call.getKey());
            assertEquals(wait, thrown.failure().retryAfter(), call.getKey());
            assertClean(call.getKey(), thrown.failure());
        }
    }

    /** The name change and the profile creation report failures as FAILED results of the same kind. */
    private void assertFailedMutations(Kind kind, Optional<Duration> wait) {
        NameChangeResult change = services.name().change("Wanted");
        assertEquals(NameChangeResult.Outcome.FAILED, change.outcome(), "name.change");
        assertEquals(kind, change.failure().orElseThrow().kind(), "name.change");
        assertEquals(wait, change.failure().orElseThrow().retryAfter(), "name.change");
        assertClean("name.change", change.failure().orElseThrow());

        ProfileCreationResult created = services.profile().create("Wanted");
        assertEquals(ProfileCreationResult.Outcome.FAILED, created.outcome(), "profile.create");
        assertEquals(kind, created.failure().orElseThrow().kind(), "profile.create");
        assertEquals(wait, created.failure().orElseThrow().retryAfter(), "profile.create");
        assertClean("profile.create", created.failure().orElseThrow());
    }

    @Test
    void aRefusedTokenIsUnauthorizedEverywhere() {
        for (int status : new int[] {401, 403}) {
            server.canned(status, HOSTILE_BODY);
            assertThrown(throwingCalls(), Kind.UNAUTHORIZED, Optional.empty());
            assertThrown(lookupCalls(), Kind.UNAUTHORIZED, Optional.empty());
        }
        server.canned(401, HOSTILE_BODY);
        assertFailedMutations(Kind.UNAUTHORIZED, Optional.empty());
    }

    @Test
    void aMissingResourceIsNotFoundAndAMissingProfileIsNotEntitled() {
        server.canned(404, HOSTILE_BODY);
        Map<String, Executable> others = throwingCalls();
        Map<String, Executable> profile = new LinkedHashMap<>();
        profile.put("profile.fetch", others.remove("profile.fetch"));
        profile.put("cape.owned", () -> services.cape().owned());

        assertThrown(others, Kind.NOT_FOUND, Optional.empty());
        assertThrown(profile, Kind.NOT_ENTITLED, Optional.empty());
        assertEquals(Optional.empty(), services.profile().fetchIfPresent(), "an answer, not a failure");
    }

    @Test
    void aThrottleIsRateLimitedWithItsWaitWhenStated() {
        server.rateLimited(40);
        assertThrown(throwingCalls(), Kind.RATE_LIMITED, Optional.of(Duration.ofSeconds(40)));
        assertThrown(lookupCalls(), Kind.RATE_LIMITED, Optional.of(Duration.ofSeconds(40)));
        assertFailedMutations(Kind.RATE_LIMITED, Optional.of(Duration.ofSeconds(40)));

        server.canned(429, HOSTILE_BODY);
        assertThrown(throwingCalls(), Kind.RATE_LIMITED, Optional.empty());
        assertThrown(lookupCalls(), Kind.RATE_LIMITED, Optional.empty());
        assertFailedMutations(Kind.RATE_LIMITED, Optional.empty());
    }

    @Test
    void aServerErrorOrARequestTimeoutIsNetwork() {
        for (int status : new int[] {503, 408}) {
            server.canned(status, HOSTILE_BODY);
            assertThrown(throwingCalls(), Kind.NETWORK, Optional.empty());
            assertThrown(lookupCalls(), Kind.NETWORK, Optional.empty());
            assertFailedMutations(Kind.NETWORK, Optional.empty());
        }
    }

    @Test
    void aSuccessWhoseBodyIsNotTheProtocolsIsProtocol() {
        // Every read that needs a body, given one that is not JSON at all.
        server.canned(200, "<html>" + TOKEN + "</html>");
        Map<String, Executable> reads = new LinkedHashMap<>();
        reads.put("profile.fetch", () -> services.profile().fetch());
        reads.put("entitlements.fetch", () -> services.entitlements().fetch());
        reads.put("name.eligibility", () -> services.name().eligibility());
        reads.put("attributes.fetch", () -> services.attributes().fetch());
        reads.put("blocklist.fetch", () -> services.blocklist().fetch());
        reads.put("certificates.fetch", () -> services.certificates().fetch());
        reads.put("lookup.byName", () -> lookup.byName("Alex"));
        reads.put("lookup.byNames", () -> lookup.byNames(List.of("Alex")));
        assertThrown(reads, Kind.PROTOCOL, Optional.empty());

        // JSON, but fields of the wrong shape: a parser exception must not escape as itself.
        server.canned(200, "{\"id\":{\"nested\":true},\"name\":[1,2],\"skins\":\"" + TOKEN + "\"}");
        assertThrown(Map.of("profile.fetch", () -> services.profile().fetch()), Kind.PROTOCOL, Optional.empty());
    }

    @Test
    void aRefusedConnectionIsNetwork() throws Exception {
        int port;
        try (ServerSocket closed = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            port = closed.getLocalPort();
        }
        open(new AccountEndpoints("http://" + InetAddress.getLoopbackAddress().getHostAddress() + ":" + port));

        assertThrown(throwingCalls(), Kind.NETWORK, Optional.empty());
        assertThrown(lookupCalls(), Kind.NETWORK, Optional.empty());
        assertFailedMutations(Kind.NETWORK, Optional.empty());
    }

    @Test
    void aClosedTransportIsCancelled() {
        var transport = TestTransports.direct();
        services = AccountServices.create(transport, TOKEN, "11111111-2222-3333-4444-555555555555", server.endpoints());
        lookup = new ProfileLookupServiceImpl(transport, server.endpoints());
        transport.close();

        assertThrown(throwingCalls(), Kind.CANCELLED, Optional.empty());
        assertThrown(lookupCalls(), Kind.CANCELLED, Optional.empty());
        assertFailedMutations(Kind.CANCELLED, Optional.empty());
        assertEquals(0, server.requests().size(), "nothing left a closed transport");
    }
}

package lol.trq.alts.account;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import lol.trq.alts.net.HttpUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The public profile lookup. What these defend: no credential is ever sent to an endpoint that needs
 * none, "nobody has that name" is an empty answer rather than an exception, ids come back dashed, and a
 * value placed in a URL path cannot address a different endpoint.
 */
class ProfileLookupServiceTest {

    private static final Map<String, String> PLAYERS = Map.of(
            "alex", "{\"id\":\"069a79f444e94726a5befca90e38aaf5\",\"name\":\"Alex\"}",
            "steve_1", "{\"id\":\"853c80ef3c3749fdaa49938b674adae6\",\"name\":\"Steve_1\"}");

    private HttpServer server;
    private ProfileLookupService lookup;
    private final List<String> paths = new CopyOnWriteArrayList<>();
    private final List<String> authorizations = new CopyOnWriteArrayList<>();
    private volatile int forcedStatus;
    private volatile String forcedRetryAfter;

    @BeforeEach
    void setUp() throws IOException {
        HttpUtil.bind(null);
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", exchange -> {
            String path = exchange.getRequestURI().getRawPath();
            paths.add(exchange.getRequestMethod() + " " + path);
            authorizations.add(String.valueOf(exchange.getRequestHeaders().getFirst("Authorization")));
            exchange.getRequestBody().readAllBytes();

            int status = 404;
            String body = "{\"path\":\"" + path + "\",\"error\":\"NOT_FOUND\",\"errorMessage\":\"Not Found\"}";
            if (forcedStatus != 0) {
                status = forcedStatus;
                body = "{\"error\":\"X\",\"errorMessage\":\"forced\"}";
                if (forcedRetryAfter != null) {
                    exchange.getResponseHeaders().add("Retry-After", forcedRetryAfter);
                }
            } else {
                String key = path.substring(path.lastIndexOf('/') + 1).toLowerCase(Locale.ROOT);
                String byName = path.startsWith("/minecraft/profile/lookup/name/") ? PLAYERS.get(key) : null;
                String byId = null;
                if (path.startsWith("/minecraft/profile/lookup/") && !path.contains("/name/")) {
                    byId = PLAYERS.values().stream()
                            .filter(player -> player.contains(key))
                            .findFirst()
                            .orElse(null);
                }
                String found = byName != null ? byName : byId;
                if (found != null) {
                    status = 200;
                    body = found;
                }
            }
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        server.start();
        lookup = ProfileLookupService.create(new AccountEndpoints("http://"
                + InetAddress.getLoopbackAddress().getHostAddress() + ":"
                + server.getAddress().getPort()));
    }

    @AfterEach
    void tearDown() {
        server.stop(0);
    }

    @Test
    void aNameResolvesToADashedIdAndTheCanonicalName() throws Exception {
        Optional<PublicProfile> found = lookup.byName("ALEX");

        assertEquals("069a79f4-44e9-4726-a5be-fca90e38aaf5", found.orElseThrow().uuid());
        assertEquals("Alex", found.orElseThrow().name(), "the name comes back as the player capitalised it");
        assertEquals(List.of("GET /minecraft/profile/lookup/name/ALEX"), paths);
    }

    @Test
    void noCredentialIsSentToThePublicEndpoints() throws Exception {
        lookup.byName("Alex");
        lookup.byUuid("069a79f4-44e9-4726-a5be-fca90e38aaf5");

        assertEquals(List.of("null", "null"), authorizations, "the lookup is anonymous");
    }

    @Test
    void anUnknownNameIsEmptyNotAnException() throws Exception {
        assertTrue(lookup.byName("Nobody_Here").isEmpty());
        assertEquals(1, paths.size());
    }

    @Test
    void aValueThatCannotBeANameIsAnsweredWithoutARequest() throws Exception {
        assertTrue(lookup.byName(null).isEmpty());
        assertTrue(lookup.byName("").isEmpty());
        assertTrue(lookup.byName("ab").isEmpty());
        assertTrue(lookup.byName("../../entitlements/mcstore").isEmpty());
        assertTrue(lookup.byName("name?with=query").isEmpty());
        assertTrue(lookup.byName("has space").isEmpty());

        assertTrue(paths.isEmpty(), "no request is made for a name that cannot exist");
    }

    @Test
    void aUuidResolvesInEitherFormAndIsSentUndashed() throws Exception {
        PublicProfile dashed =
                lookup.byUuid("853C80EF-3C37-49FD-AA49-938B674ADAE6").orElseThrow();
        PublicProfile undashed =
                lookup.byUuid("853c80ef3c3749fdaa49938b674adae6").orElseThrow();

        assertEquals("Steve_1", dashed.name());
        assertEquals("853c80ef-3c37-49fd-aa49-938b674adae6", dashed.uuid());
        assertEquals(dashed, undashed);
        assertEquals(
                List.of(
                        "GET /minecraft/profile/lookup/853c80ef3c3749fdaa49938b674adae6",
                        "GET /minecraft/profile/lookup/853c80ef3c3749fdaa49938b674adae6"),
                paths);
    }

    @Test
    void anUnknownOrMalformedUuidIsEmpty() throws Exception {
        assertTrue(lookup.byUuid("00000000-0000-0000-0000-000000000000").isEmpty());
        assertEquals(1, paths.size());

        assertTrue(lookup.byUuid("not-a-uuid").isEmpty());
        assertTrue(lookup.byUuid("name/Alex").isEmpty());
        assertTrue(lookup.byUuid(null).isEmpty());
        assertEquals(1, paths.size(), "a value that is not a UUID is answered without a request");
    }

    @Test
    void aListResolvesKnownNamesAndLeavesUnknownOnesOut() throws Exception {
        List<PublicProfile> found = lookup.byNames(Arrays.asList("Steve_1", "Nobody_Here", "alex", null, "x", "ALEX"));

        assertEquals(2, found.size());
        assertEquals("Steve_1", found.get(0).name(), "results keep the order the names were given in");
        assertEquals("Alex", found.get(1).name());
        assertEquals("069a79f4-44e9-4726-a5be-fca90e38aaf5", found.get(1).uuid());
        assertEquals(3, paths.size(), "a repeated name is resolved once and an invalid one not at all");
    }

    @Test
    void aListOfAnyLengthIsAccepted() throws Exception {
        List<String> names = new ArrayList<>();
        for (int i = 0; i < 23; i++) {
            names.add("Player_" + i);
        }
        names.add("Alex");

        List<PublicProfile> found = lookup.byNames(names);

        assertEquals(1, found.size());
        assertEquals("Alex", found.get(0).name());
        assertEquals(24, paths.size());
        assertTrue(lookup.byNames(List.of()).isEmpty());
        assertTrue(lookup.byNames(null).isEmpty());
    }

    @Test
    void aRateLimitIsAnExceptionNotAnEmptyAnswer() {
        forcedStatus = 429;
        forcedRetryAfter = "9";

        AccountException single = assertThrows(AccountException.class, () -> lookup.byName("Alex"));
        AccountException byId =
                assertThrows(AccountException.class, () -> lookup.byUuid("069a79f4-44e9-4726-a5be-fca90e38aaf5"));
        AccountException list = assertThrows(AccountException.class, () -> lookup.byNames(List.of("Alex", "Steve_1")));

        assertTrue(single.rateLimited());
        assertEquals(Duration.ofSeconds(9), single.retryAfter());
        assertTrue(byId.rateLimited());
        assertTrue(list.rateLimited(), "a limited list fails rather than reading as nobody existing");
        assertEquals(3, paths.size(), "the list stops at the limit instead of sending the rest");
    }

    @Test
    void aRefusalOrServerErrorIsAnExceptionCarryingItsStatus() {
        forcedStatus = 401;
        AccountException refused = assertThrows(AccountException.class, () -> lookup.byName("Alex"));
        assertEquals(401, refused.status());
        assertTrue(refused.tokenRefused());

        forcedStatus = 503;
        AccountException down = assertThrows(AccountException.class, () -> lookup.byName("Alex"));
        assertEquals(503, down.status());
        assertFalse(down.notFound());
    }

    @Test
    void anUnreachableServiceIsAnException() {
        server.stop(0);

        AccountException thrown = assertThrows(AccountException.class, () -> lookup.byName("Alex"));
        assertEquals(0, thrown.status());
    }

    @Test
    void lookupPathSegmentsAreEncoded() {
        AccountEndpoints endpoints = new AccountEndpoints("https://services.example");

        assertEquals(
                "https://services.example/minecraft/profile/lookup/name/Plain_Name1",
                endpoints.lookupByName("Plain_Name1"),
                "an ordinary name is unchanged by encoding");
        assertEquals(
                "https://services.example/minecraft/profile/lookup/name/a%2Fb%20c", endpoints.lookupByName("a/b c"));
        assertEquals("https://services.example/minecraft/profile/lookup/a%2Bb", endpoints.lookupByUuid("a+b"));
        assertNull(Uuids.undashed("069a79f444e94726a5befca90e38aaf"), "thirty-one digits is not a UUID");
        assertEquals("not-an-id", Uuids.dashed("not-an-id"), "a value that is not a UUID is left alone");
    }
}

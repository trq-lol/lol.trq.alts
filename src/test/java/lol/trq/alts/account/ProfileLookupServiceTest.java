package lol.trq.alts.account;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonParser;
import com.sun.net.httpserver.HttpExchange;
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
import lol.trq.alts.net.NetTestHooks;
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
    private final List<List<String>> batches = new CopyOnWriteArrayList<>();
    private volatile int forcedStatus;
    private volatile String forcedRetryAfter;
    private volatile int forcedFromBatch;
    private volatile String batchBody;

    @BeforeEach
    void setUp() throws IOException {
        NetTestHooks.resetHttp();
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", exchange -> {
            String path = exchange.getRequestURI().getRawPath();
            paths.add(exchange.getRequestMethod() + " " + path);
            authorizations.add(String.valueOf(exchange.getRequestHeaders().getFirst("Authorization")));
            String sent = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);

            if (path.equals("/minecraft/profile/lookup/bulk/byname")) {
                answerBatch(exchange, sent);
                return;
            }
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
        lookup = new ProfileLookupServiceImpl(new AccountEndpoints("http://"
                + InetAddress.getLoopbackAddress().getHostAddress() + ":"
                + server.getAddress().getPort()));
    }

    @AfterEach
    void tearDown() {
        server.stop(0);
    }

    /** Answers the batch endpoint the way the service does: an array of the names that exist, no more. */
    private void answerBatch(HttpExchange exchange, String sent) throws IOException {
        int request = batches.size();
        List<String> names = new ArrayList<>();
        JsonParser.parseString(sent).getAsJsonArray().forEach(name -> names.add(name.getAsString()));
        batches.add(names);

        int status = 200;
        String body;
        if (forcedStatus != 0 && request >= forcedFromBatch) {
            status = forcedStatus;
            body = "{\"error\":\"X\",\"errorMessage\":\"forced\"}";
            if (forcedRetryAfter != null) {
                exchange.getResponseHeaders().add("Retry-After", forcedRetryAfter);
            }
        } else if (batchBody != null) {
            body = batchBody;
        } else if (names.size() > 10) {
            status = 400;
            body = "{\"error\":\"CONSTRAINT_VIOLATION\",\"errorMessage\":\"size must be between 0 and 10\"}";
        } else {
            // Reversed, because the service makes no promise about the order it answers in.
            List<String> found = new ArrayList<>();
            for (String name : names) {
                String player = PLAYERS.get(name.toLowerCase(Locale.ROOT));
                if (player != null) {
                    found.add(0, player);
                }
            }
            body = "[" + String.join(",", found) + "]";
        }
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
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
        assertTrue(lookup.byName("seventeen_chars_x").isEmpty());
        assertTrue(lookup.byName("../../entitlements/mcstore").isEmpty());
        assertTrue(lookup.byName("name?with=query").isEmpty());
        assertTrue(lookup.byName("has space").isEmpty());

        assertTrue(paths.isEmpty(), "no request is made for a name that cannot exist");
    }

    /**
     * Names of one and two characters cannot be taken today, but accounts created before the minimum
     * was raised still hold them. Answering "nobody has that name" without asking would be wrong.
     */
    @Test
    void aLegacyNameShorterThanThreeCharactersIsLookedUp() throws Exception {
        lookup.byName("ab");
        lookup.byName("x");
        lookup.byName("sixteen_chars_xx");

        assertEquals(
                List.of(
                        "GET /minecraft/profile/lookup/name/ab",
                        "GET /minecraft/profile/lookup/name/x",
                        "GET /minecraft/profile/lookup/name/sixteen_chars_xx"),
                paths,
                "the service is the one that knows whether a short name is held");

        lookup.byNames(List.of("ab", "x", "Alex"));

        assertEquals(List.of(List.of("ab", "x", "Alex")), batches, "and the same in a list");
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
        List<PublicProfile> found =
                lookup.byNames(Arrays.asList("Steve_1", "Nobody_Here", "alex", null, "bad name", "ALEX"));

        assertEquals(2, found.size());
        assertEquals("Steve_1", found.get(0).name(), "results keep the order the names were given in");
        assertEquals("Alex", found.get(1).name());
        assertEquals("069a79f4-44e9-4726-a5be-fca90e38aaf5", found.get(1).uuid(), "ids come back dashed");
        assertEquals(List.of("POST /minecraft/profile/lookup/bulk/byname"), paths, "one request for the list");
        assertEquals(
                List.of(List.of("Steve_1", "Nobody_Here", "alex")),
                batches,
                "a repeated name is sent once and an invalid one not at all");
        assertEquals(List.of("null"), authorizations, "the batch lookup is anonymous too");
    }

    @Test
    void aListOfInvalidNamesAloneCostsNoRequest() throws Exception {
        assertTrue(lookup.byNames(Arrays.asList(null, "", "seventeen_chars_x", "has space", "../x"))
                .isEmpty());

        assertTrue(paths.isEmpty());
    }

    /** The endpoint refuses more than ten names, so a longer list is split rather than refused. */
    @Test
    void aLongListIsSentTenNamesAtATime() throws Exception {
        List<String> names = new ArrayList<>();
        for (int i = 0; i < 12; i++) {
            names.add("Player_" + i);
        }
        names.add("Steve_1");
        names.addAll(List.of("Other_1", "Other_2", "Other_3", "Other_4", "Other_5", "Other_6", "Other_7"));
        names.add("alex");
        names.add("PLAYER_3");

        List<PublicProfile> found = lookup.byNames(names);

        assertEquals(List.of(10, 10, 1), batches.stream().map(List::size).toList());
        assertEquals(2, found.size());
        assertEquals("Steve_1", found.get(0).name(), "order follows the input across batches");
        assertEquals("Alex", found.get(1).name());
    }

    /**
     * A limit on the second request must not read as "the rest of those players do not exist", and the
     * caller needs the stated wait to know when to come back.
     */
    @Test
    void aRateLimitPartWayThroughAListFailsTheCallWithTheStatedWait() {
        forcedStatus = 429;
        forcedRetryAfter = "17";
        forcedFromBatch = 1;
        List<String> names = new ArrayList<>();
        for (int i = 0; i < 25; i++) {
            names.add("Player_" + i);
        }

        AccountException limited = assertThrows(AccountException.class, () -> lookup.byNames(names));

        assertTrue(limited.rateLimited());
        assertEquals(429, limited.status());
        assertEquals(Duration.ofSeconds(17), limited.retryAfter());
        assertEquals(2, batches.size(), "the list stops at the limit instead of sending the rest");
    }

    @Test
    void aBatchAnswerThatIsNotAListIsAnExceptionNotAnEmptyAnswer() {
        batchBody = "{\"unexpected\":true}";

        assertThrows(AccountException.class, () -> lookup.byNames(List.of("Alex")));
    }

    @Test
    void aBatchAnswerIsReadLeniently() throws Exception {
        batchBody = "[{\"id\":\"069a79f444e94726a5befca90e38aaf5\",\"name\":\"Alex\"},7,{\"name\":\"NoId\"}]";

        List<PublicProfile> found = lookup.byNames(List.of("Alex", "NoId"));

        assertEquals(List.of(new PublicProfile("069a79f4-44e9-4726-a5be-fca90e38aaf5", "Alex")), found);
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
        assertEquals(3, paths.size(), "twenty-four names are three requests, not twenty-four");
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
        assertEquals(Duration.ofSeconds(9), list.retryAfter());
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

package lol.trq.alts.account;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.time.Duration;
import java.util.Optional;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure.Kind;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The "no profile yet" state and the way out of it. An account can authenticate and still have no
 * profile; what these defend is that this is distinguishable from every other failure of the profile
 * read, and that creating one reports a taken name, a blocked name, and an unentitled account as the
 * different things they are.
 */
class ProfileCreationTest {

    private static final String NOT_FOUND = "{\"path\":\"/minecraft/profile\",\"errorType\":\"NOT_FOUND\","
            + "\"error\":\"NOT_FOUND\",\"errorMessage\":\"The server has not found anything matching the request URI\"}";

    private LoopbackServices server;

    @BeforeEach
    void setUp() throws IOException {
        server = new LoopbackServices();
    }

    @AfterEach
    void tearDown() {
        server.close();
    }

    private static String refusal(String detail) {
        return "{\"path\":\"/minecraft/profile\",\"errorType\":\"CONSTRAINT_VIOLATION\",\"error\":\"CONSTRAINT_VIOLATION\","
                + "\"errorMessage\":\"Invalid profile name\",\"details\":{\"status\":\"" + detail + "\"}}";
    }

    @Test
    void anAccountWithNoProfileIsAnEmptyResultNotAFailure() throws Exception {
        server.canned(404, NOT_FOUND);

        Optional<PlayerProfile> profile = server.services().profile().fetchIfPresent();

        assertTrue(profile.isEmpty());
    }

    @Test
    void fetchStillThrowsForAMissingProfileAndSaysThatIsWhatItWas() {
        server.canned(404, NOT_FOUND);

        AltsException thrown = assertThrows(
                AltsException.class, () -> server.services().profile().fetch());

        assertEquals(
                Kind.NOT_ENTITLED,
                thrown.kind(),
                "a missing profile is typed as sign-in and check type it, not as a credential problem");
    }

    @Test
    void fetchIfPresentReturnsTheProfileWhenThereIsOne() throws Exception {
        server.canned(200, "{\"id\":\"abc\",\"name\":\"Alex\"}");

        Optional<PlayerProfile> profile = server.services().profile().fetchIfPresent();

        assertEquals("Alex", profile.orElseThrow().name());
    }

    @Test
    void fetchIfPresentDoesNotSwallowOtherFailures() {
        server.canned(401, "{\"errorMessage\":\"Invalid token\"}");
        AltsException refused = assertThrows(
                AltsException.class, () -> server.services().profile().fetchIfPresent());
        assertEquals(Kind.UNAUTHORIZED, refused.kind());

        server.rateLimited(3);
        AltsException limited = assertThrows(
                AltsException.class, () -> server.services().profile().fetchIfPresent());
        assertEquals(Kind.RATE_LIMITED, limited.kind());
        assertEquals(Duration.ofSeconds(3), limited.failure().retryAfter().orElse(null));

        server.canned(503, "");
        AltsException down = assertThrows(
                AltsException.class, () -> server.services().profile().fetchIfPresent());
        assertEquals(Kind.NETWORK, down.kind());
    }

    @Test
    void creatingAProfilePostsTheNameAndReturnsTheProfile() throws Exception {
        server.canned(200, "{\"id\":\"abc\",\"name\":\"Fresh_Name\",\"skins\":[],\"capes\":[]}");

        ProfileCreationResult result = server.services().profile().create("Fresh_Name");

        assertTrue(result.success());
        assertEquals(ProfileCreationResult.Outcome.CREATED, result.outcome());
        assertEquals("Fresh_Name", result.profile().name());
        assertEquals("POST", server.last().method());
        assertEquals("/minecraft/profile", server.last().rawPath());
        assertEquals("{\"profileName\":\"Fresh_Name\"}", server.last().bodyText());
        assertEquals("Bearer test-token", server.last().authorization());
    }

    @Test
    void anInvalidNameIsRefusedLocallyWithoutARequest() throws Exception {
        ProfileService profile = server.services().profile();

        for (String bad :
                new String[] {null, "", "ab", "seventeen_chars__", "has space", "dash-ed", "sl/ash", "näme"}) {
            ProfileCreationResult result = profile.create(bad);
            assertEquals(ProfileCreationResult.Outcome.INVALID_NAME, result.outcome(), "name: " + bad);
            assertFalse(result.success());
            assertNull(result.profile());
        }

        assertTrue(server.requests().isEmpty(), "a name that can only be refused costs no request");
    }

    @Test
    void theBoundaryLengthsAreAccepted() throws Exception {
        server.canned(200, "{\"id\":\"abc\",\"name\":\"x\"}");

        assertTrue(server.services().profile().create("abc").success());
        assertTrue(server.services().profile().create("sixteen_chars___").success());
        assertEquals(2, server.requests().size());
    }

    @Test
    void aRefusalIsClassifiedFromTheDetailsStatus() throws Exception {
        ProfileService profile = server.services().profile();

        server.canned(400, refusal("DUPLICATE"));
        ProfileCreationResult duplicate = profile.create("Taken");
        assertEquals(ProfileCreationResult.Outcome.DUPLICATE, duplicate.outcome());
        assertFalse(duplicate.message().contains("Invalid profile name"), "the service's own text is not repeated");

        server.canned(400, refusal("NOT_ALLOWED"));
        assertEquals(
                ProfileCreationResult.Outcome.NOT_ALLOWED,
                profile.create("Blocked").outcome());

        server.canned(400, refusal("NOT_ENTITLED"));
        ProfileCreationResult unentitled = profile.create("Wanted");
        assertEquals(ProfileCreationResult.Outcome.FAILED, unentitled.outcome());
        assertEquals(Kind.NOT_ENTITLED, unentitled.failure().orElseThrow().kind());
        assertFalse(unentitled.success());
    }

    @Test
    void aBadRequestNamingNoKnownCauseIsAnInvalidName() throws Exception {
        server.canned(400, refusal("SOMETHING_NEW"));
        assertEquals(
                ProfileCreationResult.Outcome.INVALID_NAME,
                server.services().profile().create("Wanted").outcome());

        server.canned(400, "{}");
        assertEquals(
                ProfileCreationResult.Outcome.INVALID_NAME,
                server.services().profile().create("Wanted").outcome());
    }

    @Test
    void aRefusedTokenAndARateLimitAreFailedResultsNotExceptions() throws Exception {
        server.canned(401, "{\"errorMessage\":\"Invalid token\"}");
        ProfileCreationResult refused = server.services().profile().create("Wanted");
        assertEquals(ProfileCreationResult.Outcome.FAILED, refused.outcome());
        assertEquals(Kind.UNAUTHORIZED, refused.failure().orElseThrow().kind());
        assertFalse(refused.message().contains("Invalid token"), "the service's own text is not repeated");

        server.rateLimited(12);
        ProfileCreationResult limited = server.services().profile().create("Wanted");
        assertEquals(ProfileCreationResult.Outcome.FAILED, limited.outcome());
        assertEquals(Kind.RATE_LIMITED, limited.failure().orElseThrow().kind());
        assertEquals(
                Duration.ofSeconds(12),
                limited.failure().orElseThrow().retryAfter().orElse(null));

        server.canned(500, "");
        ProfileCreationResult down = server.services().profile().create("Wanted");
        assertEquals(ProfileCreationResult.Outcome.FAILED, down.outcome());
        assertEquals(Kind.NETWORK, down.failure().orElseThrow().kind());
    }

    @Test
    void anUnreachableServiceIsAFailedResultOfKindNetwork() {
        server.close();

        ProfileCreationResult unreachable = server.services().profile().create("Wanted");
        assertEquals(ProfileCreationResult.Outcome.FAILED, unreachable.outcome());
        assertEquals(Kind.NETWORK, unreachable.failure().orElseThrow().kind());
    }
}

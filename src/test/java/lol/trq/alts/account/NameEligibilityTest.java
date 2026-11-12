package lol.trq.alts.account;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import lol.trq.alts.net.NetTestHooks;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Name-change eligibility: when the name last changed, and the estimate built on it. The estimate is
 * arithmetic over a documented cooldown, not something the service returns, so what these pin down is the
 * arithmetic and that it never overrules the service's own flag.
 */
class NameEligibilityTest {

    private LoopbackServices server;

    @BeforeEach
    void setUp() throws IOException {
        NetTestHooks.resetHttp();
        server = new LoopbackServices();
    }

    @AfterEach
    void tearDown() {
        server.close();
    }

    @Test
    void eligibilityReadsWhenTheNameLastChanged() throws Exception {
        server.canned(
                200,
                "{\"changedAt\":\"2024-03-01T12:00:00Z\",\"createdAt\":\"2020-01-01T00:00:00Z\","
                        + "\"nameChangeAllowed\":false}");

        NameEligibility eligibility = server.services().name().eligibility();

        assertEquals("/minecraft/profile/namechange", server.last().rawPath());
        assertFalse(eligibility.nameChangeAllowed());
        assertEquals(Instant.parse("2024-03-01T12:00:00Z"), eligibility.changedAt());
        assertEquals(Instant.parse("2020-01-01T00:00:00Z"), eligibility.createdAt());
        assertEquals(
                Instant.parse("2024-03-31T12:00:00Z"),
                eligibility.estimatedNextChange(),
                "the estimate is the last change plus the thirty-day cooldown");
        assertEquals(Duration.ofDays(10), eligibility.estimatedWaitAt(Instant.parse("2024-03-21T12:00:00Z")));
        assertEquals(Duration.ZERO, eligibility.estimatedWaitAt(Instant.parse("2025-01-01T00:00:00Z")));
    }

    @Test
    void aNameNeverChangedHasNothingToEstimateFrom() throws Exception {
        server.canned(200, "{\"createdAt\":\"2020-01-01T00:00:00Z\",\"nameChangeAllowed\":true}");

        NameEligibility eligibility = server.services().name().eligibility();

        assertTrue(eligibility.nameChangeAllowed());
        assertNull(eligibility.changedAt());
        assertNull(eligibility.estimatedNextChange());
        assertEquals(Duration.ZERO, eligibility.estimatedWaitAt(Instant.now()), "allowed now means no wait");
        assertNotNull(eligibility.ageAt(Instant.now()));
        assertNull(new NameEligibility(false, null).estimatedWaitAt(Instant.now()));
    }

    @Test
    void eligibilityFailuresCarryTheirStatus() {
        server.canned(401, "{}");
        assertTrue(assertThrows(
                        AccountException.class, () -> server.services().name().eligibility())
                .tokenRefused());

        server.rateLimited(1);
        assertTrue(assertThrows(
                        AccountException.class, () -> server.services().name().eligibility())
                .rateLimited());
    }
}

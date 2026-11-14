package lol.trq.alts.internal.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import lol.trq.alts.net.NetworkScope;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * What a throttled response tells its caller. The delay may be stated as seconds or as a date, and may
 * not be stated at all; in every case the caller must still be able to see that it was throttled, because
 * the alternative reading — the request failed, try the next account — is how a rate limit becomes a ban.
 */
class HttpUtilRateLimitTest {

    private final HttpTransport http = TestTransports.direct();

    private static final Instant NOW = Instant.parse("2026-10-21T07:28:00Z");
    private static final String NOW_HEADER = "Wed, 21 Oct 2026 07:28:00 GMT";

    private HttpServer server;

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    /** Starts a server answering {@code /limited} with a 429 and, when given, a {@code Retry-After}. */
    private String startThrottlingServer(String retryAfter) throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/limited", exchange -> {
            exchange.getRequestBody().readAllBytes();
            if (retryAfter != null) {
                exchange.getResponseHeaders().add("Retry-After", retryAfter);
            }
            byte[] bytes = "{\"error\":\"slow down\"}".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(429, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        server.start();
        return "http://" + InetAddress.getLoopbackAddress().getHostAddress() + ":"
                + server.getAddress().getPort() + "/limited";
    }

    @Test
    void aDelayInSecondsIsRead() {
        assertEquals(Duration.ofSeconds(120), HttpTransport.parseRetryAfter("120", null, NOW));
        assertEquals(Duration.ofSeconds(120), HttpTransport.parseRetryAfter(" 120 ", NOW_HEADER, NOW));
        assertEquals(Duration.ZERO, HttpTransport.parseRetryAfter("0", null, NOW));
    }

    @Test
    void aDelayGivenAsADateIsMeasuredAgainstTheResponsesOwnClock() {
        // The local clock is an hour off; the response's Date header is what the delay is relative to.
        Instant skewed = NOW.plus(Duration.ofHours(1));

        Duration delay = HttpTransport.parseRetryAfter("Wed, 21 Oct 2026 07:29:30 GMT", NOW_HEADER, skewed);

        assertEquals(Duration.ofSeconds(90), delay);
    }

    @Test
    void withoutADateHeaderTheLocalClockIsTheReference() {
        assertEquals(Duration.ofSeconds(90), HttpTransport.parseRetryAfter("Wed, 21 Oct 2026 07:29:30 GMT", null, NOW));
        assertEquals(
                Duration.ofSeconds(90),
                HttpTransport.parseRetryAfter("Wed, 21 Oct 2026 07:29:30 GMT", "not a date", NOW));
    }

    @Test
    void aDateAlreadyPastIsNoWaitRatherThanNoAnswer() {
        Duration delay = HttpTransport.parseRetryAfter("Wed, 21 Oct 2026 07:00:00 GMT", NOW_HEADER, NOW);

        assertEquals(Duration.ZERO, delay, "the service did state a delay; it has merely elapsed");
    }

    @Test
    void anUnreadableDelayIsReportedAsNoneGiven() {
        assertNull(HttpTransport.parseRetryAfter(null, NOW_HEADER, NOW));
        assertNull(HttpTransport.parseRetryAfter("   ", NOW_HEADER, NOW));
        assertNull(HttpTransport.parseRetryAfter("soon", NOW_HEADER, NOW));
        assertNull(HttpTransport.parseRetryAfter("-5", NOW_HEADER, NOW));
    }

    @Test
    void aDateFormDelaySurvivesARealResponse() throws Exception {
        String at = DateTimeFormatter.RFC_1123_DATE_TIME.format(
                Instant.now().plusSeconds(90).atOffset(ZoneOffset.UTC));
        String url = startThrottlingServer(at);

        HttpTransport.HttpResponse response = http.postFormForStatus(url, null, "grant_type=refresh_token");

        assertTrue(response.rateLimited());
        assertNotNull(response.retryAfter(), "a date is a stated delay: " + at);
        long seconds = response.retryAfter().toSeconds();
        assertTrue(seconds >= 80 && seconds <= 91, "about ninety seconds, not " + seconds);
        assertEquals(response.retryAfter(), Backoff.after(response, 1, Duration.ofSeconds(1)));
    }

    @Test
    void aThrottleThatStatesNoDelayIsStillAThrottle() throws Exception {
        String url = startThrottlingServer(null);

        HttpTransport.HttpResponse json = http.postJsonForStatus(url, null, "{}", NetworkScope.of(null));
        HttpTransport.BytesResponse bytes = http.getBytesForStatus(url, null, 1024, null);
        HttpTransport.HeaderResponse header = http.getHeader(url, null, "Location", null);

        assertTrue(json.rateLimited(), "429 is a rate limit with or without Retry-After");
        assertNull(json.retryAfter());
        assertNotNull(json.body(), "and its body still reaches the caller");
        assertTrue(bytes.rateLimited());
        assertFalse(bytes.successful());
        assertNull(bytes.body());
        assertNull(bytes.retryAfter());
        assertTrue(header.rateLimited());
        assertNull(header.value());
    }

    @Test
    void aThrottledBinaryFetchCarriesItsDelay() throws Exception {
        String url = startThrottlingServer("7");

        HttpTransport.BytesResponse response = http.getBytesForStatus(url, null, 1024, null);

        assertEquals(429, response.status());
        assertEquals(Duration.ofSeconds(7), response.retryAfter());
        assertNull(http.getBytes(url, null, 1024, null), "the collapsing form still reports nothing");
    }

    /**
     * A stated wait is the service's to name, but not without limit: a hundred-quadrillion-second wait
     * overflows every millisecond conversion downstream and would park a run for good. A day is longer
     * than any real throttle and still a wait a host can honour.
     */
    @Test
    void anAbsurdStatedWaitIsHeldToADay() {
        assertEquals(Duration.ofDays(1), HttpTransport.parseRetryAfter("100000000000000000", null, NOW));
        assertEquals(Duration.ofDays(1), HttpTransport.parseRetryAfter("99999999999999999999999", null, NOW));
        assertEquals(
                Duration.ofDays(1), HttpTransport.parseRetryAfter("Fri, 31 Dec 9999 23:59:59 GMT", NOW_HEADER, NOW));
        assertEquals(Duration.ofDays(1), HttpTransport.parseRetryAfter("86400", null, NOW));
        assertEquals(Duration.ofSeconds(86_399), HttpTransport.parseRetryAfter("86399", null, NOW));
    }

    @Test
    void anAbsurdStatedWaitOnARealResponseIsHeldToADay() throws Exception {
        String url = startThrottlingServer("100000000000000000");

        HttpTransport.HttpResponse response = http.postFormForStatus(url, null, "grant_type=refresh_token");

        assertTrue(response.rateLimited());
        assertEquals(Duration.ofDays(1), response.retryAfter());
    }
}

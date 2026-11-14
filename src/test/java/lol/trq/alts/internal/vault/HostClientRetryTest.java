package lol.trq.alts.internal.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.internal.net.HttpTransport;
import lol.trq.alts.internal.net.TestTransports;
import org.junit.jupiter.api.Test;

/**
 * The {@code 422 missing_parents} retry (SPEC 10.4): it pauses on the transport, so a runtime that closes
 * during a pause ends the operation at once with {@code CANCELLED} instead of retrying into the closed
 * transport for the whole budget.
 */
class HostClientRetryTest {

    private static AltsException missingParents() {
        return VaultFailures.refused(422, "missing_parents", null, "the write");
    }

    @Test
    void aMissingParentsAnswerIsRetriedUntilTheHostHasThem() {
        try (HttpTransport transport = TestTransports.direct()) {
            AtomicInteger runs = new AtomicInteger();
            String out = HostClient.retryMissingParents(transport, () -> {
                if (runs.incrementAndGet() < 3) {
                    throw missingParents();
                }
                return "stored";
            });
            assertEquals("stored", out);
            assertEquals(3, runs.get());
        }
    }

    @Test
    void aCloseDuringThePauseEndsTheRetryPromptlyAsCancelled() {
        HttpTransport transport = TestTransports.direct();
        AtomicInteger runs = new AtomicInteger();
        AtomicLong closedAt = new AtomicLong();
        AltsException e = assertThrows(
                AltsException.class,
                () -> HostClient.retryMissingParents(transport, () -> {
                    if (runs.incrementAndGet() == 1) {
                        // Close early in the pause that follows this answer.
                        CompletableFuture.runAsync(
                                () -> {
                                    closedAt.set(System.nanoTime());
                                    transport.close();
                                },
                                CompletableFuture.delayedExecutor(
                                        HostClient.RETRY_PAUSE_MILLIS / 10,
                                        TimeUnit.MILLISECONDS,
                                        TestTransports.EXECUTOR));
                    }
                    throw missingParents();
                }));
        long afterClose = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - closedAt.get());
        assertEquals(Kind.CANCELLED, e.kind());
        assertEquals(1, runs.get(), "no try after the close");
        // A sleep would hold on to the end of the pause, nine tenths of it after the close.
        assertTrue(
                afterClose < HostClient.RETRY_PAUSE_MILLIS * 6 / 10,
                "ended at the close, not at the end of the pause: " + afterClose + " ms after it");
    }
}

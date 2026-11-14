package lol.trq.alts.internal.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
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
        long start = System.nanoTime();
        AltsException e = assertThrows(
                AltsException.class,
                () -> HostClient.retryMissingParents(transport, () -> {
                    if (runs.incrementAndGet() == 1) {
                        // Close while the retry is pausing, after this answer.
                        CompletableFuture.runAsync(
                                transport::close,
                                CompletableFuture.delayedExecutor(
                                        HostClient.RETRY_PAUSE_MILLIS / 4,
                                        TimeUnit.MILLISECONDS,
                                        TestTransports.EXECUTOR));
                    }
                    throw missingParents();
                }));
        long millis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
        assertEquals(Kind.CANCELLED, e.kind());
        assertEquals(1, runs.get(), "no try after the close");
        assertTrue(
                millis < HostClient.MISSING_PARENTS_RETRIES * HostClient.RETRY_PAUSE_MILLIS / 4,
                "ended promptly, not after the retry budget: " + millis + " ms");
    }
}

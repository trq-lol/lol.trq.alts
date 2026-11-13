package lol.trq.alts.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;

/**
 * Every wait in the library goes through the transport, and none may outlive what it waits on. The JDK's
 * own delayed executor swallows a refused task, which would leave the waiter pending for good.
 */
class HttpTransportWaitTest {

    @Test
    void aWaitWhoseExecutorRefusesItFailsRatherThanHangs() throws Exception {
        // A host's executor, shut down by the host while the runtime is still open.
        ExecutorService host = Executors.newSingleThreadExecutor();
        HttpTransport transport = new HttpTransport(null, host);
        host.shutdown();

        CompletableFuture<Void> wait = transport.delay(Duration.ofMillis(100));

        ExecutionException failed = assertThrows(ExecutionException.class, () -> wait.get(2, TimeUnit.SECONDS));
        IOException closed = assertInstanceOf(IOException.class, failed.getCause());
        assertInstanceOf(RejectedExecutionException.class, closed.getCause(), "the refusal is kept as the cause");
    }

    @Test
    void aRefusedTaskNeverRunsAndIsReportedOnce() throws Exception {
        ExecutorService host = Executors.newSingleThreadExecutor();
        HttpTransport transport = new HttpTransport(null, host);
        host.shutdown();
        AtomicBoolean ran = new AtomicBoolean();
        CompletableFuture<IOException> refused = new CompletableFuture<>();

        transport.schedule(50, () -> ran.set(true), failure -> {
            if (!refused.complete(failure)) {
                throw new AssertionError("refused twice");
            }
        });

        assertInstanceOf(IOException.class, refused.get(2, TimeUnit.SECONDS));
        // Closing afterwards must not report it a second time.
        transport.close();
        Thread.sleep(100);
        assertFalse(ran.get());
    }

    @Test
    void aWaitThatCompletesRunsOnTheTransportsExecutor() throws Exception {
        ExecutorService host = Executors.newSingleThreadExecutor(task -> new Thread(task, "host-wait"));
        try {
            HttpTransport transport = new HttpTransport(null, host);
            CompletableFuture<String> thread = transport
                    .delay(Duration.ofMillis(20))
                    .thenApply(ignored -> Thread.currentThread().getName());

            assertEquals("host-wait", thread.get(2, TimeUnit.SECONDS));
        } finally {
            host.shutdownNow();
        }
    }
}

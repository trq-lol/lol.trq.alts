package lol.trq.alts.internal.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
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

    /**
     * A wait registers itself so close() can end it, and must unregister once it ends some other way,
     * or a long-lived runtime that paces many runs would hold one closure per wait it ever made.
     */
    @Test
    void completedWaitsLeaveNothingRegistered() throws Exception {
        ExecutorService host = Executors.newSingleThreadExecutor();
        try {
            HttpTransport transport = new HttpTransport(null, host);
            List<CompletableFuture<Void>> waits = new ArrayList<>();
            for (int i = 0; i < 50; i++) {
                waits.add(transport.delay(Duration.ofMillis(5 + i % 7)));
            }
            assertTrue(transport.closerCount() > 0, "a pending wait is registered");

            CompletableFuture.allOf(waits.toArray(CompletableFuture[]::new)).get(5, TimeUnit.SECONDS);

            assertEquals(0, transport.closerCount(), "every completed wait unregistered itself");
            transport.schedule(0, () -> {}, failure -> {});
            assertEquals(0, transport.closerCount(), "and so does a task run at once");
        } finally {
            host.shutdownNow();
        }
    }

    @Test
    void closingRunsAndForgetsEveryPendingWait() throws Exception {
        HttpTransport transport = TestTransports.direct();
        CompletableFuture<Void> wait = transport.delay(Duration.ofHours(1));
        assertEquals(1, transport.closerCount());

        transport.close();

        assertThrows(ExecutionException.class, () -> wait.get(2, TimeUnit.SECONDS));
        assertEquals(0, transport.closerCount());
    }

    /**
     * A wait asked for after the transport closed is ended at once, even an hour-long one on an
     * executor that is still running: it must not wait out its delay to find the runtime gone.
     */
    @Test
    void aWaitAskedForAfterCloseFailsAtOnce() throws Exception {
        ExecutorService host = Executors.newSingleThreadExecutor();
        try {
            HttpTransport transport = new HttpTransport(null, host);
            transport.close();

            CompletableFuture<Void> wait = transport.delay(Duration.ofHours(1));

            ExecutionException failed = assertThrows(ExecutionException.class, () -> wait.get(2, TimeUnit.SECONDS));
            assertInstanceOf(IOException.class, failed.getCause());
            assertFalse(host.isShutdown(), "the host's executor was never the reason");
        } finally {
            host.shutdownNow();
        }
    }

    @Test
    void anActionRegisteredAfterCloseRunsBeforeTheCallReturns() {
        HttpTransport transport = TestTransports.direct();
        transport.close();
        Thread caller = Thread.currentThread();
        AtomicReference<Thread> ranOn = new AtomicReference<>();

        transport.whenClosed(() -> ranOn.set(Thread.currentThread()));

        assertSame(caller, ranOn.get(), "it ran synchronously, on the registering thread");
        assertEquals(0, transport.closerCount(), "and left nothing registered");
    }

    /** A wait too long to count in milliseconds is a very long wait, not an arithmetic failure. */
    @Test
    void aWaitTooLongForMillisecondsStillWaitsAndStillEndsOnClose() throws Exception {
        HttpTransport transport = TestTransports.direct();

        CompletableFuture<Void> wait = transport.delay(Duration.ofSeconds(Long.MAX_VALUE));

        assertFalse(wait.isDone(), "the wait is pending, not failed");
        transport.close();
        ExecutionException failed = assertThrows(ExecutionException.class, () -> wait.get(2, TimeUnit.SECONDS));
        assertInstanceOf(IOException.class, failed.getCause());
    }
}

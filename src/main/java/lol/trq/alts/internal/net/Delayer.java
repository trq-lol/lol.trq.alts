package lol.trq.alts.internal.net;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * The library's one timer: a single daemon thread that only hands tasks over when their delay ends, never
 * runs them for long itself.
 *
 * <p>Used in place of {@code CompletableFuture.delayedExecutor} and {@code orTimeout}, whose behaviour
 * depends on the runtime: the Java 8 build's back-ported versions sleep on the calling thread instead of a
 * timer thread.
 */
public final class Delayer {

    private static final ScheduledExecutorService TIMER = timer();

    private Delayer() {}

    /** Runs {@code task} once {@code delayMillis} have passed, on the timer thread. */
    public static ScheduledFuture<?> after(long delayMillis, Runnable task) {
        return TIMER.schedule(task, delayMillis, TimeUnit.MILLISECONDS);
    }

    /**
     * Completes {@code future} with a {@link TimeoutException} if it is not done after the timeout, the
     * same as {@code CompletableFuture.orTimeout}; the timer is cancelled as soon as the future completes.
     */
    public static <T> CompletableFuture<T> orTimeout(CompletableFuture<T> future, long timeout, TimeUnit unit) {
        ScheduledFuture<?> timer = TIMER.schedule(
                () -> {
                    future.completeExceptionally(new TimeoutException());
                },
                timeout,
                unit);
        future.whenComplete((value, failure) -> timer.cancel(false));
        return future;
    }

    private static ScheduledExecutorService timer() {
        ScheduledThreadPoolExecutor timer = new ScheduledThreadPoolExecutor(1, task -> {
            Thread thread = new Thread(task, "alts-timer");
            thread.setDaemon(true);
            return thread;
        });
        timer.setRemoveOnCancelPolicy(true);
        return Executors.unconfigurableScheduledExecutorService(timer);
    }
}

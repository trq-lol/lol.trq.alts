package lol.trq.alts.net;

import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

/**
 * The executor the library runs its blocking work on: every request, and whatever waits on one.
 *
 * <p>This is the single place to obtain it. Pass {@link #executor()} as the executor argument of
 * {@link java.util.concurrent.CompletableFuture#supplyAsync(java.util.function.Supplier, Executor)} and
 * its siblings rather than using the one-argument forms, which run on the JVM-wide common pool. That
 * pool is sized for CPU work and shared with the host: a handful of requests parked on a slow endpoint
 * would starve the host's own parallel streams and futures.
 *
 * <p>The default starts one virtual thread per task, so a blocked request costs no platform thread and
 * the executor holds nothing while idle. A host that wants its own — a bounded pool, a context-propagating
 * wrapper — installs it through {@code AltsRuntime.Builder#executor(Executor)}.
 *
 * @author trq
 * @since 0.12.0
 */
public final class IoExecutor {

    private static final Executor DEFAULT = Executors.newThreadPerTaskExecutor(
            Thread.ofVirtual().name("alts-io-", 0).factory());

    private static volatile Executor override;

    private IoExecutor() {}

    /**
     * Returns the executor blocking library work should run on.
     *
     * @return the host's executor when one is bound, otherwise the virtual-thread default
     * @since 0.12.0
     */
    public static Executor executor() {
        Executor bound = override;
        return bound != null ? bound : DEFAULT;
    }

    /**
     * Binds the host's executor. Called by {@code AltsRuntime.Builder#build()}. A {@code null} is
     * ignored rather than treated as "restore the default", so a second runtime built without an
     * executor does not undo the first one's choice.
     *
     * @param executor the host-supplied executor, or null to leave the current one in place
     * @since 0.12.0
     */
    public static void bind(Executor executor) {
        if (executor != null) {
            override = executor;
        }
    }

    /**
     * Restores the virtual-thread default. For tests, which share this static across classes; neither
     * public nor usable outside the test suite, since {@link #bind(Executor)} deliberately never undoes
     * a host's choice.
     *
     * @throws IllegalStateException outside the test suite
     */
    static void resetForTests() {
        if (!Boolean.getBoolean("lol.trq.alts.testSeams")) {
            throw new IllegalStateException("test seams are disabled outside the test suite");
        }
        override = null;
    }
}

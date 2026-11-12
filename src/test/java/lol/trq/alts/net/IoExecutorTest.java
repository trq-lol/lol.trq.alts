package lol.trq.alts.net;

import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/** Where blocking library work runs: off the JVM-wide common pool, and on the host's executor if it named one. */
class IoExecutorTest {

    @AfterEach
    void restoreDefault() {
        IoExecutor.resetForTests();
    }

    @Test
    void theDefaultRunsEachTaskOnAVirtualThreadOffTheCommonPool() throws Exception {
        Thread ran = CompletableFuture.supplyAsync(Thread::currentThread, IoExecutor.executor())
                .get(5, TimeUnit.SECONDS);

        assertTrue(ran.isVirtual(), "a parked request must not hold a platform thread");
        assertNotSame(ForkJoinPool.commonPool(), IoExecutor.executor());
        assertTrue(ran.getName().startsWith("alts-io-"), "the thread must be attributable in a dump: " + ran.getName());
    }

    @Test
    void aBoundExecutorReplacesTheDefault() {
        Executor host = Runnable::run;

        IoExecutor.bind(host);

        assertSame(host, IoExecutor.executor());
    }

    @Test
    void bindingNothingLeavesTheHostsExecutorInPlace() {
        Executor host = Runnable::run;
        IoExecutor.bind(host);

        IoExecutor.bind(null);

        assertSame(host, IoExecutor.executor(), "a second runtime built without one must not undo the first");
    }
}

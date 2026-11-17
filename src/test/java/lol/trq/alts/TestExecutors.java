package lol.trq.alts;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;

/**
 * A thread per task for tests: {@link Executors#newThreadPerTaskExecutor} where the runtime has it, and a cached
 * pool over the same factory where it does not (the Java 8 build's test run).
 */
public final class TestExecutors {

    private TestExecutors() {}

    public static ExecutorService perTask(ThreadFactory factory) {
        try {
            return Executors.newThreadPerTaskExecutor(factory);
        } catch (LinkageError noPerTaskExecutor) {
            return Executors.newCachedThreadPool(factory);
        }
    }
}

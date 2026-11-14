package lol.trq.alts.vault;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import java.util.function.Supplier;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure;
import lol.trq.alts.AltsFailure.Kind;

/**
 * The futures of the public vault API: each fails only with an {@link AltsException}, inside a {@link
 * CompletionException}, whatever went wrong underneath.
 *
 * @author trq
 * @since 1.0.0
 */
final class VaultFutures {

    private VaultFutures() {}

    /** Maps whatever a future failed with to an {@link AltsException}. */
    static AltsException classify(Throwable t) {
        Throwable c = t;
        while (c instanceof CompletionException && c.getCause() != null) {
            c = c.getCause();
        }
        if (c instanceof AltsException e) {
            return e;
        }
        if (c instanceof RejectedExecutionException) {
            return new AltsException(AltsFailure.of(Kind.CANCELLED, "Vault: the runtime is closed"), c);
        }
        return new AltsException(AltsFailure.of(Kind.UNKNOWN, "Vault: the operation failed unexpectedly"), c);
    }

    /**
     * {@code f}, failing only with an {@link AltsException}.
     *
     * @param f the future
     * @param <T> its value
     * @return the guarded future
     */
    static <T> CompletableFuture<T> guard(CompletableFuture<T> f) {
        return f.handle((value, failure) -> {
            if (failure != null) {
                throw new CompletionException(classify(failure));
            }
            return value;
        });
    }

    /**
     * Runs {@code op} on {@code executor}; a refused task fails the future rather than throwing.
     *
     * @param executor the runtime's executor
     * @param op the work
     * @param <T> its value
     * @return the guarded future
     */
    static <T> CompletableFuture<T> async(Executor executor, Supplier<T> op) {
        try {
            return guard(CompletableFuture.supplyAsync(op, executor));
        } catch (RejectedExecutionException refused) {
            return CompletableFuture.failedFuture(classify(refused));
        }
    }

    /**
     * A future already failed with {@code e}.
     *
     * @param e the failure
     * @param <T> the value it would have had
     * @return the failed future
     */
    static <T> CompletableFuture<T> failed(AltsException e) {
        return CompletableFuture.failedFuture(e);
    }

    /**
     * An {@code INVALID_INPUT} failure with a library-built message.
     *
     * @param what what is wrong, a fixed phrase
     * @return the exception
     */
    static AltsException invalid(String what) {
        return new AltsException(Kind.INVALID_INPUT, "Vault: " + what);
    }
}

package lol.trq.alts.account;

import java.util.Objects;
import java.util.Optional;
import lol.trq.alts.AltsFailure;

/**
 * What a scheduled name claim came to.
 *
 * <p>{@code claimed} answers "did I get the name"; {@code stopReason} answers "why did the run end",
 * which a host needs separately. A run that ran out its window, one that met a failure that ends it (a
 * refused token, an account with nothing to rename, a rate limit, a closed runtime), and one the caller
 * cancelled all end with {@code claimed == false}, and each calls for something different next.
 *
 * @param claimed whether the name was taken
 * @param attempts how many change attempts were made
 * @param finalResult the change result that decided the run — the winning one on success, the one that
 *     stopped it on a terminal failure — else the last attempt's; {@code null} when no attempt was made
 * @param stopReason why the run ended; added in 0.12.0
 * @param failure what ended the run, present exactly when the stop reason is
 *     {@link StopReason#TERMINAL_FAILURE}; a rate limit's stated wait travels in it; added in 1.0.0
 * @author trq
 * @since 1.0.0
 */
public record ClaimResult(
        boolean claimed,
        int attempts,
        NameChangeResult finalResult,
        StopReason stopReason,
        Optional<AltsFailure> failure) {

    /**
     * Why a scheduled claim stopped.
     *
     * @author trq
     * @since 0.12.0
     */
    public enum StopReason {
        /** The name was claimed. */
        CLAIMED,

        /** The window ran out with every attempt refused. */
        WINDOW_ELAPSED,

        /**
         * A failure ended the run: one no retry can fix (a refused token, an account with nothing to
         * rename), the service asking the run to slow down, or the runtime closing under it.
         * {@link ClaimResult#failure()} says which; a rate limit carries the wait it asked for, when it
         * said.
         */
        TERMINAL_FAILURE,

        /** The caller cancelled the run. */
        CANCELLED
    }

    /**
     * Checks that a failure is present exactly on {@link StopReason#TERMINAL_FAILURE}.
     *
     * @throws NullPointerException if {@code stopReason} or {@code failure} is null
     * @throws IllegalArgumentException if the failure does not match the stop reason
     */
    public ClaimResult {
        Objects.requireNonNull(stopReason, "stopReason");
        Objects.requireNonNull(failure, "failure");
        if ((stopReason == StopReason.TERMINAL_FAILURE) != failure.isPresent()) {
            throw new IllegalArgumentException("a failure is carried by TERMINAL_FAILURE and by nothing else");
        }
    }
}

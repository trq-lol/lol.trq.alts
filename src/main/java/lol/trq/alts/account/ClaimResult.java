package lol.trq.alts.account;

/**
 * What a scheduled name claim came to.
 *
 * <p>{@code claimed} answers "did I get the name"; {@code stopReason} answers "why did the run end",
 * which a host needs separately. A run that ran out its window, one the service told to slow down, one
 * whose token died, and one the caller cancelled all end with {@code claimed == false}, and each calls
 * for something different next.
 *
 * @param claimed whether the name was taken
 * @param attempts how many change attempts were made
 * @param finalResult the change result that decided the run — the winning one on success, the one that
 *     stopped it on a rate limit or terminal failure — else the last attempt's; {@code null} when no
 *     attempt was made
 * @param stopReason why the run ended; added in 0.12.0
 * @author trq
 * @since 1.0.0
 */
public record ClaimResult(boolean claimed, int attempts, NameChangeResult finalResult, StopReason stopReason) {

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
         * The service asked the run to slow down, so it stopped rather than keep sending;
         * {@link ClaimResult#finalResult()} carries the wait it asked for, when it said.
         */
        RATE_LIMITED,

        /** An attempt failed in a way no retry can fix — a refused token, an account with nothing to rename. */
        TERMINAL_FAILURE,

        /** The caller cancelled the run. */
        CANCELLED,

        /** The reason was not recorded, or is one this release does not know. */
        UNKNOWN
    }

    /** Fills a missing stop reason from what the other components imply. */
    public ClaimResult {
        if (stopReason == null) {
            stopReason = inferred(claimed, finalResult);
        }
    }

    /**
     * Creates a result without a stated stop reason, inferring it from the outcome — the shape this
     * record had before {@code stopReason} was added.
     *
     * @param claimed whether the name was taken
     * @param attempts how many change attempts were made
     * @param finalResult the deciding or last change result
     * @since 0.12.0
     */
    public ClaimResult(boolean claimed, int attempts, NameChangeResult finalResult) {
        this(claimed, attempts, finalResult, null);
    }

    /**
     * Returns whether the run was stopped because the service asked it to slow down.
     *
     * @return true if the stop reason is {@link StopReason#RATE_LIMITED}
     * @since 0.12.0
     */
    public boolean rateLimited() {
        return stopReason == StopReason.RATE_LIMITED;
    }

    private static StopReason inferred(boolean claimed, NameChangeResult finalResult) {
        if (claimed) {
            return StopReason.CLAIMED;
        }
        if (finalResult == null) {
            return StopReason.UNKNOWN;
        }
        return switch (finalResult.outcome()) {
            case RATE_LIMITED -> StopReason.RATE_LIMITED;
            case UNAUTHORIZED, NOT_ENTITLED -> StopReason.TERMINAL_FAILURE;
            default -> StopReason.WINDOW_ELAPSED;
        };
    }
}

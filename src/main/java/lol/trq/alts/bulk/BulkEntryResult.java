package lol.trq.alts.bulk;

import java.util.Objects;
import java.util.Optional;
import lol.trq.alts.AltsFailure;
import lol.trq.alts.account.Entitlements;
import lol.trq.alts.model.AltAccount;

/**
 * What became of one entry in a bulk run.
 *
 * <p>The {@code label} is the resolved username, or a positional {@code "entry 12"} before one is known.
 * It is deliberately never the input line: for an import that line is a credential, and results are
 * exactly what a host renders into a list and writes to a log.
 *
 * @param index the entry's position in the list it was given, counting from 0
 * @param label a name safe to display and log
 * @param account the resolved or refreshed account, or {@code null} when the entry failed
 * @param failure why the entry failed, or empty when it succeeded; carried since 1.0.0 in place of the
 *     former success flag and reason
 * @param message a short human-readable description; on a failure, the failure's message
 * @param attempts how many times this entry was tried, counting the first
 * @param entitlements what the account owns, on a successful entry of an entitlement sweep; {@code null}
 *     for every other kind of run and for a failed entry; added in 0.12.0
 * @author trq
 * @since 0.9.0
 */
public record BulkEntryResult(
        int index,
        String label,
        AltAccount account,
        Optional<AltsFailure> failure,
        String message,
        int attempts,
        Entitlements entitlements) {

    /**
     * Checks that a result is exactly one of a success with an account or a failure without one.
     *
     * @throws NullPointerException if {@code failure} is null, or a success carries no account
     * @throws IllegalArgumentException if a failure carries an account or entitlements
     * @since 1.0.0
     */
    public BulkEntryResult {
        Objects.requireNonNull(failure, "failure");
        if (failure.isEmpty()) {
            Objects.requireNonNull(account, "a successful entry carries its account");
        } else if (account != null || entitlements != null) {
            throw new IllegalArgumentException("a failed entry carries no account and no entitlements");
        }
    }

    /**
     * Returns whether the entry succeeded.
     *
     * @return true when there is no failure
     * @since 0.9.0
     */
    public boolean success() {
        return failure.isEmpty();
    }

    /**
     * Creates a successful result.
     *
     * @param index the entry's position
     * @param account the account it produced
     * @param message a short description
     * @param attempts how many times it was tried
     * @return a successful result labelled with the account's username
     * @since 0.9.0
     */
    public static BulkEntryResult success(int index, AltAccount account, String message, int attempts) {
        return new BulkEntryResult(index, account.username(), account, Optional.empty(), message, attempts, null);
    }

    /**
     * Creates a successful entitlement-sweep result.
     *
     * @param index the entry's position
     * @param account the account that was read
     * @param entitlements what it owns
     * @param message a short description
     * @param attempts how many times it was tried
     * @return a successful result carrying the entitlements
     * @since 0.12.0
     */
    public static BulkEntryResult success(
            int index, AltAccount account, Entitlements entitlements, String message, int attempts) {
        return new BulkEntryResult(
                index, account.username(), account, Optional.empty(), message, attempts, entitlements);
    }

    /**
     * Creates a failed result, whose message is the failure's.
     *
     * @param index the entry's position
     * @param label a name safe to display, never the input line
     * @param failure why the entry failed
     * @param attempts how many times it was tried
     * @return a failed result
     * @since 1.0.0
     */
    public static BulkEntryResult failure(int index, String label, AltsFailure failure, int attempts) {
        return new BulkEntryResult(index, label, null, Optional.of(failure), failure.message(), attempts, null);
    }

    /**
     * Returns the label an entry carries before it has resolved a name.
     *
     * @param index the entry's position
     * @return a positional label
     * @since 0.9.0
     */
    public static String positionalLabel(int index) {
        return "entry " + (index + 1);
    }
}

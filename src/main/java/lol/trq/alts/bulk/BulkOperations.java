package lol.trq.alts.bulk;

import java.util.List;
import lol.trq.alts.model.AltAccount;
import lol.trq.alts.model.LoginMode;

/**
 * Running one operation over many accounts, paced so the service does not treat it as an attack.
 *
 * <p>No operation here installs a session. A host writing its own loop over
 * {@link lol.trq.alts.auth.AltLoginService#loginAccount} gets fifty session switches and, on account
 * nine, a rate limit it has no way to recognise.
 *
 * <p>Not designed for host implementation; methods may be added in minor releases.
 *
 * @author trq
 * @since 0.9.0
 */
public interface BulkOperations {

    /**
     * Resolves a list of pasted credentials into accounts.
     *
     * <p>Each line is classified by {@link CredentialKind#detect} and sent to the route that fits it. A
     * line that cannot be placed fails as that entry rather than being guessed at. With
     * {@link LoginMode#ADD} the resolved accounts are stored; the live session is not touched either
     * way, so the host chooses afterwards what to log into. Neither is the store's current account, and
     * no account is stamped as used: a sign-in the user makes while the import runs stays current.
     *
     * @param entries the credential lines, one per account
     * @param mode whether to store what is resolved
     * @param options how to pace the run
     * @param progress where to report progress, or {@link BulkProgress#NONE}
     * @return a handle on the running operation
     * @since 0.9.0
     */
    BulkHandle importCredentials(List<String> entries, LoginMode mode, BulkOptions options, BulkProgress progress);

    /**
     * Refreshes every given account, renewing the ones whose tokens are spent and persisting each
     * rotation.
     *
     * @param accounts the accounts to refresh
     * @param options how to pace the run
     * @param progress where to report progress, or {@link BulkProgress#NONE}
     * @return a handle on the running operation
     * @since 0.9.0
     */
    BulkHandle refreshAll(List<AltAccount> accounts, BulkOptions options, BulkProgress progress);

    /**
     * Checks every given account without renewing anything.
     *
     * <p>The one to reach for when only looking: the token endpoint rotates the refresh token on every
     * redemption, so a sweep built on {@link #refreshAll} spends one rotation per account per sweep.
     *
     * @param accounts the accounts to check
     * @param options how to pace the run
     * @param progress where to report progress, or {@link BulkProgress#NONE}
     * @return a handle on the running operation
     * @since 0.9.0
     */
    BulkHandle checkAll(List<AltAccount> accounts, BulkOptions options, BulkProgress progress);

    /**
     * Reads what every given account owns, without renewing or changing anything.
     *
     * <p>"Which of these own Java outright, and which are riding a subscription that can lapse" is a
     * question about the whole list, so it is paced like the other sweeps: the same spacing, retries,
     * progress, cancellation and stop-on-rate-limit, with each request routed for its own account. A
     * successful entry carries the product set on {@link BulkEntryResult#entitlements()}; an account
     * that owns nothing succeeds with an empty set, because the read worked.
     *
     * <p>Each account is read with the access token it currently holds. One whose token has expired
     * fails its entry as {@link lol.trq.alts.AltsFailure.Kind#UNAUTHORIZED}; run
     * {@link #refreshAll} first when the tokens may be stale. An account with no token at all — an
     * offline one — fails the same way without a request being made.
     *
     * @param accounts the accounts to read
     * @param options how to pace the run
     * @param progress where to report progress, or {@link BulkProgress#NONE}
     * @return a handle on the running operation
     * @throws UnsupportedOperationException if this implementation predates the entitlement sweep
     * @since 0.12.0
     */
    default BulkHandle entitlementsAll(List<AltAccount> accounts, BulkOptions options, BulkProgress progress) {
        throw new UnsupportedOperationException("the entitlement sweep is not supported by this implementation");
    }
}

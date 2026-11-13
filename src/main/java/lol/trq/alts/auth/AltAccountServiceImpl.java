package lol.trq.alts.auth;

import java.time.Clock;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;
import lol.trq.alts.AltsFailure;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.auth.AccountNetworkUtil.ProfileLookup;
import lol.trq.alts.auth.AccountStatus.State;
import lol.trq.alts.model.AccountType;
import lol.trq.alts.model.AltAccount;
import lol.trq.alts.net.FailureText;
import lol.trq.alts.net.HttpTransport;
import lol.trq.alts.net.NetworkScope;
import lol.trq.alts.store.AccountStore;

/**
 * Concrete {@link AltAccountService}: validation and renewal, with no session anywhere in it.
 *
 * <p>{@link AltLoginServiceImpl} delegates here and adds the injection as its last step, which is the
 * decomposition that lets an account be operated on without being logged into.
 *
 * @author trq
 * @since 0.8.0
 */
public class AltAccountServiceImpl implements AltAccountService {

    private final AccountStore store;
    private final MicrosoftAuthConfig microsoftAuth;
    private final Clock clock;
    private final HttpTransport http;
    private final AccountNetworkUtil profiles;
    private final MicrosoftAuthUtil microsoft;

    /**
     * Creates an account service that persists rotated and spent credentials to {@code store}.
     *
     * @param store the runtime's account store; a renewal updates an account only if it already holds
     *     it
     * @param microsoftAuth the host's Microsoft authentication configuration, or {@code null} to disable
     *     renewal (validation still works)
     * @param http the runtime's transport, which every request goes through and whose executor every
     *     blocking step runs on
     * @since 1.0.0
     */
    public AltAccountServiceImpl(AccountStore store, MicrosoftAuthConfig microsoftAuth, HttpTransport http) {
        this(store, microsoftAuth, http, Clock.systemUTC());
    }

    // Exists so expiry-sensitive behaviour can be exercised against a fixed clock in tests.
    AltAccountServiceImpl(AccountStore store, MicrosoftAuthConfig microsoftAuth, HttpTransport http, Clock clock) {
        this.store = Objects.requireNonNull(store, "store");
        this.microsoftAuth = microsoftAuth;
        this.http = Objects.requireNonNull(http, "http");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.profiles = new AccountNetworkUtil(http);
        this.microsoft = new MicrosoftAuthUtil(http);
    }

    @Override
    public CompletableFuture<AccountStatus> check(AltAccount account) {
        if (account == null) {
            return CompletableFuture.completedFuture(
                    AccountStatus.failure(null, State.UNKNOWN, AltsFailure.of(Kind.INVALID_INPUT, "No account given")));
        }
        if (account.type() == AccountType.OFFLINE) {
            return CompletableFuture.completedFuture(AccountStatus.valid(account));
        }
        if (account.accessToken() == null || account.accessToken().isBlank()) {
            // Nothing to ask about. Whether that is recoverable depends only on what else it carries.
            return CompletableFuture.completedFuture(AccountStatus.failure(
                    account,
                    renewable(account) ? State.EXPIRED : State.REAUTH_REQUIRED,
                    AltsFailure.of(Kind.UNAUTHORIZED, "No stored session token")));
        }
        return guarded("Check", account, () -> CompletableFuture.supplyAsync(() -> validate(account), http.executor()));
    }

    @Override
    public CompletableFuture<AccountStatus> refresh(AltAccount account) {
        if (account == null) {
            return CompletableFuture.completedFuture(
                    AccountStatus.failure(null, State.UNKNOWN, AltsFailure.of(Kind.INVALID_INPUT, "No account given")));
        }
        if (account.type() == AccountType.OFFLINE) {
            return CompletableFuture.completedFuture(AccountStatus.valid(account));
        }

        boolean renewable = renewable(account);
        boolean expired = TokenExpiry.isExpired(account, clock);

        if (!renewable) {
            // A live token on an account that cannot be renewed is taken at its word, so refreshing is
            // no more expensive than logging in was.
            return expired
                    ? guarded(
                            "Refresh",
                            account,
                            () -> CompletableFuture.supplyAsync(() -> validate(account), http.executor()))
                    : CompletableFuture.completedFuture(AccountStatus.valid(account));
        }
        if (expired) {
            return guarded("Refresh", account, () -> renew(account));
        }
        return guarded(
                "Refresh",
                account,
                () -> CompletableFuture.supplyAsync(() -> validate(account), http.executor())
                        .thenCompose(status -> {
                            // Only a refused token is worth a renewal. An unreachable service, or an account with no
                            // profile, says nothing about the credential -- and the token endpoint rotates the refresh
                            // token on every redemption, so renewing on those spends a rotation to fix something else.
                            if (status.state() != State.EXPIRED) {
                                return CompletableFuture.completedFuture(status);
                            }
                            return renew(account);
                        }));
    }

    /**
     * Starts a check or a renewal whose future must hold a status whatever happens: a start that throws
     * (an executor that refuses the task once the runtime is closed) and a future that fails both become
     * a classified failed status, never an exception at the caller or a future completed exceptionally.
     *
     * @param label what is being done ("Check" or "Refresh"), prefixed to a failure message
     * @param account the account the status describes
     * @param start what starts the work
     * @return a future that always completes with a status
     */
    private CompletableFuture<AccountStatus> guarded(
            String label, AltAccount account, Supplier<CompletableFuture<AccountStatus>> start) {
        if (http.isClosed()) {
            return CompletableFuture.completedFuture(AccountStatus.failure(
                    account, State.UNKNOWN, AltsFailure.of(Kind.CANCELLED, label + ": the runtime is closed")));
        }
        try {
            return start.get().exceptionally(failure -> unexpectedFailure(label, account, failure));
        } catch (RuntimeException refused) {
            return CompletableFuture.completedFuture(unexpectedFailure(label, account, refused));
        }
    }

    private static AccountStatus unexpectedFailure(String label, AltAccount account, Throwable failure) {
        AltsFailure classified = FailureText.toFailure(label, failure);
        return AccountStatus.failure(account, stateFor(classified.kind(), false), classified);
    }

    /**
     * Asks the profile endpoint what the account's stored token is worth.
     *
     * @param account the account to validate
     * @return the classified outcome
     */
    private AccountStatus validate(AltAccount account) {
        ProfileLookup lookup;
        try {
            lookup = profiles.fetchProfile(account.accessToken(), profileUrl(), scopeFor(account));
        } catch (Exception unreachable) {
            AltsFailure failure = FailureText.toFailure("Validation failed", unreachable);
            return AccountStatus.failure(account, stateFor(failure.kind(), false), failure);
        }
        if (lookup.found()) {
            return AccountStatus.valid(correctUsername(account, lookup.username()));
        }
        AltsFailure failure = failureFor(lookup);
        return AccountStatus.failure(account, stateFor(failure.kind(), renewable(account)), failure);
    }

    /**
     * Updates and persists the stored username when the profile lookup returned a different one, so a
     * renamed account stops showing the name it carried when it was saved. Free, since the lookup that
     * validated the token already carried the current name. A no-op when the name is unchanged or the
     * store does not hold the account.
     *
     * @param account the account being validated
     * @param currentUsername the username the profile endpoint returned
     * @return the account carrying the current username
     */
    private AltAccount correctUsername(AltAccount account, String currentUsername) {
        if (currentUsername == null || currentUsername.equals(account.username())) {
            return account;
        }
        AltAccount renamed = account.withUsername(currentUsername);
        store.updateCredentials(renamed);
        return renamed;
    }

    /**
     * Renews an account from its stored refresh token, persisting the rotated credentials. The renewed
     * account is derived from the stored one, so bans, provenance, and shared attribution survive.
     *
     * @param account the account to renew
     * @return a future holding the outcome
     */
    private CompletableFuture<AccountStatus> renew(AltAccount account) {
        // The scope names the account on every hop, so a host proxying per account can route this
        // renewal apart from the next account's.
        NetworkScope scope = NetworkScope.forAccount(NetworkScope.Purpose.AUTH, account.uuid(), account.username());
        return microsoft
                .authenticateWithRefreshToken(microsoftAuth, account.refreshToken(), scope)
                .thenApply(profile -> {
                    AltAccount renewed =
                            account.withTokens(profile.accessToken(), profile.refreshToken(), profile.expiresAt());
                    store.updateCredentials(renewed);
                    return AccountStatus.renewed(renewed);
                })
                .exceptionally(failure -> renewalFailure(failure, account));
    }

    /**
     * Maps a failed renewal onto a status, discarding the stored refresh token only when the rejection
     * is permanent. A transient failure must never cost the user a working credential.
     *
     * @param failure the failure the renewal completed with
     * @param account the account being renewed
     * @return the classified status
     */
    private AccountStatus renewalFailure(Throwable failure, AltAccount account) {
        AltsFailure classified = FailureText.toFailure("Refresh", failure);

        if (classified.kind() != Kind.REAUTH_REQUIRED) {
            // The token was redeemed, or never got the chance: whatever failed after that is classified by
            // the step that failed. A throttle keeps its stated wait, and a refusal further down the chain
            // -- Xbox Live turning the account away -- is reported as what it is rather than as an outage a
            // caller would retry into.
            return AccountStatus.failure(account, renewalStateFor(classified.kind()), classified);
        }
        store.clearRefreshToken(account.uuid());
        return AccountStatus.failure(
                account.withTokens(account.accessToken(), null, 0L), State.REAUTH_REQUIRED, classified);
    }

    /**
     * Returns whether an account could be renewed if its token turned out to be spent.
     *
     * @param account the account to inspect
     * @return true if it holds a refresh token and Microsoft login is configured
     */
    private boolean renewable(AltAccount account) {
        return account.hasRefreshToken() && microsoftAuth != null;
    }

    /**
     * Returns the profile endpoint to validate against — the configured one when Microsoft login is
     * wired up, and the public default otherwise.
     *
     * @return the Minecraft services profile endpoint
     */
    private String profileUrl() {
        return microsoftAuth != null
                ? microsoftAuth.minecraftProfileUrl()
                : MicrosoftAuthConfig.DEFAULT_MINECRAFT_PROFILE_URL;
    }

    /**
     * Builds the network scope for a request made on one account's behalf, so a host proxying per
     * account can tell whose validation this is.
     *
     * @param account the account being validated
     * @return the scope
     */
    private static NetworkScope scopeFor(AltAccount account) {
        return NetworkScope.forAccount(NetworkScope.Purpose.PROFILE, account.uuid(), account.username());
    }

    /**
     * Classifies a profile lookup that did not resolve an identity. Package-private because the login
     * routes classify the same answers the same way: a refusal, an account with no profile, a throttle
     * and an outage each keep their own kind, and a success that named nobody is a protocol failure.
     *
     * @param lookup the lookup that failed
     * @return the classified failure
     */
    static AltsFailure failureFor(ProfileLookup lookup) {
        if (lookup.refused()) {
            return AltsFailure.of(Kind.UNAUTHORIZED, "Session token was refused");
        }
        if (lookup.missingProfile()) {
            return AltsFailure.of(Kind.NOT_ENTITLED, "This account has no Minecraft profile");
        }
        if (lookup.rateLimited()) {
            return AltsFailure.rateLimited("Rate limited by the profile service", lookup.retryAfter());
        }
        if (lookup.status() >= 200 && lookup.status() < 300) {
            return AltsFailure.of(Kind.PROTOCOL, "Profile lookup returned an unexpected response");
        }
        return AltsFailure.of(
                Kind.NETWORK, "Profile lookup failed with status " + lookup.status(), lookup.retryAfter());
    }

    /**
     * Maps a failure's kind onto the account state that describes it, given whether renewal is still on
     * the table. A refused token is only re-authentication material when there is no refresh token left
     * to try.
     *
     * <p>Exhaustive on purpose, with no {@code default}: a kind added later has to be placed here
     * deliberately rather than landing on {@link State#UNKNOWN} by omission.
     *
     * @param kind the failure's kind
     * @param renewable whether the account could still be renewed
     * @return the matching state
     */
    static State stateFor(Kind kind, boolean renewable) {
        return switch (kind) {
            case UNAUTHORIZED -> renewable ? State.EXPIRED : State.REAUTH_REQUIRED;
            case REAUTH_REQUIRED -> State.REAUTH_REQUIRED;
            // Xbox Live turning the account away shares the remedy of a missing profile: neither a retry
            // nor a fresh login changes it, and the kind says which of the two it was.
            case NOT_ENTITLED, XBOX_DENIED -> State.NOT_ENTITLED;
            // A throttle is the service being unavailable to this caller for now. Nothing was spent, and
            // it is the kind, not the state, that tells a caller to wait rather than retry.
            case NETWORK, RATE_LIMITED -> State.UNREACHABLE;
            // Only an interactive sign-in can be declined or run out of time, and neither check nor
            // refresh is one, so there is no account state these describe.
            case DECLINED, TIMED_OUT -> State.UNKNOWN;
            // A closed runtime, a refused argument, an unreadable answer: none says what the account is.
            case CANCELLED, INVALID_INPUT, PROTOCOL, NOT_CONFIGURED, UNKNOWN -> State.UNKNOWN;
            // Never raised by a check or a refresh; placed so the switch stays exhaustive.
            case NOT_FOUND, CONFLICT, STORAGE, CRYPTO -> State.UNKNOWN;
        };
    }

    /**
     * Maps the kind of a failed renewal onto a state. Differs from {@link #stateFor} in one place: a
     * token refused part-way down the chain is not a verdict on the stored refresh token, which the
     * token endpoint had just accepted (or refused without stating it spent), so it neither asks for
     * another refresh nor claims the credential was discarded.
     *
     * @param kind the failure's kind
     * @return the matching state
     */
    private static State renewalStateFor(Kind kind) {
        return kind == Kind.UNAUTHORIZED ? State.UNKNOWN : stateFor(kind, false);
    }
}

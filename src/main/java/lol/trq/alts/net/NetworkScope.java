package lol.trq.alts.net;

import java.util.Objects;
import java.util.Optional;

/**
 * What a request is for, and on whose behalf. A host's {@link lol.trq.alts.spi.ProxyProvider} reads this
 * to decide which route the request should take.
 *
 * <p>The account is carried because per-account proxying is the point: an alt manager that validates
 * fifty accounts from one address looks like one machine hammering the service, which is what the rate
 * limiter is there to stop. Both account fields are {@code null} for a request that has no account yet —
 * a fresh Microsoft login, a cookie import — and a host proxying those assigns from its own pool.
 *
 * <p>The route tag is the host's own label for a request that has no account to route on yet. A host
 * that runs one proxy per account, the host of a bot for one, signs a new account in through
 * {@code AltLoginService.routed(tag)} (or a bulk import with {@code BulkOptions.withRouteTag(tag)}), and
 * every request of that sign-in, on every hop, reaches the provider with the tag. It is empty for every
 * other request.
 *
 * <p>A final class rather than a record since 1.0.0, so a later field is an addition and not a break:
 * build one with {@link #of}, {@link #forAccount} and {@link #withRouteTag}. Two scopes are equal when
 * every field is.
 *
 * @author trq
 * @since 0.8.0
 */
public final class NetworkScope {

    /**
     * The kind of request being made, so a host can route authentication and avatars differently.
     *
     * @author trq
     * @since 0.8.0
     */
    public enum Purpose {
        /**
         * A token, cookie, or OAuth exchange with the identity services.
         *
         * @since 0.8.0
         */
        AUTH,

        /**
         * A Minecraft services profile lookup, used to validate a token and resolve an identity.
         *
         * @since 0.8.0
         */
        PROFILE,

        /**
         * A player avatar or skin fetch.
         *
         * @since 0.8.0
         */
        AVATAR,

        /**
         * A host-registered game-stats lookup.
         *
         * @since 0.8.0
         */
        STATS,

        /**
         * A shared-vault transport call.
         *
         * @since 0.8.0
         */
        VAULT
    }

    private final Purpose purpose;
    private final String accountUuid;
    private final String accountUsername;
    private final Optional<String> routeTag;

    /**
     * Substitutes {@link Purpose#AUTH} for a missing purpose, so a scope always states one.
     *
     * @throws IllegalArgumentException if the route tag is present but blank: a provider must never be
     *     handed a tag that names no route
     */
    private NetworkScope(Purpose purpose, String accountUuid, String accountUsername, Optional<String> routeTag) {
        if (routeTag.isPresent() && routeTag.get().isBlank()) {
            throw new IllegalArgumentException("a route tag must not be blank");
        }
        this.purpose = purpose == null ? Purpose.AUTH : purpose;
        this.accountUuid = accountUuid;
        this.accountUsername = accountUsername;
        this.routeTag = routeTag;
    }

    /**
     * Creates a scope for a request that belongs to no particular account.
     *
     * @param purpose what is being fetched; {@code null} reads as {@link Purpose#AUTH}
     * @return an account-less scope
     * @since 0.8.0
     */
    public static NetworkScope of(Purpose purpose) {
        return new NetworkScope(purpose, null, null, Optional.empty());
    }

    /**
     * Creates a scope for a request made on one account's behalf.
     *
     * @param purpose what is being fetched; {@code null} reads as {@link Purpose#AUTH}
     * @param accountUuid the dashed UUID of the account, or {@code null}
     * @param accountUsername the username of the account, or {@code null}
     * @return a scope naming the account
     * @since 0.8.0
     */
    public static NetworkScope forAccount(Purpose purpose, String accountUuid, String accountUsername) {
        return new NetworkScope(purpose, accountUuid, accountUsername, Optional.empty());
    }

    /**
     * Returns a copy of this scope carrying a route tag.
     *
     * @param tag the host's route tag, or null for none
     * @return the tagged copy
     * @throws IllegalArgumentException if {@code tag} is blank
     * @since 1.0.0
     */
    public NetworkScope withRouteTag(String tag) {
        return new NetworkScope(purpose, accountUuid, accountUsername, Optional.ofNullable(tag));
    }

    /**
     * Returns what is being fetched.
     *
     * @return the purpose, never {@code null}
     * @since 0.8.0
     */
    public Purpose purpose() {
        return purpose;
    }

    /**
     * Returns the dashed UUID of the account this is for.
     *
     * @return the UUID, or {@code null} for a request with no account
     * @since 0.8.0
     */
    public String accountUuid() {
        return accountUuid;
    }

    /**
     * Returns the username of the account this is for.
     *
     * @return the username, or {@code null} for a request with no account
     * @since 0.8.0
     */
    public String accountUsername() {
        return accountUsername;
    }

    /**
     * Returns the host's route tag for this request.
     *
     * @return the tag, or empty
     * @since 1.0.0
     */
    public Optional<String> routeTag() {
        return routeTag;
    }

    /**
     * Returns whether {@code o} is a scope with every field equal to this one's.
     *
     * @param o the object to compare
     * @return true when every field is equal
     * @since 0.8.0
     */
    @Override
    public boolean equals(Object o) {
        return o instanceof NetworkScope other
                && purpose == other.purpose
                && Objects.equals(accountUuid, other.accountUuid)
                && Objects.equals(accountUsername, other.accountUsername)
                && routeTag.equals(other.routeTag);
    }

    /**
     * Returns a hash over every field, consistent with {@link #equals(Object)}.
     *
     * @return the hash
     * @since 0.8.0
     */
    @Override
    public int hashCode() {
        return Objects.hash(purpose, accountUuid, accountUsername, routeTag);
    }

    /**
     * Returns every field, in the form the record printed them.
     *
     * @return a description
     * @since 0.8.0
     */
    @Override
    public String toString() {
        return "NetworkScope[purpose=" + purpose + ", accountUuid=" + accountUuid + ", accountUsername="
                + accountUsername + ", routeTag=" + routeTag + "]";
    }
}

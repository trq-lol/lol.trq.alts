package lol.trq.alts.net;

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
 * @param purpose what is being fetched
 * @param accountUuid the dashed UUID of the account this is for, or {@code null}
 * @param accountUsername the username of the account this is for, or {@code null}
 * @param routeTag the host's route tag for this request, or empty; added in 1.0.0
 * @author trq
 * @since 0.8.0
 */
public record NetworkScope(Purpose purpose, String accountUuid, String accountUsername, Optional<String> routeTag) {

    /**
     * The kind of request being made, so a host can route authentication and avatars differently.
     *
     * @author trq
     * @since 0.8.0
     */
    public enum Purpose {
        /** A token, cookie, or OAuth exchange with the identity services. */
        AUTH,

        /** A Minecraft services profile lookup, used to validate a token and resolve an identity. */
        PROFILE,

        /** A player avatar or skin fetch. */
        AVATAR,

        /** A host-registered game-stats lookup. */
        STATS,

        /** A shared-vault transport call. */
        VAULT
    }

    /**
     * Substitutes {@link Purpose#AUTH} for a missing purpose, so a scope always states one, and empty for
     * a missing route tag.
     */
    public NetworkScope {
        if (purpose == null) {
            purpose = Purpose.AUTH;
        }
        routeTag = routeTag == null ? Optional.empty() : routeTag;
    }

    /**
     * Creates a scope with no route tag: the shape before the tag existed.
     *
     * @param purpose what is being fetched
     * @param accountUuid the dashed UUID of the account, or {@code null}
     * @param accountUsername the username of the account, or {@code null}
     * @since 0.8.0
     */
    public NetworkScope(Purpose purpose, String accountUuid, String accountUsername) {
        this(purpose, accountUuid, accountUsername, Optional.empty());
    }

    /**
     * Returns a copy of this scope carrying a route tag.
     *
     * @param tag the host's route tag, or null for none
     * @return the tagged copy
     * @since 1.0.0
     */
    public NetworkScope withRouteTag(String tag) {
        return new NetworkScope(purpose, accountUuid, accountUsername, Optional.ofNullable(tag));
    }

    /**
     * Creates a scope for a request that belongs to no particular account.
     *
     * @param purpose what is being fetched
     * @return an account-less scope
     * @since 0.8.0
     */
    public static NetworkScope of(Purpose purpose) {
        return new NetworkScope(purpose, null, null);
    }

    /**
     * Creates a scope for a request made on one account's behalf.
     *
     * @param purpose what is being fetched
     * @param accountUuid the dashed UUID of the account, or {@code null}
     * @param accountUsername the username of the account, or {@code null}
     * @return a scope naming the account
     * @since 0.8.0
     */
    public static NetworkScope forAccount(Purpose purpose, String accountUuid, String accountUsername) {
        return new NetworkScope(purpose, accountUuid, accountUsername);
    }
}

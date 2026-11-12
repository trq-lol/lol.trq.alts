package lol.trq.alts.account;

import com.google.gson.annotations.SerializedName;
import java.time.Instant;
import java.util.Map;

/**
 * What an account is allowed to do online, from {@code GET /player/attributes}: its privileges, its
 * safety preferences, and any ban it is serving.
 *
 * <p>Read leniently, because the endpoint grows: every block is optional, a field this release does not
 * know is ignored, and a ban scope it has not heard of is kept under its own name rather than dropped. A
 * privilege the service did not state is {@code null} — "not said" — which the convenience accessors
 * treat as not granted, the same reading the game itself makes.
 *
 * @param privileges what the account may do online; never null, its members null where unstated
 * @param profanityFilter whether the profanity filter is on, or {@code null} when the service did not say
 * @param friendsPreferences the friends preferences as the service sent them, keyed by wire name; empty
 *     when absent
 * @param chatPreferences the chat preferences as the service sent them, keyed by wire name; empty when
 *     absent
 * @param bannedScopes the bans the account is serving, keyed by scope; empty for an account in good
 *     standing
 * @author trq
 * @since 0.12.0
 */
public record PlayerAttributes(
        @SerializedName("privileges") Privileges privileges,
        @SerializedName("profanityFilterPreferences") Boolean profanityFilter,
        @SerializedName("friendsPreferences") Map<String, String> friendsPreferences,
        @SerializedName("chatPreferences") Map<String, String> chatPreferences,
        @SerializedName("banStatus") Map<String, Ban> bannedScopes) {

    /**
     * The ban scope covering multiplayer servers — the one a host asks about before joining a server.
     *
     * @since 0.12.0
     */
    public static final String SCOPE_MULTIPLAYER = "MULTIPLAYER";

    /** Normalises the absent blocks to empties, so a caller never has to null-check them. */
    public PlayerAttributes {
        privileges = privileges == null ? new Privileges(null, null, null, null, null) : privileges;
        friendsPreferences = friendsPreferences == null ? Map.of() : Map.copyOf(friendsPreferences);
        chatPreferences = chatPreferences == null ? Map.of() : Map.copyOf(chatPreferences);
        bannedScopes = bannedScopes == null ? Map.of() : Map.copyOf(bannedScopes);
    }

    /**
     * Returns whether the account may use online chat.
     *
     * @return true only if the service stated the chat privilege as enabled
     * @since 0.12.0
     */
    public boolean canChat() {
        return Boolean.TRUE.equals(privileges.onlineChat());
    }

    /**
     * Returns whether the account may join multiplayer servers: the privilege is enabled and no
     * {@link #SCOPE_MULTIPLAYER} ban is listed.
     *
     * @return true if multiplayer is permitted and the account is not banned from it
     * @since 0.12.0
     */
    public boolean canPlayMultiplayer() {
        return Boolean.TRUE.equals(privileges.multiplayerServer()) && !bannedScopes.containsKey(SCOPE_MULTIPLAYER);
    }

    /**
     * Returns whether the account may join Realms.
     *
     * @return true only if the service stated the Realms privilege as enabled
     * @since 0.12.0
     */
    public boolean canPlayRealms() {
        return Boolean.TRUE.equals(privileges.multiplayerRealms());
    }

    /**
     * Returns whether the service lists any ban on the account, in any scope.
     *
     * @return true if at least one scope is banned
     * @since 0.12.0
     */
    public boolean banned() {
        return !bannedScopes.isEmpty();
    }

    /**
     * Returns whether any listed ban is still in force at the given instant, discounting one whose
     * expiry has passed.
     *
     * @param now the instant to measure against
     * @return true if a permanent or unexpired ban is listed
     * @since 0.12.0
     */
    public boolean bannedAt(Instant now) {
        return bannedScopes.values().stream().anyMatch(ban -> ban.activeAt(now));
    }

    /**
     * Returns the ban on one scope.
     *
     * @param scope the scope name, for example {@link #SCOPE_MULTIPLAYER}
     * @return the ban, or {@code null} when that scope is not banned
     * @since 0.12.0
     */
    public Ban ban(String scope) {
        return bannedScopes.get(scope);
    }

    /**
     * The privileges block. Each member is whether that privilege is enabled, or {@code null} when the
     * service did not state it.
     *
     * @param onlineChat whether online chat is permitted
     * @param multiplayerServer whether joining multiplayer servers is permitted
     * @param multiplayerRealms whether joining Realms is permitted
     * @param telemetry whether required telemetry is enabled
     * @param optionalTelemetry whether optional telemetry is enabled
     * @author trq
     * @since 0.12.0
     */
    public record Privileges(
            @SerializedName("onlineChat") Boolean onlineChat,
            @SerializedName("multiplayerServer") Boolean multiplayerServer,
            @SerializedName("multiplayerRealms") Boolean multiplayerRealms,
            @SerializedName("telemetry") Boolean telemetry,
            @SerializedName("optionalTelemetry") Boolean optionalTelemetry) {}

    /**
     * One ban, as listed under a scope.
     *
     * @param banId the ban's id
     * @param expires when the ban lifts, or {@code null} for a ban with no stated end
     * @param reason the service's reason code
     * @param reasonMessage the service's human-readable reason, when it gave one
     * @author trq
     * @since 0.12.0
     */
    public record Ban(
            @SerializedName("banId") String banId,
            @SerializedName("expires") Instant expires,
            @SerializedName("reason") String reason,
            @SerializedName("reasonMessage") String reasonMessage) {

        /**
         * Returns whether the ban has no stated end.
         *
         * @return true if no expiry was given
         * @since 0.12.0
         */
        public boolean permanent() {
            return expires == null;
        }

        /**
         * Returns whether the ban is in force at the given instant.
         *
         * @param now the instant to measure against
         * @return true if the ban is permanent or has not yet expired
         * @since 0.12.0
         */
        public boolean activeAt(Instant now) {
            return expires == null || now.isBefore(expires);
        }
    }
}

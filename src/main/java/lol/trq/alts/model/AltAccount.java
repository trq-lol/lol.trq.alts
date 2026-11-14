package lol.trq.alts.model;

import com.google.gson.annotations.SerializedName;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * An immutable Minecraft account stored locally within a client. Holds the credentials and metadata
 * required to reconstruct a game session. Every field carries a {@link SerializedName}, which names the
 * store file's format; only the library's own stores serialize an account, through an internal record of
 * the same shape, so the store file keeps the shape it had when this was a record. A host's own Gson cannot
 * read or write this class on the module path, and on the class path only by setting final fields through
 * reflection: a host that persists accounts itself goes through the accessors and {@link #builder}.
 *
 * <p>A final class rather than a record since 1.0.0, so a later field is an addition and not a break: build
 * one with {@link #of}, {@link #builder} or {@link #toBuilder()}, and derive copies with the {@code withX}
 * methods. Two accounts are equal when every field is.
 *
 * <p>When this account lives in a shared repository, {@code lastUsed}/{@code lastUsedBy} and {@code bans}
 * are shared state so members coordinate (who used it last, where it got banned). For a purely local
 * account the attribution fields are {@code null}.
 *
 * <p>{@code bans} maps a {@code serverId} to a {@link BanInfo} — bans are per-server, because an account
 * banned on one server may be fine on another. The {@code serverId} is an opaque, host-supplied string
 * (the same namespace a host uses for game stats); the library never inspects a connection or detects a
 * server. A {@code null}/empty map means "not known to be banned anywhere".
 *
 * <p>{@code sourceClient}/{@code sourceUser} record provenance for cross-client sharing: which client
 * (mod) the alt was added from and the user within that client, so members of a shared repo can tell a
 * given alt came from, say, one client's user versus another's. They are plain, opaque, implementer-set
 * strings — the standard defines only the field names, never their values. Both are {@code null} for a
 * purely local or unattributed account, and they ride inside the encrypted repo payload only (the sync
 * server never sees them), preserving the zero-knowledge guarantee.
 *
 * <p>{@code refreshToken} and {@code expiresAt} back silent session renewal. The refresh token is a
 * durable credential — far longer-lived than the access token — so it is stripped from a shared
 * repository payload unless that repository has explicitly opted in. {@code expiresAt} is epoch millis
 * and {@code 0} means "unknown", which callers read as "assume expired and renew".
 *
 * @author trq
 * @since 0.1.0
 */
public final class AltAccount {

    // The field names and their order are the store file's format. The library's Gson reads and writes them
    // through a record with the same components in the same order (internal.store.AltAccountJson), so no
    // final field is written by reflection; keep the two in step.
    @SerializedName("uuid")
    private final String uuid;

    @SerializedName("username")
    private final String username;

    @SerializedName("accessToken")
    private final String accessToken;

    @SerializedName("type")
    private final AccountType type;

    @SerializedName("lastUsed")
    private final long lastUsed;

    @SerializedName("lastUsedBy")
    private final String lastUsedBy;

    @SerializedName("bans")
    private final Map<String, BanInfo> bans;

    @SerializedName("sourceClient")
    private final String sourceClient;

    @SerializedName("sourceUser")
    private final String sourceUser;

    @SerializedName("refreshToken")
    private final String refreshToken;

    @SerializedName("expiresAt")
    private final long expiresAt;

    private AltAccount(
            String uuid,
            String username,
            String accessToken,
            AccountType type,
            long lastUsed,
            String lastUsedBy,
            Map<String, BanInfo> bans,
            String sourceClient,
            String sourceUser,
            String refreshToken,
            long expiresAt) {
        this.uuid = uuid;
        this.username = username;
        this.accessToken = accessToken;
        this.type = type;
        this.lastUsed = lastUsed;
        this.lastUsedBy = lastUsedBy;
        // Its own copy, unmodifiable, so neither the map it was built from nor the one bans() returns can
        // change the account. null stays null.
        this.bans = bans == null ? null : Collections.unmodifiableMap(new LinkedHashMap<>(bans));
        this.sourceClient = sourceClient;
        this.sourceUser = sourceUser;
        this.refreshToken = refreshToken;
        this.expiresAt = expiresAt;
    }

    /**
     * Creates a freshly authenticated account stamped as used at the current system time, unattributed.
     *
     * @param uuid the player's UUID
     * @param username the player's username
     * @param accessToken the authentication token
     * @param type the authentication protocol used
     * @return a new account with {@code lastUsed} set to now
     * @since 0.1.0
     */
    public static AltAccount of(String uuid, String username, String accessToken, AccountType type) {
        return new AltAccount(
                uuid, username, accessToken, type, System.currentTimeMillis(), null, null, null, null, null, 0L);
    }

    /**
     * Starts an account with every other field empty: never used ({@code lastUsed} 0), unattributed, no
     * bans, no refresh token, expiry unknown. This is what the record's canonical constructor was for: an
     * account rebuilt field by field, from a host's own storage, say.
     *
     * @param uuid the player's UUID
     * @param username the player's username
     * @param accessToken the authentication token
     * @param type the authentication protocol used
     * @return a builder holding those four
     * @since 1.0.0
     */
    public static Builder builder(String uuid, String username, String accessToken, AccountType type) {
        return new Builder(uuid, username, accessToken, type);
    }

    /**
     * Returns a builder holding every field of this account, to change several at once.
     *
     * @return a builder that builds an account equal to this one until a field is changed
     * @since 1.0.0
     */
    public Builder toBuilder() {
        return new Builder(uuid, username, accessToken, type)
                .lastUsed(lastUsed)
                .lastUsedBy(lastUsedBy)
                .bans(bans)
                .sourceClient(sourceClient)
                .sourceUser(sourceUser)
                .refreshToken(refreshToken)
                .expiresAt(expiresAt);
    }

    /**
     * Returns the unique identifier of the Minecraft player.
     *
     * @return the dashed UUID
     * @since 0.1.0
     */
    public String uuid() {
        return uuid;
    }

    /**
     * Returns the last known display name of the account.
     *
     * @return the username
     * @since 0.1.0
     */
    public String username() {
        return username;
    }

    /**
     * Returns the sensitive authentication token (OAuth, session, or cookie derived).
     *
     * @return the access token
     * @since 0.1.0
     */
    public String accessToken() {
        return accessToken;
    }

    /**
     * Returns the protocol used to authenticate this account.
     *
     * @return the account type
     * @since 0.1.0
     */
    public AccountType type() {
        return type;
    }

    /**
     * Returns the epoch-millis timestamp of the last successful login with this account.
     *
     * @return the last-used time, or {@code 0} when never used
     * @since 0.1.0
     */
    public long lastUsed() {
        return lastUsed;
    }

    /**
     * Returns the member id (Ed25519 identity) that last used this account in a shared repo.
     *
     * @return the member id, or {@code null} when used locally / unattributed
     * @since 0.1.0
     */
    public String lastUsedBy() {
        return lastUsedBy;
    }

    /**
     * Returns the locally-observed ban records keyed by server id, unmodifiable.
     *
     * @return the bans, or {@code null} if never observed banned
     * @since 0.5.0
     */
    public Map<String, BanInfo> bans() {
        // Already this account's own unmodifiable copy.
        return bans;
    }

    /**
     * Returns the client (mod) the alt was added from.
     *
     * @return the source client, or {@code null} when unattributed
     * @since 0.2.0
     */
    public String sourceClient() {
        return sourceClient;
    }

    /**
     * Returns the user within {@link #sourceClient()} that added the alt.
     *
     * @return the source user, or {@code null}
     * @since 0.2.0
     */
    public String sourceUser() {
        return sourceUser;
    }

    /**
     * Returns the OAuth refresh token used to renew the session.
     *
     * @return the refresh token, or {@code null} when the account has none (cookie, session, and offline
     *     accounts never do)
     * @since 0.6.0
     */
    public String refreshToken() {
        return refreshToken;
    }

    /**
     * Returns the epoch-millis expiry of {@link #accessToken()}.
     *
     * @return the expiry, or {@code 0} when unknown
     * @since 0.6.0
     */
    public long expiresAt() {
        return expiresAt;
    }

    /**
     * Returns a copy of this account with {@code lastUsed} refreshed to now, preserving any existing
     * attribution.
     *
     * @return a copy stamped as used now
     * @since 0.1.0
     */
    public AltAccount usedNow() {
        return toBuilder().lastUsed(System.currentTimeMillis()).build();
    }

    /**
     * Returns a copy of this account stamped as used now by the given member — for attributing activity
     * inside a shared repository.
     *
     * @param byMember the member id (Ed25519 identity) that used the account, or {@code null}
     * @return a copy stamped as used now by {@code byMember}
     * @since 0.1.0
     */
    public AltAccount usedNow(String byMember) {
        return toBuilder()
                .lastUsed(System.currentTimeMillis())
                .lastUsedBy(byMember)
                .build();
    }

    /**
     * Returns a copy of this account with the ban record for {@code serverId} set (or cleared). Other
     * servers' entries are preserved.
     *
     * @param serverId the server the ban applies to
     * @param ban the ban record, or {@code null} to clear this server's entry
     * @return a copy with {@code serverId}'s ban entry replaced
     * @since 0.5.0
     */
    public AltAccount withBan(String serverId, BanInfo ban) {
        Map<String, BanInfo> updated = bans == null ? new LinkedHashMap<>() : new LinkedHashMap<>(bans);
        if (ban == null) {
            updated.remove(serverId);
        } else {
            updated.put(serverId, ban);
        }
        return toBuilder().bans(updated).build();
    }

    /**
     * Returns a copy of this account with its username replaced. A username is mutable — a player can
     * rename — so a validation that resolves the current one updates the stored record through this
     * rather than leaving a stale display name behind.
     *
     * @param username the current username
     * @return a copy carrying the given username
     * @since 0.10.0
     */
    public AltAccount withUsername(String username) {
        return toBuilder().username(username).build();
    }

    /**
     * Returns a copy of this account stamped with its provenance — the client it was added from and the
     * user within that client — for cross-client shared repositories.
     *
     * @param sourceClient the client (mod) the alt was added from, or {@code null} to clear
     * @param sourceUser the user within {@code sourceClient} that added it, or {@code null}
     * @return a copy carrying the given provenance
     * @since 0.2.0
     */
    public AltAccount withSource(String sourceClient, String sourceUser) {
        return toBuilder().sourceClient(sourceClient).sourceUser(sourceUser).build();
    }

    /**
     * Returns a copy of this account carrying freshly issued credentials, preserving attribution, bans,
     * and provenance. Used by the renewal path, which must persist the rotated refresh token.
     *
     * @param accessToken the newly issued access token
     * @param refreshToken the newly issued refresh token, or {@code null} to clear it
     * @param expiresAt the epoch-millis expiry of {@code accessToken}, or {@code 0} when unknown
     * @return a copy carrying the given credentials
     * @since 0.6.0
     */
    public AltAccount withTokens(String accessToken, String refreshToken, long expiresAt) {
        return toBuilder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .expiresAt(expiresAt)
                .build();
    }

    /**
     * Returns this account's identity and credentials applied onto a record the store already holds, so
     * re-authenticating an alt refreshes what it logs in with without discarding what the store learned
     * about it. Bans, provenance, and shared attribution come from {@code existing} unless this account
     * carries its own, and a route that issues no refresh token leaves the stored one in place rather
     * than clearing it. {@code expiresAt} is always this account's, because it describes this account's
     * access token.
     *
     * @param existing the stored record for the same UUID, or {@code null} when the store holds none
     * @return this account merged onto {@code existing}, or this account unchanged when there is none
     * @since 0.6.0
     */
    public AltAccount mergedOnto(AltAccount existing) {
        if (existing == null) {
            return this;
        }
        return toBuilder()
                .lastUsedBy(lastUsedBy != null ? lastUsedBy : existing.lastUsedBy)
                .bans(bans != null && !bans.isEmpty() ? bans : existing.bans)
                .sourceClient(sourceClient != null ? sourceClient : existing.sourceClient)
                .sourceUser(sourceUser != null ? sourceUser : existing.sourceUser)
                .refreshToken(refreshToken != null ? refreshToken : existing.refreshToken)
                .build();
    }

    /**
     * Returns whether this account carries a usable refresh token.
     *
     * @return true if a non-blank refresh token is present
     * @since 0.6.0
     */
    public boolean hasRefreshToken() {
        return refreshToken != null && !refreshToken.isBlank();
    }

    /**
     * Returns whether this account is considered banned on the given server.
     *
     * @param serverId the server to check
     * @return {@code true} if a ban record for {@code serverId} is present and flags the account banned
     * @since 0.5.0
     */
    public boolean banned(String serverId) {
        BanInfo ban = bans == null ? null : bans.get(serverId);
        return ban != null && ban.banned();
    }

    /**
     * Returns whether this account is considered banned on any server.
     *
     * @return {@code true} if any server's ban record flags the account banned
     * @since 0.1.0
     */
    public boolean banned() {
        return bans != null && bans.values().stream().anyMatch(b -> b != null && b.banned());
    }

    /**
     * Returns the set of server ids on which this account is considered banned.
     *
     * @return an unmodifiable set of banned server ids (empty if none)
     * @since 0.5.0
     */
    public Set<String> bannedServers() {
        if (bans == null) {
            return Set.of();
        }
        return bans.entrySet().stream()
                .filter(e -> e.getValue() != null && e.getValue().banned())
                .map(Map.Entry::getKey)
                .collect(Collectors.toUnmodifiableSet());
    }

    /**
     * Returns whether {@code o} is an account with every field equal to this one's, the bans compared as
     * maps.
     *
     * @param o the object to compare
     * @return true when every field is equal
     * @since 0.1.0
     */
    @Override
    public boolean equals(Object o) {
        return o instanceof AltAccount other
                && lastUsed == other.lastUsed
                && expiresAt == other.expiresAt
                && Objects.equals(uuid, other.uuid)
                && Objects.equals(username, other.username)
                && Objects.equals(accessToken, other.accessToken)
                && type == other.type
                && Objects.equals(lastUsedBy, other.lastUsedBy)
                && Objects.equals(bans, other.bans)
                && Objects.equals(sourceClient, other.sourceClient)
                && Objects.equals(sourceUser, other.sourceUser)
                && Objects.equals(refreshToken, other.refreshToken);
    }

    /**
     * Returns a hash over every field, consistent with {@link #equals(Object)}.
     *
     * @return the hash
     * @since 0.1.0
     */
    @Override
    public int hashCode() {
        return Objects.hash(
                uuid,
                username,
                accessToken,
                type,
                lastUsed,
                lastUsedBy,
                bans,
                sourceClient,
                sourceUser,
                refreshToken,
                expiresAt);
    }

    /**
     * Returns a description of this account with both credentials redacted. Printing the access and
     * refresh tokens verbatim would let a host that logs an account — or anything embedding one, such as a
     * login result — write a durable credential to disk. Identity and state stay readable, because that is
     * what a log is for.
     *
     * @return a loggable description carrying no credential
     * @since 0.6.0
     */
    @Override
    public String toString() {
        return "AltAccount[uuid=" + uuid + ", username=" + username + ", accessToken=" + redacted(accessToken)
                + ", type=" + type + ", lastUsed=" + lastUsed + ", lastUsedBy=" + lastUsedBy + ", bans=" + bans
                + ", sourceClient=" + sourceClient + ", sourceUser=" + sourceUser + ", refreshToken="
                + redacted(refreshToken) + ", expiresAt=" + expiresAt + "]";
    }

    /**
     * Renders a credential as its presence alone.
     *
     * @param credential the secret to describe
     * @return {@code "null"} when absent, and a fixed placeholder otherwise
     */
    private static String redacted(String credential) {
        return credential == null ? "null" : "<redacted>";
    }

    /**
     * Builds an {@link AltAccount} field by field. Every setter takes {@code null} (or {@code 0}) as "none",
     * as the account's fields do. A builder is not thread-safe; the account it builds is immutable and takes
     * its own copy of the bans.
     *
     * @author trq
     * @since 1.0.0
     */
    public static final class Builder {

        private final String uuid;
        private String username;
        private String accessToken;
        private AccountType type;
        private long lastUsed;
        private String lastUsedBy;
        private Map<String, BanInfo> bans;
        private String sourceClient;
        private String sourceUser;
        private String refreshToken;
        private long expiresAt;

        private Builder(String uuid, String username, String accessToken, AccountType type) {
            this.uuid = uuid;
            this.username = username;
            this.accessToken = accessToken;
            this.type = type;
        }

        /**
         * Sets the username.
         *
         * @param value the username
         * @return this builder
         * @since 1.0.0
         */
        public Builder username(String value) {
            this.username = value;
            return this;
        }

        /**
         * Sets the access token.
         *
         * @param value the access token
         * @return this builder
         * @since 1.0.0
         */
        public Builder accessToken(String value) {
            this.accessToken = value;
            return this;
        }

        /**
         * Sets the account type.
         *
         * @param value the authentication protocol
         * @return this builder
         * @since 1.0.0
         */
        public Builder type(AccountType value) {
            this.type = value;
            return this;
        }

        /**
         * Sets the epoch-millis time of the last successful login.
         *
         * @param value the last-used time, or {@code 0} for never
         * @return this builder
         * @since 1.0.0
         */
        public Builder lastUsed(long value) {
            this.lastUsed = value;
            return this;
        }

        /**
         * Sets the member that last used the account in a shared repository.
         *
         * @param value the member id, or {@code null}
         * @return this builder
         * @since 1.0.0
         */
        public Builder lastUsedBy(String value) {
            this.lastUsedBy = value;
            return this;
        }

        /**
         * Sets the ban records keyed by server id. The account takes its own copy when built.
         *
         * @param value the bans, or {@code null} for never observed banned
         * @return this builder
         * @since 1.0.0
         */
        public Builder bans(Map<String, BanInfo> value) {
            this.bans = value;
            return this;
        }

        /**
         * Sets the client (mod) the alt was added from.
         *
         * @param value the source client, or {@code null}
         * @return this builder
         * @since 1.0.0
         */
        public Builder sourceClient(String value) {
            this.sourceClient = value;
            return this;
        }

        /**
         * Sets the user within the source client that added the alt.
         *
         * @param value the source user, or {@code null}
         * @return this builder
         * @since 1.0.0
         */
        public Builder sourceUser(String value) {
            this.sourceUser = value;
            return this;
        }

        /**
         * Sets the OAuth refresh token.
         *
         * @param value the refresh token, or {@code null} for none
         * @return this builder
         * @since 1.0.0
         */
        public Builder refreshToken(String value) {
            this.refreshToken = value;
            return this;
        }

        /**
         * Sets the epoch-millis expiry of the access token.
         *
         * @param value the expiry, or {@code 0} when unknown
         * @return this builder
         * @since 1.0.0
         */
        public Builder expiresAt(long value) {
            this.expiresAt = value;
            return this;
        }

        /**
         * Builds the account.
         *
         * @return a new immutable account
         * @since 1.0.0
         */
        public AltAccount build() {
            return new AltAccount(
                    uuid,
                    username,
                    accessToken,
                    type,
                    lastUsed,
                    lastUsedBy,
                    bans,
                    sourceClient,
                    sourceUser,
                    refreshToken,
                    expiresAt);
        }
    }
}

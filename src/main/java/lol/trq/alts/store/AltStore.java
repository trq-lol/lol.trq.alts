package lol.trq.alts.store;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.annotations.SerializedName;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.UnaryOperator;
import lol.trq.alts.model.AltAccount;
import lol.trq.alts.model.BanInfo;
import lol.trq.alts.spi.StoreKeyProvider;
import lol.trq.alts.spi.VaultDirectoryProvider;

/**
 * Persists and manages the lifecycle of Minecraft accounts on local disk. Data is stored encrypted
 * with a hardware-bound key to prevent unauthorized access or transfer between systems.
 *
 * <p>The directory is supplied by the host through a {@link VaultDirectoryProvider} bound at runtime
 * startup; the store keeps no Minecraft or platform types. This store holds <em>accounts</em> only —
 * accounts may be shared into a multi-member repository, so a user's own secrets (API keys and the like)
 * live separately in {@link SecretStore} and never travel with the accounts.
 *
 * <p>One carve-out: an account's OAuth {@code refreshToken} is a credential and it <em>does</em> sit on
 * the {@link AltAccount} record, because renewal has to work for a shared alt too — otherwise every
 * member except whoever added it watches the alt die when its access token lapses. It is therefore not
 * covered by the rule above, and is governed instead by the repository's sharing policy: a repository
 * withholds refresh tokens unless its manifest opts in, and the strip runs on both write and read (see
 * {@link lol.trq.alts.vault.SharedVault}). A purely local account is unaffected — its refresh token
 * never leaves this file.
 *
 * <p>Every mutator here is atomic with respect to the others and to a save, and a save replaces the
 * file in one step, so neither a concurrent login nor a crash can leave a half-written store. A write
 * that fails is reported on {@link #saveError()}; nothing here throws at a caller for an I/O failure.
 *
 * @author trq
 * @since 0.1.0
 */
public final class AltStore {

    /**
     * How long a burst of mutations is gathered for before one write covers them, once
     * {@code AltsRuntime.Builder#build()} has turned coalescing on. See {@link #writeDelay(Duration)}.
     *
     * @since 0.12.0
     */
    public static final Duration DEFAULT_WRITE_DELAY = StoreFile.DEFAULT_WRITE_DELAY;

    /** Gson keyed purely on {@link SerializedName}, the house serialization convention. */
    private static final Gson GSON = new GsonBuilder().create();

    /** The encrypted file, with the neutral default name and key binding a host may override. */
    private static final StoreFile FILE = new StoreFile("accounts.dat", "lol.trq.alts");

    /** Guards every compound mutation, and the hand-off of its snapshot to {@link #FILE}. */
    private static final Object LOCK = new Object();

    // Copy-on-write because logins resolve on the library executor while the host reads accounts() from its
    // render thread; a plain ArrayList lets one thread's write blow up the other's iteration.
    private static final List<AltAccount> ACCOUNTS = new CopyOnWriteArrayList<>();

    private static volatile AltAccount currentAccount = null;
    private static volatile String loadWarning;

    private AltStore() {}

    /**
     * Binds the host directory provider. Called once by {@code AltsRuntime.Builder#build()} before any
     * load or save.
     *
     * <p>Binding starts from the defaults: writes are synchronous and the key is machine-derived until
     * {@link #writeDelay(Duration)} and {@link #keyProvider(StoreKeyProvider)} are called after it, which
     * the runtime builder does. Code that binds the store directly — a test, mostly — therefore gets a
     * file that is on disk the moment a mutator returns.
     *
     * @param provider the host-supplied vault directory provider
     */
    public static void bind(VaultDirectoryProvider provider) {
        FILE.bind(provider);
    }

    /**
     * Overrides the store filename and key-binding constant. Hosts with pre-existing encrypted files
     * pass the legacy values here so those files keep loading; fresh hosts can ignore this and take the
     * neutral defaults. Null or blank arguments leave the current value unchanged.
     *
     * @param storeFileName the on-disk filename, or null/blank to keep the default
     * @param storeKeyBinding the key-binding constant, or null/blank to keep the default
     */
    public static void configure(String storeFileName, String storeKeyBinding) {
        FILE.configure(storeFileName, storeKeyBinding);
    }

    /**
     * Installs a host key provider, so the file is sealed under the host's secret instead of the
     * machine-derived default. Call after {@link #bind} and before {@link #load()}; the runtime builder
     * does both. A file written before the provider was installed still loads, and is rewritten under
     * the host's key; a file written under a host key does not open without it.
     *
     * @param provider the host key provider, or null for the machine-derived default
     * @since 0.12.0
     */
    public static void keyProvider(StoreKeyProvider provider) {
        FILE.keyProvider(provider);
    }

    /**
     * Sets how long mutations are gathered for before one write covers them all. With a delay, a
     * mutator returns as soon as memory is updated and a single background daemon thread writes the
     * file shortly after, so a burst — a bulk refresh, an import — costs one write instead of one each,
     * and none of them on the caller's thread. Pending state is written by {@link #flush()}, by
     * {@link #load()}, and at JVM shutdown, so a host that never flushes still loses nothing on a
     * normal exit.
     *
     * @param delay the coalescing window; null, zero, or negative writes synchronously inside the mutator
     * @since 0.12.0
     */
    public static void writeDelay(Duration delay) {
        FILE.writeDelay(delay);
    }

    /**
     * Records a locally-observed ban for the account with {@code uuid} on {@code serverId} and persists
     * it. Updates the stored list entry and the current account when they match; a no-op if the UUID is
     * unknown. Other servers' ban entries on the account are preserved.
     *
     * @param uuid the dashed UUID of the banned account
     * @param serverId the server the ban was observed on (a host-supplied id; use a fallback such as
     *     {@code "unknown"} when the server cannot be identified)
     * @param ban the observed ban record
     */
    public static void markBanned(String uuid, String serverId, BanInfo ban) {
        synchronized (LOCK) {
            replace(uuid, a -> a.withBan(serverId, ban));
            AltAccount current = currentAccount;
            if (matches(current, uuid)) {
                currentAccount = current.withBan(serverId, ban);
            }
            scheduleSave();
        }
    }

    /**
     * Returns the list of all accounts currently held in memory. The list is copy-on-write, so a host
     * may iterate it from its render thread while a login resolving on a background thread mutates it;
     * the iteration sees a snapshot rather than failing.
     *
     * @return the live list of accounts
     */
    public static List<AltAccount> accounts() {
        return ACCOUNTS;
    }

    /**
     * Returns why the last {@link #load()} could not read an existing store file, if it could not.
     *
     * <p>A store that fails to decrypt is not an empty store, and the two must not be confused: the key
     * is derived from machine properties, so a renamed OS user or a moved home directory turns a
     * perfectly good file into an unreadable one. While this is set, {@link #save()} preserves the
     * unreadable file rather than overwriting it, and a host should tell the user their accounts did not
     * load instead of showing an empty list.
     *
     * <p>The description is the file's name and a fixed phrase. It never carries a filesystem path, so
     * it is safe to show and to log.
     *
     * @return the failure description, or empty when the last load succeeded or found no file
     * @since 0.7.0
     */
    public static Optional<String> loadError() {
        return Optional.ofNullable(FILE.loadError());
    }

    /**
     * Returns a note about entries the last successful {@link #load()} had to leave out. A stored entry
     * with no UUID cannot be addressed by anything here, and a second entry for a UUID already read is a
     * duplicate; both are skipped so that one bad record does not cost the rest. Unlike
     * {@link #loadError()} this does not mean the store failed to load — every valid account is in
     * {@link #accounts()}.
     *
     * @return the note, or empty when the last load skipped nothing
     * @since 0.12.0
     */
    public static Optional<String> loadWarning() {
        return Optional.ofNullable(loadWarning);
    }

    /**
     * Returns why the most recent write did not reach the disk, if it did not. While this is set the
     * file is whatever the last successful write left — never a partial one — and the accounts in
     * memory are ahead of it; the write is retried by the next mutation, {@link #save()}, or
     * {@link #flush()}, and a success clears this. Like {@link #loadError()}, the description carries no
     * filesystem path.
     *
     * @return the failure description, or empty when the last write succeeded
     * @since 0.12.0
     */
    public static Optional<String> saveError() {
        return Optional.ofNullable(FILE.saveError());
    }

    /**
     * Returns the currently active account, if any.
     *
     * @return an optional holding the active account, or empty if none is set
     */
    public static Optional<AltAccount> currentAccount() {
        return Optional.ofNullable(currentAccount);
    }

    /**
     * Marks {@code account} as the active account, stamping it as used now. If the store holds an entry
     * with the same UUID, that entry's last-used time is refreshed and persisted.
     *
     * <p>Only the timestamp of the stored entry changes. Its credentials are deliberately left alone: a
     * caller restoring an earlier current account holds a copy read before some renewal rotated its
     * tokens, and writing that copy back would put a spent refresh token on disk. Credentials reach the
     * store through {@link #addAccount} and {@link #updateCredentials} only.
     *
     * @param account the account to make current, or null to clear
     */
    public static void useAccount(AltAccount account) {
        synchronized (LOCK) {
            if (account == null) {
                currentAccount = null;
                return;
            }
            boolean stored = replace(account.uuid(), AltAccount::usedNow);
            currentAccount = account.usedNow();
            if (stored) {
                scheduleSave();
            }
        }
    }

    /**
     * Replaces the stored entry for {@code account}'s UUID with the given record and persists. Called
     * after a renewal so the rotated refresh token survives a restart; without it the next process start
     * would replay a token the authentication service has already invalidated.
     *
     * <p><strong>Silently does nothing when the UUID is not already stored</strong>, and that is
     * deliberate, not an oversight. Accounts reach the login service from places this file is not meant
     * to mirror — a shared repository, or a one-off {@code LoginMode.DIRECT} login the user explicitly
     * declined to save — and writing them here would persist credentials the user chose to keep out of
     * the store, which is a worse failure than not persisting them. The rotated credential is never lost
     * either way: it is returned on {@code LoginResult.account()}, and for an account the store does not
     * hold it is the host's job to put it wherever that account actually lives.
     *
     * @param account the account carrying freshly issued credentials
     * @since 0.6.0
     */
    public static void updateCredentials(AltAccount account) {
        synchronized (LOCK) {
            replace(account.uuid(), a -> account);
            if (matches(currentAccount, account.uuid())) {
                currentAccount = account;
            }
            scheduleSave();
        }
    }

    /**
     * Discards the refresh token and expiry for the account with {@code uuid} and persists. Called when
     * the authentication service permanently rejects the token, so a spent credential is not retried or
     * left at rest. A no-op if the UUID is unknown.
     *
     * @param uuid the dashed UUID of the account whose refresh token is spent
     * @since 0.6.0
     */
    public static void clearRefreshToken(String uuid) {
        synchronized (LOCK) {
            replace(uuid, a -> a.withTokens(a.accessToken(), null, 0L));
            AltAccount current = currentAccount;
            if (matches(current, uuid)) {
                currentAccount = current.withTokens(current.accessToken(), null, 0L);
            }
            scheduleSave();
        }
    }

    /**
     * Adds an account to storage, then saves. When an entry with the same UUID is already stored the
     * incoming credentials are <em>merged onto</em> it (see {@link AltAccount#mergedOnto}) rather than
     * replacing it, so re-authenticating an alt the user already saved refreshes its tokens without
     * discarding the observed bans, provenance, and shared attribution the store had accumulated.
     *
     * <p>The merge happens in place and in one step: the entry keeps its position in
     * {@link #accounts()}, a reader never sees the account missing, and two logins adding the same
     * account at once leave one entry rather than two.
     *
     * @param account the account to add or update
     */
    public static void addAccount(AltAccount account) {
        Objects.requireNonNull(account.uuid(), "uuid");
        synchronized (LOCK) {
            if (!replace(account.uuid(), account::mergedOnto)) {
                ACCOUNTS.add(account);
            }
            scheduleSave();
        }
    }

    /**
     * Removes the stored account with the same UUID and saves. Keyed on the UUID like every other
     * mutator here, so a caller holding a stale copy — one read before a renewal rotated its tokens —
     * still removes the right entry.
     *
     * @param account the account to remove
     */
    public static void removeAccount(AltAccount account) {
        synchronized (LOCK) {
            ACCOUNTS.removeIf(a -> matches(a, account.uuid()));
            if (matches(currentAccount, account.uuid())) {
                currentAccount = null;
            }
            scheduleSave();
        }
    }

    /**
     * Encrypts the current accounts and writes them to disk before returning, whatever
     * {@link #writeDelay(Duration)} is set to. The mutators here persist on their own; this is for a
     * host that edited {@link #accounts()} directly.
     *
     * <p>The file is replaced in one step, so it is always either the previous state or this one. A
     * failure is reported on {@link #saveError()} rather than thrown.
     *
     * <p>Does not overwrite a file the last {@link #load()} could not read unless that file was first
     * copied aside — see {@link #loadError()}. Persisting there would write an empty store over accounts
     * that are merely unreadable, which is worse than not persisting at all.
     */
    public static void save() {
        synchronized (LOCK) {
            scheduleSave();
        }
        FILE.flush();
    }

    /**
     * Writes any state still waiting on {@link #writeDelay(Duration)} and returns once it is on disk. A
     * no-op when nothing is waiting. Worth calling before a host exits by a route that skips shutdown
     * hooks; a normal exit flushes on its own.
     *
     * @since 0.12.0
     */
    public static void flush() {
        FILE.flush();
    }

    /**
     * Loads and decrypts accounts from disk into memory, clearing existing entries first. A file that
     * exists but cannot be read leaves the in-memory list alone and records the reason on
     * {@link #loadError()}. Entries that cannot be used are skipped and noted on {@link #loadWarning()}.
     */
    public static void load() {
        synchronized (LOCK) {
            int[] skipped = {0};
            StoreFile.LoadOutcome outcome = FILE.load(json -> {
                JsonElement root = normalizeLegacyBans(JsonParser.parseString(json));
                StorageData loaded = GSON.fromJson(root, StorageData.class);
                if (loaded == null) {
                    return;
                }
                List<AltAccount> valid = usable(loaded.accounts(), skipped);
                ACCOUNTS.clear();
                ACCOUNTS.addAll(valid);
            });
            if (skipped[0] > 0 && outcome != StoreFile.LoadOutcome.FAILED) {
                loadWarning = FILE.fileName() + ": skipped " + skipped[0] + " invalid or duplicate "
                        + (skipped[0] == 1 ? "entry" : "entries");
            } else {
                loadWarning = null;
            }
            if (outcome == StoreFile.LoadOutcome.MIGRATED) {
                scheduleSave();
            }
        }
    }

    /**
     * Filters what a file held down to the entries the store can address. Every lookup here keys on the
     * UUID, so an entry without one would make each of them throw; a repeated UUID keeps its first
     * position and its last value, the later entry being the more recently written.
     *
     * @param loaded the entries as deserialized, or null
     * @param skipped a one-element counter of the entries left out
     * @return the usable entries, in file order
     */
    private static List<AltAccount> usable(List<AltAccount> loaded, int[] skipped) {
        Map<String, AltAccount> byUuid = new LinkedHashMap<>();
        if (loaded != null) {
            for (AltAccount account : loaded) {
                if (account == null || account.uuid() == null || account.uuid().isBlank()) {
                    skipped[0]++;
                } else if (byUuid.put(account.uuid(), account) != null) {
                    skipped[0]++;
                }
            }
        }
        return new ArrayList<>(byUuid.values());
    }

    /**
     * Applies {@code change} to every stored entry with the given UUID, in one step as far as a reader
     * of {@link #accounts()} is concerned.
     *
     * @param uuid the dashed UUID to match
     * @param change produces the replacement for a matching entry
     * @return true when an entry matched
     */
    private static boolean replace(String uuid, UnaryOperator<AltAccount> change) {
        boolean[] found = {false};
        ACCOUNTS.replaceAll(a -> {
            if (!matches(a, uuid)) {
                return a;
            }
            found[0] = true;
            return change.apply(a);
        });
        return found[0];
    }

    /**
     * Returns whether {@code account} is the one with the given UUID, tolerating the nulls a host can
     * put in the live list.
     *
     * @param account the account to test, or null
     * @param uuid the dashed UUID to match, or null
     * @return true when the account carries that UUID
     */
    private static boolean matches(AltAccount account, String uuid) {
        return account != null && uuid != null && uuid.equals(account.uuid());
    }

    /**
     * Hands a snapshot of the accounts to the file. Must be called with {@link #LOCK} held, so snapshots
     * reach the file in the order the mutations happened.
     */
    private static void scheduleSave() {
        List<AltAccount> snapshot = new ArrayList<>(ACCOUNTS);
        FILE.submit(() -> GSON.toJson(new StorageData(snapshot)));
    }

    /**
     * Migrates legacy stored accounts in place: an account carrying a single {@code "ban"} object (and
     * no {@code "bans"} map) is rewritten to {@code "bans": { "unknown": <ban> }}, since bans are now
     * per-server. Returns the same element. Package-private for unit testing.
     *
     * @param root the parsed storage root
     * @return the (possibly mutated) root
     */
    static JsonElement normalizeLegacyBans(JsonElement root) {
        if (root == null || !root.isJsonObject()) {
            return root;
        }
        JsonElement accountsEl = root.getAsJsonObject().get("accounts");
        if (accountsEl == null || !accountsEl.isJsonArray()) {
            return root;
        }
        for (JsonElement element : accountsEl.getAsJsonArray()) {
            if (!element.isJsonObject()) {
                continue;
            }
            JsonObject account = element.getAsJsonObject();
            if (account.has("ban") && !account.get("ban").isJsonNull() && !account.has("bans")) {
                JsonObject bans = new JsonObject();
                bans.add("unknown", account.get("ban"));
                account.add("bans", bans);
                account.remove("ban");
            }
        }
        return root;
    }

    /**
     * Internal serialization wrapper for the stored accounts.
     *
     * @param accounts the stored accounts
     */
    private record StorageData(@SerializedName("accounts") List<AltAccount> accounts) {}
}

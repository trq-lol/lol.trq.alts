package lol.trq.alts.store;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.annotations.SerializedName;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.UnaryOperator;
import lol.trq.alts.AltsFailure;
import lol.trq.alts.internal.store.StoreFile;
import lol.trq.alts.model.AltAccount;
import lol.trq.alts.model.BanInfo;
import lol.trq.alts.spi.StoreKeyProvider;

/**
 * One runtime's saved Minecraft accounts, persisted encrypted in one file on local disk. A host reaches
 * it through {@code AltsRuntime#store()}; every runtime has its own, so two runtimes in one process never
 * see each other's accounts.
 *
 * <p>The default key is derived from values that are not secret (the OS user, OS name and home
 * directory), so it deters casual copying and nothing more; a host that needs real protection supplies
 * its own key through a {@link StoreKeyProvider}.
 *
 * <p>This store holds <em>accounts</em> only. Accounts may be shared into a multi-member repository, so a
 * user's own secrets (API keys and the like) live separately in {@link HostSecrets} and never travel with
 * the accounts.
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
 * <p>The store holds an exclusive lock on a sidecar {@code <file>.lock} in its directory for the life of
 * the runtime that owns it, so a second runtime on the same file, in this process or another, is refused
 * when it builds rather than discovered later as a corrupt file. Once the runtime is closed the mutators
 * still change the list in memory but write nothing: each records "the store is closed" on
 * {@link #saveError()} instead.
 *
 * @author trq
 * @since 1.0.0
 */
public final class AccountStore {

    /** The neutral default filename. */
    static final String DEFAULT_FILE_NAME = "accounts.dat";

    /** The neutral default key-binding constant. */
    static final String DEFAULT_KEY_BINDING = "lol.trq.alts";

    /** Gson keyed purely on {@link SerializedName}, the house serialization convention. */
    private static final Gson GSON = new GsonBuilder().create();

    /** The encrypted file, owned and locked by this store. */
    private final StoreFile file;

    /** The file behind this store, for tests in this package and {@code StoreTestHooks}. */
    StoreFile fileForTests() {
        return file;
    }

    /** Guards every compound mutation, and the hand-off of its snapshot to {@link #file}. */
    private final Object lock = new Object();

    // Copy-on-write because logins resolve on the library executor while the host reads accounts() from its
    // render thread; a plain ArrayList lets one thread's write blow up the other's iteration.
    private final List<AltAccount> accounts = new CopyOnWriteArrayList<>();

    private volatile AltAccount currentAccount;
    private volatile AltsFailure loadWarning;

    static {
        // The runtime, in another package, opens and closes stores through this bridge only, so neither
        // the factories nor close() have to be public.
        StoreBridge.install();
    }

    private AccountStore(StoreFile file) {
        this.file = file;
    }

    /**
     * Opens the account store in {@code directory} with the neutral defaults: the default filename and
     * key binding, the machine-derived key, and synchronous writes, so a file is on disk the moment a
     * mutator returns. Nothing is read until {@link #load()}. For tests; a host gets its store from the
     * runtime.
     *
     * @param directory the directory the store file lives in; created when missing
     * @return the open store, which the caller closes
     * @throws lol.trq.alts.AltsException of kind {@code CONFLICT} when the store file is in use by another owner,
     *     or {@code STORAGE} when it cannot be locked;
     *     the message names the file, never its path
     */
    static AccountStore open(Path directory) {
        return open(directory, null, null, null, false, Duration.ZERO);
    }

    /**
     * Opens the account store in {@code directory} and takes the exclusive lock on its sidecar lock file.
     * Nothing is read until {@link #load()}.
     *
     * <p>{@code migrateFromMachineKey} is the explicit, one-time opt-in for a host adopting a key provider
     * over a store written before it had one. While it is on, a file that does not open under the host's
     * key is tried under the machine-derived key and, when that works, loaded and rewritten under the
     * host's key, together with every kept copy of it — the rolling backup included — so no file is left
     * that opens under the machine key. Pass true for the upgrade launch only. Left on, it lets anyone who
     * can write the directory, without knowing the host's secret, plant a store sealed under the guessable
     * machine key and have it load. While it is off a file that does not open under the host's key is
     * reported on {@link #loadError()} and left as it is.
     *
     * @param directory the directory the store file lives in; created when missing
     * @param fileName the on-disk filename, or null/blank for the default; a host with an existing file
     *     passes its name so the file keeps loading
     * @param keyBinding the constant mixed into the encryption key, or null/blank for the default; changing
     *     it for an existing store renders the file undecryptable
     * @param keyProvider the host key provider, or null for the machine-derived key
     * @param migrateFromMachineKey whether to accept and reseal a file from before the key provider; has no
     *     effect without one
     * @param writeDelay how long mutations are gathered for before one write covers them; null, zero, or
     *     negative writes synchronously inside the mutator
     * @return the open store, which the caller closes
     * @throws lol.trq.alts.AltsException of kind {@code CONFLICT} when the store file is in use by another owner,
     *     or {@code STORAGE} when it cannot be locked;
     *     the message names the file, never its path
     */
    static AccountStore open(
            Path directory,
            String fileName,
            String keyBinding,
            StoreKeyProvider keyProvider,
            boolean migrateFromMachineKey,
            Duration writeDelay) {
        return new AccountStore(StoreFile.open(
                directory,
                orDefault(fileName, DEFAULT_FILE_NAME),
                orDefault(keyBinding, DEFAULT_KEY_BINDING),
                keyProvider,
                migrateFromMachineKey,
                writeDelay));
    }

    static String orDefault(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
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
     * @since 1.0.0
     */
    public void markBanned(String uuid, String serverId, BanInfo ban) {
        synchronized (lock) {
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
     * @since 1.0.0
     */
    public List<AltAccount> accounts() {
        return accounts;
    }

    /**
     * Returns why the last {@link #load()} could not read an existing store file, if it could not.
     *
     * <p>A store that fails to decrypt is not an empty store, and the two must not be confused: the
     * default key is derived from machine properties, so a renamed OS user or a moved home directory turns
     * a perfectly good file into an unreadable one. While this is set, a host should tell the user their
     * accounts did not load instead of showing an empty list.
     *
     * <p>While this is set nothing is written: every mutation, {@link #save()} and {@link #flush()} is
     * refused and reported on {@link #saveError()}, so the file on disk stays exactly as it was. Accounts
     * added in the meantime live in memory only. Writes resume after one of three things:
     *
     * <ul>
     *   <li>a later {@link #load()} succeeds, for example once a locked keychain behind a
     *       {@link StoreKeyProvider} answers again; what was added in memory is replaced by what it read;
     *   <li>the file is gone, so there is nothing left to protect;
     *   <li>the host calls {@link #discardUnreadable()}, the route when the file will never open again: a
     *       renamed OS user or a moved home directory under the machine-derived key, or a rotated host
     *       key. The next write then starts a new store from what memory holds.
     * </ul>
     *
     * <p>A file that failed to decrypt, held contents that are not a store, or could not be read is
     * copied aside as {@code <name>.unreadable.<time>} when the load fails, one copy per distinct file,
     * newest five kept. A file that failed only because the key was unavailable is intact and is not
     * copied until it is discarded. A successful write after a discard clears this, since the file on
     * disk is then the one just written.
     *
     * <p>Its message is the file's name and a fixed phrase. It never carries a filesystem path, so it
     * is safe to show and to log.
     *
     * @return the failure, of kind {@link AltsFailure.Kind#STORAGE}, or empty when the last load succeeded or found no file, or the
     *     store has been written successfully since
     * @since 1.0.0
     */
    public Optional<AltsFailure> loadError() {
        return Optional.ofNullable(file.loadError());
    }

    /**
     * Returns a note about entries the last successful {@link #load()} had to leave out. A stored entry
     * with no UUID cannot be addressed by anything here, and a second entry for a UUID already read is a
     * duplicate; both are skipped so that one bad record does not cost the rest. Unlike
     * {@link #loadError()} this does not mean the store failed to load — every valid account is in
     * {@link #accounts()}.
     *
     * @return the note, as a failure of kind {@link AltsFailure.Kind#STORAGE}, or empty when the last
     *     load skipped nothing
     * @since 1.0.0
     */
    public Optional<AltsFailure> loadWarning() {
        return Optional.ofNullable(loadWarning);
    }

    /**
     * Returns why the most recent write did not reach the disk, if it did not. While this is set the
     * file is whatever the last successful write left — never a partial one — and the accounts in
     * memory are ahead of it; the write is retried by the next mutation, {@link #save()}, or
     * {@link #flush()}, and a success clears this. Like {@link #loadError()}, the message carries no
     * filesystem path.
     *
     * <p>Two failures are not retried by writing: while the last {@link #load()} failed on a file that
     * exists, writes are refused on purpose until a {@code load()} succeeds or the host calls
     * {@link #discardUnreadable()} (see {@link #loadError()}); and once the runtime is closed nothing is
     * written at all.
     *
     * @return the failure, of kind {@link AltsFailure.Kind#STORAGE}, or empty when the last write succeeded
     * @since 1.0.0
     */
    public Optional<AltsFailure> saveError() {
        return Optional.ofNullable(file.saveError());
    }

    /**
     * Returns the currently active account, if any.
     *
     * @return an optional holding the active account, or empty if none is set
     * @since 1.0.0
     */
    public Optional<AltAccount> currentAccount() {
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
     * @since 1.0.0
     */
    public void useAccount(AltAccount account) {
        synchronized (lock) {
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
     * @since 1.0.0
     */
    public void updateCredentials(AltAccount account) {
        synchronized (lock) {
            replace(account.uuid(), a -> account);
            if (matches(currentAccount, account.uuid())) {
                currentAccount = account;
            }
            scheduleSave();
        }
    }

    /**
     * Applies {@code change} to the stored entry for {@code uuid}, under the store lock, and persists;
     * the current account is changed the same way when it is the same one. The way a check or a renewal
     * writes back what it learned: the change receives the record as the store holds it now and alters
     * only what that operation found out, so a ban marked, or a token rotated, since the caller read its
     * copy is kept. Reached from the sign-in chain through {@code StoreAccess}; not API.
     *
     * <p>Does nothing to the stored list when the store holds no entry for {@code uuid}: an account the
     * store does not hold is never persisted (see {@link #updateCredentials}).
     *
     * @param uuid the dashed UUID of the account
     * @param change derives the new record from the one held now
     * @return the stored entry after the change, or empty when the store holds none for {@code uuid}
     */
    Optional<AltAccount> update(String uuid, UnaryOperator<AltAccount> change) {
        Objects.requireNonNull(change, "change");
        synchronized (lock) {
            AltAccount[] changed = {null};
            boolean stored = replace(uuid, held -> changed[0] = change.apply(held));
            AltAccount current = currentAccount;
            if (matches(current, uuid)) {
                currentAccount = change.apply(current);
            }
            if (!stored) {
                return Optional.empty();
            }
            scheduleSave();
            return Optional.of(changed[0]);
        }
    }

    /**
     * Discards the refresh token and expiry for the account with {@code uuid} and persists. Called when
     * the authentication service permanently rejects the token, so a spent credential is not retried or
     * left at rest. A no-op if the UUID is unknown.
     *
     * @param uuid the dashed UUID of the account whose refresh token is spent
     * @since 1.0.0
     */
    public void clearRefreshToken(String uuid) {
        synchronized (lock) {
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
     * @since 1.0.0
     */
    public void addAccount(AltAccount account) {
        Objects.requireNonNull(account.uuid(), "uuid");
        synchronized (lock) {
            if (!replace(account.uuid(), account::mergedOnto)) {
                accounts.add(account);
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
     * @since 1.0.0
     */
    public void removeAccount(AltAccount account) {
        synchronized (lock) {
            accounts.removeIf(a -> matches(a, account.uuid()));
            if (matches(currentAccount, account.uuid())) {
                currentAccount = null;
            }
            scheduleSave();
        }
    }

    /**
     * Encrypts the current accounts and writes them to disk before returning, whatever write delay the
     * store was opened with. The mutators here persist on their own; this is for a host that edited
     * {@link #accounts()} directly.
     *
     * <p>The file is replaced in one step, so it is always either the previous state or this one. A
     * failure is reported on {@link #saveError()} rather than thrown.
     *
     * <p>Does not write at all while the last {@link #load()} failed on a file that exists — see
     * {@link #loadError()}. Persisting there would write an empty store over accounts that are merely
     * unreadable, which is worse than not persisting at all.
     *
     * @since 1.0.0
     */
    public void save() {
        synchronized (lock) {
            scheduleSave();
        }
        file.flush();
    }

    /**
     * Gives up on a store file the last {@link #load()} could not read, so the store can be written
     * again. This is the route when the file will never open: under the machine-derived key, after the
     * OS user was renamed or the home directory moved; under a {@link StoreKeyProvider}, after the host
     * key was rotated or lost. Only the host can know that, so nothing here does it on its own.
     *
     * <p>The file is first copied aside as {@code <name>.unreadable.<time>} (a copy of the same bytes
     * that already exists is not made twice), the refusal is lifted, and what memory holds is written as
     * a new store at once. A no-op when writes are not refused.
     *
     * @return true when writes were refused and are allowed again; false when there was nothing to
     *     discard, the runtime is closed, or the file could not be copied aside, which
     *     {@link #saveError()} then reports and which leaves the refusal in place
     * @since 1.0.0
     */
    public boolean discardUnreadable() {
        synchronized (lock) {
            return file.discardUnreadable();
        }
    }

    /**
     * Writes any state still waiting on the write delay and returns once it is on disk. A no-op when
     * nothing is waiting. Worth calling before a host exits by a route that skips shutdown hooks; a normal
     * exit flushes on its own, and closing the runtime flushes too.
     *
     * @since 1.0.0
     */
    public void flush() {
        file.flush();
    }

    /**
     * Loads and decrypts accounts from disk into memory, clearing existing entries first. A file that
     * exists but cannot be read leaves the in-memory list alone and records the reason on
     * {@link #loadError()}. Entries that cannot be used are skipped and noted on {@link #loadWarning()}.
     * Once the runtime is closed nothing is read, and {@link #loadError()} says so.
     *
     * @since 1.0.0
     */
    public void load() {
        synchronized (lock) {
            int[] skipped = {0};
            StoreFile.LoadOutcome outcome = file.load(json -> {
                JsonElement root = normalizeLegacyBans(JsonParser.parseString(json));
                StorageData loaded = GSON.fromJson(root, StorageData.class);
                if (loaded == null) {
                    return;
                }
                List<AltAccount> valid = usable(loaded.accounts(), skipped);
                accounts.clear();
                accounts.addAll(valid);
            });
            if (skipped[0] > 0 && outcome != StoreFile.LoadOutcome.FAILED) {
                loadWarning = AltsFailure.of(
                        AltsFailure.Kind.STORAGE,
                        file.fileName() + ": skipped " + skipped[0] + " invalid or duplicate "
                                + (skipped[0] == 1 ? "entry" : "entries"));
            } else {
                loadWarning = null;
            }
            if (outcome == StoreFile.LoadOutcome.MIGRATED) {
                scheduleSave();
            }
        }
    }

    /**
     * Writes what is still waiting, releases the store's lock and stops its background writer. Reached
     * from {@code AltsRuntime#close()} only, so a store is never closed under a runtime that is still
     * open. Idempotent.
     *
     * <p>After this the store writes nothing. The list stays readable, and the mutators still change it
     * in memory, but each records "the store is closed" on {@link #saveError()} instead of writing, as
     * does {@link #save()}; {@link #flush()} does nothing, and {@link #load()} reads nothing. Another owner
     * may open the file as soon as this returns.
     */
    void close() {
        synchronized (lock) {
            file.close();
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
    private boolean replace(String uuid, UnaryOperator<AltAccount> change) {
        boolean[] found = {false};
        accounts.replaceAll(a -> {
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
     * Hands a snapshot of the accounts to the file. Must be called with {@link #lock} held, so snapshots
     * reach the file in the order the mutations happened.
     */
    private void scheduleSave() {
        List<AltAccount> snapshot = new ArrayList<>(accounts);
        file.submit(() -> GSON.toJson(new StorageData(snapshot)));
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

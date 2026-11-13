package lol.trq.alts.store;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.annotations.SerializedName;
import java.nio.file.Path;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import lol.trq.alts.spi.StoreKeyProvider;

/**
 * One runtime's per-user encrypted key/value secrets on local disk, separate from the account store.
 * Holds host secrets (API keys, referral codes, integration tokens) that belong to the individual user
 * and must never travel into a shared account repository. A host reaches it through
 * {@code AltsRuntime#secrets()}; every runtime has its own.
 *
 * <p>Secrets are encrypted with a machine-derived key unless the host supplies its own through a
 * {@link StoreKeyProvider}. That default is built from values that are not secret, so it deters casual
 * copying and nothing more. Hosts namespace their own keys (for example {@code "myfeature.api-key"}); the
 * library imposes no schema.
 *
 * <p>This store is deliberately split from {@link AccountStore}: accounts may be shared into a
 * multi-member repository, but secrets stay local to one user.
 *
 * <p>Persistence follows the account store's rules: a write replaces the file in one step, writes are
 * serialized, a failure is reported on {@link #saveError()} rather than thrown, and a file that exists but
 * could not be read is never written over: nothing is written until a load succeeds or the host calls
 * {@link #discardUnreadable()}. The store holds an exclusive lock on a sidecar {@code <file>.lock} for the life of the
 * runtime that owns it; once the runtime is closed the mutators change memory only and record "the store
 * is closed" on {@link #saveError()}.
 *
 * @author trq
 * @since 1.0.0
 */
public final class HostSecrets {

    /** The neutral default filename. */
    static final String DEFAULT_FILE_NAME = "secrets.dat";

    /** The neutral default key-binding constant. */
    static final String DEFAULT_KEY_BINDING = "lol.trq.alts.secrets";

    /** Gson keyed purely on {@link SerializedName}, the house serialization convention. */
    private static final Gson GSON = new GsonBuilder().create();

    /** The encrypted file, owned and locked by this store. */
    private final StoreFile file;

    /** Guards each mutation together with the hand-off of its snapshot to {@link #file}. */
    private final Object lock = new Object();

    // Concurrent because a host reads secrets from its render thread while background work writes them.
    /** Arbitrary host key/value secrets, persisted as a single encrypted file. */
    private final Map<String, String> secrets = new ConcurrentHashMap<>();

    static {
        StoreBridge.install();
    }

    private HostSecrets(StoreFile file) {
        this.file = file;
    }

    /**
     * Opens the secret store in {@code directory} with the neutral defaults: the default filename and key
     * binding, the machine-derived key, and synchronous writes. Nothing is read until {@link #load()}. For
     * tests; a host gets its secrets from the runtime.
     *
     * @param directory the directory the store file lives in; created when missing
     * @return the open store, which the caller closes
     * @throws IllegalStateException when the store file is in use by another owner or cannot be locked;
     *     the message names the file, never its path
     */
    static HostSecrets open(Path directory) {
        return open(directory, null, null, null, false, Duration.ZERO);
    }

    /**
     * Opens the secret store in {@code directory} and takes the exclusive lock on its sidecar lock file.
     * Nothing is read until {@link #load()}. The parameters mean what they mean for
     * {@link AccountStore#open(Path, String, String, StoreKeyProvider, boolean, Duration)}, including the
     * one-launch-only rule for {@code migrateFromMachineKey}.
     *
     * @param directory the directory the store file lives in; created when missing
     * @param fileName the on-disk filename, or null/blank for the default
     * @param keyBinding the constant mixed into the encryption key, or null/blank for the default
     * @param keyProvider the host key provider, or null for the machine-derived key
     * @param migrateFromMachineKey whether to accept and reseal a file from before the key provider
     * @param writeDelay the coalescing window; null, zero, or negative writes synchronously
     * @return the open store, which the caller closes
     * @throws IllegalStateException when the store file is in use by another owner or cannot be locked;
     *     the message names the file, never its path
     */
    static HostSecrets open(
            Path directory,
            String fileName,
            String keyBinding,
            StoreKeyProvider keyProvider,
            boolean migrateFromMachineKey,
            Duration writeDelay) {
        return new HostSecrets(StoreFile.open(
                directory,
                AccountStore.orDefault(fileName, DEFAULT_FILE_NAME),
                AccountStore.orDefault(keyBinding, DEFAULT_KEY_BINDING),
                keyProvider,
                migrateFromMachineKey,
                writeDelay));
    }

    /**
     * Returns the stored secret for {@code key}, or {@code null} if absent.
     *
     * @param key the secret key
     * @return the stored value, or null if absent
     * @since 1.0.0
     */
    public String get(String key) {
        return secrets.get(key);
    }

    /**
     * Stores a secret and persists. A null or blank value removes the key instead.
     *
     * @param key the secret key
     * @param value the value to store, or null/blank to remove the key
     * @since 1.0.0
     */
    public void put(String key, String value) {
        synchronized (lock) {
            if (value == null || value.isBlank()) {
                secrets.remove(key);
            } else {
                secrets.put(key, value);
            }
            scheduleSave();
        }
    }

    /**
     * Returns whether a non-blank secret is stored for {@code key}.
     *
     * @param key the secret key
     * @return true if a non-blank value is stored
     * @since 1.0.0
     */
    public boolean has(String key) {
        String value = secrets.get(key);
        return value != null && !value.isBlank();
    }

    /**
     * Removes a secret and persists.
     *
     * @param key the secret key to clear
     * @since 1.0.0
     */
    public void clear(String key) {
        synchronized (lock) {
            if (secrets.remove(key) != null) {
                scheduleSave();
            }
        }
    }

    /**
     * Returns why the last {@link #load()} could not read an existing secret file, if it could not. As
     * with the account store, an unreadable file is not an empty one: it is copied aside when the load
     * fails (unless it failed only for want of the key), and nothing is written over it until a later
     * load succeeds or the host calls {@link #discardUnreadable()} — see
     * {@link AccountStore#loadError()}. The description carries no filesystem path.
     *
     * @return the failure description, or empty when the last load succeeded or found no file, or the
     *     store has been written successfully since
     * @since 1.0.0
     */
    public Optional<String> loadError() {
        return Optional.ofNullable(file.loadError());
    }

    /**
     * Returns why the most recent write did not reach the disk, if it did not. The write is retried by
     * the next mutation, {@link #save()}, or {@link #flush()}, and a success clears this; a write refused
     * because the last load failed, or because the store is closed, is not retried. The description
     * carries no filesystem path.
     *
     * @return the failure description, or empty when the last write succeeded
     * @since 1.0.0
     */
    public Optional<String> saveError() {
        return Optional.ofNullable(file.saveError());
    }

    /**
     * Encrypts the current secrets and writes them to disk before returning, replacing the file in one
     * step. A failure is reported on {@link #saveError()}. Does not write at all while the last
     * {@link #load()} failed on a file that exists — see {@link #loadError()}.
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
     * Gives up on a secret file the last {@link #load()} could not read, so the secrets can be written
     * again; the route when the file will never open (a renamed OS user or moved home under the
     * machine-derived key, a rotated host key). The file is copied aside first, and the next write starts
     * a new file from what memory holds. See {@link AccountStore#discardUnreadable()}.
     *
     * @return true when writes were refused and are allowed again; false when there was nothing to
     *     discard, the runtime is closed, or the file could not be copied aside
     * @since 1.0.0
     */
    public boolean discardUnreadable() {
        synchronized (lock) {
            return file.discardUnreadable();
        }
    }

    /**
     * Writes any state still waiting on the write delay and returns once it is on disk. A no-op when
     * nothing is waiting.
     *
     * @since 1.0.0
     */
    public void flush() {
        file.flush();
    }

    /**
     * Loads and decrypts secrets from disk into memory, clearing existing entries first. A file that
     * exists but cannot be read leaves the in-memory map alone and records the reason on
     * {@link #loadError()}. Once the runtime is closed nothing is read, and {@link #loadError()} says so.
     *
     * @since 1.0.0
     */
    public void load() {
        synchronized (lock) {
            StoreFile.LoadOutcome outcome = file.load(json -> {
                SecretData loaded = GSON.fromJson(json, SecretData.class);
                if (loaded == null) {
                    return;
                }
                secrets.clear();
                if (loaded.secrets() != null) {
                    // A null key or value cannot live in the map, and one of them must not cost the rest.
                    loaded.secrets().forEach((key, value) -> {
                        if (key != null && value != null) {
                            secrets.put(key, value);
                        }
                    });
                }
            });
            if (outcome == StoreFile.LoadOutcome.MIGRATED) {
                scheduleSave();
            }
        }
    }

    /**
     * Writes what is still waiting, releases the store's lock and stops its background writer. Reached
     * from {@code AltsRuntime#close()} only. Idempotent. Afterwards the secrets stay readable, a mutator
     * changes memory only and records "the store is closed" on {@link #saveError()}, {@link #flush()} does
     * nothing, and {@link #load()} reads nothing.
     */
    void close() {
        synchronized (lock) {
            file.close();
        }
    }

    /**
     * Hands a snapshot of the secrets to the file. Must be called with {@link #lock} held, so snapshots
     * reach the file in the order the mutations happened.
     */
    private void scheduleSave() {
        Map<String, String> snapshot = new LinkedHashMap<>(secrets);
        file.submit(() -> GSON.toJson(new SecretData(snapshot)));
    }

    /**
     * Internal serialization wrapper for the encrypted secret map.
     *
     * @param secrets the host key/value secrets, or null
     */
    private record SecretData(@SerializedName("secrets") Map<String, String> secrets) {

        // Every value is a secret the host asked to have kept; only the count is safe to print.
        @Override
        public String toString() {
            return "SecretData[" + (secrets == null ? 0 : secrets.size()) + " secrets]";
        }
    }
}

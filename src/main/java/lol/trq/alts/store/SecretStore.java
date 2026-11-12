package lol.trq.alts.store;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.annotations.SerializedName;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import lol.trq.alts.spi.StoreKeyProvider;
import lol.trq.alts.spi.VaultDirectoryProvider;

/**
 * Per-user encrypted key/value secret storage on local disk, separate from the account store. Holds
 * host secrets (API keys, referral codes, integration tokens) that belong to the individual user and
 * must never travel into a shared account repository.
 *
 * <p>Secrets are encrypted with a hardware-bound key from {@link EncryptionUtil#getHardwareKey(String)}
 * so the file cannot be transferred between systems. The directory is supplied by the host through a
 * {@link VaultDirectoryProvider} bound at runtime startup; the store keeps no Minecraft or platform
 * types. Hosts namespace their own keys (for example {@code "myfeature.api-key"}); the library imposes
 * no schema.
 *
 * <p>This store is deliberately split from the account store: accounts may be shared into a
 * multi-member repository, but secrets stay local to one user.
 *
 * <p>Persistence follows the account store's rules: a write replaces the file in one step, writes are
 * serialized, and a failure is reported on {@link #saveError()} rather than thrown.
 *
 * @author trq
 * @since 0.2.0
 */
public final class SecretStore {

    /** Gson keyed purely on {@link SerializedName}, the house serialization convention. */
    private static final Gson GSON = new GsonBuilder().create();

    /** The encrypted file, with the neutral default name and key binding a host may override. */
    private static final StoreFile FILE = new StoreFile("secrets.dat", "lol.trq.alts.secrets");

    /** Guards each mutation together with the hand-off of its snapshot to {@link #FILE}. */
    private static final Object LOCK = new Object();

    // Concurrent because a host reads secrets from its render thread while background work writes them.
    /** Arbitrary host key/value secrets, persisted as a single encrypted file. */
    private static final Map<String, String> SECRETS = new ConcurrentHashMap<>();

    private SecretStore() {}

    /**
     * Binds the host directory provider. Called once by {@code AltsRuntime.Builder#build()} before any
     * load or save. As with {@link AltStore#bind}, binding starts from synchronous writes and the
     * machine-derived key.
     *
     * @param provider the host-supplied vault directory provider
     */
    public static void bind(VaultDirectoryProvider provider) {
        FILE.bind(provider);
    }

    /**
     * Overrides the store filename and key-binding constant. Null or blank arguments leave the current
     * value unchanged.
     *
     * @param storeFileName the on-disk filename, or null/blank to keep the default
     * @param storeKeyBinding the key-binding constant, or null/blank to keep the default
     */
    public static void configure(String storeFileName, String storeKeyBinding) {
        FILE.configure(storeFileName, storeKeyBinding);
    }

    /**
     * Installs a host key provider, so the file is sealed under the host's secret instead of the
     * machine-derived default. See {@link AltStore#keyProvider(StoreKeyProvider)}.
     *
     * @param provider the host key provider, or null for the machine-derived default
     * @since 0.12.0
     */
    public static void keyProvider(StoreKeyProvider provider) {
        FILE.keyProvider(provider);
    }

    /**
     * Sets how long mutations are gathered for before one write covers them all. See
     * {@link AltStore#writeDelay(Duration)}.
     *
     * @param delay the coalescing window; null, zero, or negative writes synchronously inside the mutator
     * @since 0.12.0
     */
    public static void writeDelay(Duration delay) {
        FILE.writeDelay(delay);
    }

    /**
     * Returns the stored secret for {@code key}, or {@code null} if absent.
     *
     * @param key the secret key
     * @return the stored value, or null if absent
     */
    public static String get(String key) {
        return SECRETS.get(key);
    }

    /**
     * Stores a secret and persists. A null or blank value removes the key instead.
     *
     * @param key the secret key
     * @param value the value to store, or null/blank to remove the key
     */
    public static void put(String key, String value) {
        synchronized (LOCK) {
            if (value == null || value.isBlank()) {
                SECRETS.remove(key);
            } else {
                SECRETS.put(key, value);
            }
            scheduleSave();
        }
    }

    /**
     * Returns whether a non-blank secret is stored for {@code key}.
     *
     * @param key the secret key
     * @return true if a non-blank value is stored
     */
    public static boolean has(String key) {
        String value = SECRETS.get(key);
        return value != null && !value.isBlank();
    }

    /**
     * Removes a secret and persists.
     *
     * @param key the secret key to clear
     */
    public static void clear(String key) {
        synchronized (LOCK) {
            if (SECRETS.remove(key) != null) {
                scheduleSave();
            }
        }
    }

    /**
     * Returns why the last {@link #load()} could not read an existing secret file, if it could not. As
     * with the account store, an unreadable file is not an empty one: while this is set, {@link #save()}
     * preserves the file rather than overwriting it. The description carries no filesystem path.
     *
     * @return the failure description, or empty when the last load succeeded or found no file
     * @since 0.7.0
     */
    public static Optional<String> loadError() {
        return Optional.ofNullable(FILE.loadError());
    }

    /**
     * Returns why the most recent write did not reach the disk, if it did not. The write is retried by
     * the next mutation, {@link #save()}, or {@link #flush()}, and a success clears this. The
     * description carries no filesystem path.
     *
     * @return the failure description, or empty when the last write succeeded
     * @since 0.12.0
     */
    public static Optional<String> saveError() {
        return Optional.ofNullable(FILE.saveError());
    }

    /**
     * Encrypts the current secrets and writes them to disk before returning, replacing the file in one
     * step. A failure is reported on {@link #saveError()}. Does not overwrite a file the last
     * {@link #load()} could not read unless it was first copied aside — see {@link #loadError()}.
     */
    public static void save() {
        synchronized (LOCK) {
            scheduleSave();
        }
        FILE.flush();
    }

    /**
     * Writes any state still waiting on {@link #writeDelay(Duration)} and returns once it is on disk. A
     * no-op when nothing is waiting.
     *
     * @since 0.12.0
     */
    public static void flush() {
        FILE.flush();
    }

    /**
     * Loads and decrypts secrets from disk into memory, clearing existing entries first. A file that
     * exists but cannot be read leaves the in-memory map alone and records the reason on
     * {@link #loadError()}.
     */
    public static void load() {
        synchronized (LOCK) {
            StoreFile.LoadOutcome outcome = FILE.load(json -> {
                SecretData loaded = GSON.fromJson(json, SecretData.class);
                if (loaded == null) {
                    return;
                }
                SECRETS.clear();
                if (loaded.secrets() != null) {
                    // A null key or value cannot live in the map, and one of them must not cost the rest.
                    loaded.secrets().forEach((key, value) -> {
                        if (key != null && value != null) {
                            SECRETS.put(key, value);
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
     * Hands a snapshot of the secrets to the file. Must be called with {@link #LOCK} held, so snapshots
     * reach the file in the order the mutations happened.
     */
    private static void scheduleSave() {
        Map<String, String> snapshot = new LinkedHashMap<>(SECRETS);
        FILE.submit(() -> GSON.toJson(new SecretData(snapshot)));
    }

    /**
     * Internal serialization wrapper for the encrypted secret map.
     *
     * @param secrets the host key/value secrets, or null
     */
    private record SecretData(@SerializedName("secrets") Map<String, String> secrets) {}
}

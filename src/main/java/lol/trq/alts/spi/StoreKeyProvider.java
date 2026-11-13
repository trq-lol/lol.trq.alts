package lol.trq.alts.spi;

/**
 * Supplies the key material the encrypted stores are sealed under, in place of the default derived from
 * machine properties. A host that can reach a real secret — an operating-system keystore entry, a
 * hardware-backed key, a passphrase the user typed — installs one of these so the files at rest are
 * protected by that secret rather than by values any local process can read.
 *
 * <p>Entirely optional. Without a provider the stores behave exactly as they always have. With one, a
 * file opens under the host's key or not at all: a store that does not open under it is reported
 * unreadable and left untouched, whatever key did seal it.
 *
 * <p>Files written before the provider was installed are the one exception, and only when the host
 * asks: {@code AltsRuntime.Builder#migrateFromMachineKey(boolean)} lets a store that opens under the
 * machine-derived default load once and be rewritten under the host's key, along with every kept copy
 * of it, so that nothing sealed under the old key is left in the directory. Turn it on for the launch
 * that adopts the provider and off afterwards. It is off by default because the machine-derived key can
 * be reconstructed by anyone who can read the machine's properties: accepting it indefinitely would let
 * whoever can write the store directory plant a file, or put back a copy from before the migration, and
 * have it load as though the host had sealed it.
 *
 * <p>Resolution fails closed. A provider that throws, or returns {@code null} or fewer than
 * {@link #MIN_LENGTH} bytes, leaves the store unreadable and unwritable; the library never falls back to
 * the machine-derived key for a write, because that would silently store credentials under the weaker
 * key at the moment the host believed otherwise. A load that fails this way also holds every later
 * write back, even once the provider answers, until the store has been loaded successfully — the file
 * on disk is intact, and writing what is in memory would replace it. Call the store's {@code load()}
 * again when the secret becomes available, or its {@code discardUnreadable()} if it never will (the key
 * was rotated or lost), which copies the file aside and starts a new store.
 *
 * <p>The provider belongs to the runtime it is given to. Each of that runtime's stores asks it, and no
 * other runtime's store ever does. A later runtime built without it, on the same directory, cannot open
 * the files and does not write over them either: a file that did not open is never overwritten.
 *
 * @author trq
 * @since 0.12.0
 */
@FunctionalInterface
public interface StoreKeyProvider {

    /**
     * The fewest bytes of key material accepted.
     *
     * @since 0.12.0
     */
    int MIN_LENGTH = 16;

    /**
     * Returns the key material. It must be the same bytes on every call for as long as the stored files
     * are meant to stay readable; each store asks when it first needs the key and keeps the answer in
     * memory for as long as it is open. The material is stretched and bound to each store before use, so
     * one secret serves both stores.
     *
     * @return at least {@link #MIN_LENGTH} bytes of secret key material
     * @throws Exception if the material cannot be obtained; the store then reports itself unavailable
     * @since 0.12.0
     */
    byte[] keyMaterial() throws Exception;
}

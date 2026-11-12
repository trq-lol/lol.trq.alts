package lol.trq.alts.spi;

/**
 * Supplies the key material the encrypted stores are sealed under, in place of the default derived from
 * machine properties. A host that can reach a real secret — an operating-system keystore entry, a
 * hardware-backed key, a passphrase the user typed — installs one of these so the files at rest are
 * protected by that secret rather than by values any local process can read.
 *
 * <p>Entirely optional. Without a provider the stores behave exactly as they always have, and files
 * written before one was installed still load: a store that does not open under the host's key is
 * tried once under the machine-derived default and, when that works, rewritten under the host's key.
 * The reverse is deliberately not true — a file sealed under a host key does not open without it, and
 * is reported unreadable and left untouched instead.
 *
 * <p>Resolution fails closed. A provider that throws, or returns {@code null} or fewer than
 * {@link #MIN_LENGTH} bytes, leaves the store unreadable and unwritable until it answers; the library
 * never falls back to the machine-derived key for a write, because that would silently store
 * credentials under the weaker key at the moment the host believed otherwise.
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
     * are meant to stay readable; the library asks once per process and keeps the answer in memory. The
     * material is stretched and bound to each store before use, so one secret serves both stores.
     *
     * @return at least {@link #MIN_LENGTH} bytes of secret key material
     * @throws Exception if the material cannot be obtained; the store then reports itself unavailable
     * @since 0.12.0
     */
    byte[] keyMaterial() throws Exception;
}

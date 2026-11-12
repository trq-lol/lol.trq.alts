package lol.trq.alts.vault;

import com.google.gson.annotations.SerializedName;

/**
 * A host-persisted rollback floor for one shared repository: the highest key epoch and payload version
 * the host has already accepted for it. A manifest is served by the repository's server and nothing in
 * it is signed, so without a local memory of where the repository had got to, a server could hand back
 * an earlier manifest (an older key epoch, from before a member was removed) and nothing would notice.
 *
 * <p>The host keeps one pin per repository, alongside whatever else it remembers about that
 * repository, passes it to {@link SharedVault#openRepo(lol.trq.alts.vault.transport.VaultManifest,
 * lol.trq.alts.crypto.VaultIdentity, RepoPin)}, and stores {@link RepoContext#pin()} again whenever the
 * context advances. The record is plain data and safe to persist: it holds two counters and no key.
 *
 * @param minimumKeyEpoch the lowest key epoch to accept
 * @param minimumPayloadVersion the lowest payload version to accept
 * @author trq
 * @since 0.12.0
 */
public record RepoPin(
        @SerializedName("minimumKeyEpoch") long minimumKeyEpoch,
        @SerializedName("minimumPayloadVersion") long minimumPayloadVersion) {

    /** Validates that neither floor is negative. */
    public RepoPin {
        if (minimumKeyEpoch < 0) {
            throw new IllegalArgumentException("minimumKeyEpoch is negative");
        }
        if (minimumPayloadVersion < 0) {
            throw new IllegalArgumentException("minimumPayloadVersion is negative");
        }
    }

    /**
     * Returns the pin for a repository the host has never opened: it accepts any epoch and version.
     *
     * @return a pin with no floor
     */
    public static RepoPin none() {
        return new RepoPin(0L, 0L);
    }

    /**
     * Returns the stricter of this pin and {@code other}, so a stored pin never moves backwards.
     *
     * @param other the pin to merge with
     * @return a pin holding the higher epoch and the higher version of the two
     */
    public RepoPin advancedTo(RepoPin other) {
        return new RepoPin(
                Math.max(minimumKeyEpoch, other.minimumKeyEpoch),
                Math.max(minimumPayloadVersion, other.minimumPayloadVersion));
    }
}

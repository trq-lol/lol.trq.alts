package lol.trq.alts.vault;

import lol.trq.alts.crypto.RepoDataKey;

/**
 * The in-memory working state for an opened repository: the repo id, the member's unlocked identity,
 * the unwrapped data key for the current epoch, and the payload version the member last saw. Held only
 * in memory while a repository is open; never serialized (the data key would leak).
 *
 * @param repoId the repository id
 * @param identity the member's unlocked identity
 * @param dataKey the unwrapped data key for the current epoch
 * @param payloadVersion the payload version this context is synced to
 * @param shareRefreshTokens whether this repository's manifest permits sharing OAuth refresh tokens;
 *     mirrors {@link lol.trq.alts.vault.transport.VaultManifest#shareRefreshTokens()} so the policy is
 *     enforced locally on every read and write; added in 0.6.0
 * @author trq
 * @since 0.2.0
 */
public record RepoContext(
        String repoId, VaultIdentity identity, RepoDataKey dataKey, long payloadVersion, boolean shareRefreshTokens) {

    /**
     * Returns a copy advanced to a new payload version.
     *
     * @param version the new payload version
     * @return the updated context
     */
    public RepoContext withPayloadVersion(long version) {
        return new RepoContext(repoId, identity, dataKey, version, shareRefreshTokens);
    }

    /**
     * Returns the rollback floor this context establishes: the key epoch and payload version it has
     * reached. Persist it per repository and pass it to
     * {@link SharedVault#openRepo(lol.trq.alts.vault.transport.VaultManifest, VaultIdentity, RepoPin)}
     * next time, so a server cannot serve an older manifest unnoticed.
     *
     * @return the pin to persist
     * @since 0.12.0
     */
    public RepoPin pin() {
        return new RepoPin(dataKey.epoch(), payloadVersion);
    }

    /**
     * Returns a copy holding a rotated data key.
     *
     * @param rotated the new data key
     * @return the updated context
     */
    public RepoContext withDataKey(RepoDataKey rotated) {
        return new RepoContext(repoId, identity, rotated, payloadVersion, shareRefreshTokens);
    }
}

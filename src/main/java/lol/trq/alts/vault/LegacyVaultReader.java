package lol.trq.alts.vault;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import lol.trq.alts.AltsException;
import lol.trq.alts.internal.vault.legacy.LegacyRepository;
import lol.trq.alts.model.AltAccount;

/**
 * The read-only importer for a repository of the 0.4 shared vault, which 1.0 no longer speaks: given the
 * repository's manifest and envelope, as the 0.4 host wrote them (the JSON is parsed strictly), and the
 * member's own {@link VaultIdentity} (restored from its {@link WrappedIdentity} with the passphrase or the
 * recovery code), it returns the accounts. It never writes, never talks to a host and keeps nothing; the
 * host fetches the two documents itself (authenticating to its 0.4 server with {@link
 * VaultIdentity#signChallenge}) or exported them while it still ran 0.12. The owner then creates an AVP 0.5
 * repository ({@link SharedVault#create}) with the accounts they choose and invites the members again.
 *
 * <p>It accepts what a 0.12 member could read and nothing else: the manifest must name the {@code
 * X25519-HKDF-SHA256-AESGCM-v1} wrap and list this member at its key epoch, the data key must unwrap with this
 * identity's key, and the envelope must name the manifest's repository and key epoch, carry a payload version
 * no lower than the manifest's, and authenticate under the 0.4 AAD. While the manifest withholds refresh
 * tokens, no account returned carries a {@code refreshToken} or an {@code expiresAt}, whatever the payload
 * holds. There is no rollback floor: an import is one read, with no earlier state to compare.
 *
 * <p>An import proves nothing 0.4 did not: nothing in a 0.4 repository is signed, so a 0.4 host that lied
 * could have substituted keys or served an older payload before the import. Review the accounts before
 * writing them into the new repository.
 *
 * @author trq
 * @since 1.0.0
 */
public final class LegacyVaultReader {

    private LegacyVaultReader() {}

    /**
     * Reads the accounts of a 0.4 repository.
     *
     * @param manifestJson the repository manifest, as the 0.4 host served it
     * @param envelopeJson the encrypted payload envelope, as the 0.4 host served it
     * @param identity this member's identity
     * @return the accounts, in the order the payload holds them
     * @throws AltsException of kind {@code INVALID_INPUT} for text that is not strict JSON, {@code PROTOCOL}
     *     for JSON that is not a 0.4 manifest or envelope, a manifest that does not list this member, or an
     *     envelope that does not belong with the manifest, and {@code CRYPTO} if the data key does not unwrap
     *     with this identity or the payload does not authenticate; every message starts {@code "Vault 0.4
     *     import: "}
     * @since 1.0.0
     */
    public static List<AltAccount> read(String manifestJson, String envelopeJson, VaultIdentity identity) {
        Objects.requireNonNull(manifestJson, "manifestJson");
        Objects.requireNonNull(envelopeJson, "envelopeJson");
        Objects.requireNonNull(identity, "identity");
        // The importer needs the member id and the X25519 scalar only: it never signs, so the Ed25519 seed
        // stays inside the identity, and the scalar is zeroed as soon as the read is done.
        byte[] x25519Private = identity.keyAgreementScalar();
        try {
            return LegacyRepository.read(manifestJson, envelopeJson, identity.identityId(), x25519Private);
        } finally {
            Arrays.fill(x25519Private, (byte) 0);
        }
    }
}

package lol.trq.alts.account;

/**
 * Obtains the account's chat-signing key pair.
 *
 * <p>Not designed for host implementation; methods may be added in minor releases.
 *
 * @author trq
 * @since 0.12.0
 */
public interface CertificateService {

    /**
     * Requests the account's key pair. Call it again once
     * {@link PlayerCertificate#shouldRefresh(java.time.Instant)} says a held pair is due.
     *
     * <p>Nothing is persisted: the pair lives in the returned record and nowhere else.
     *
     * @return the key pair and its signatures
     * @throws lol.trq.alts.AltsException if the token was refused or the service failed
     * @since 0.12.0
     */
    PlayerCertificate fetch();
}

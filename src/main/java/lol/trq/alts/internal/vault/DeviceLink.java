package lol.trq.alts.internal.vault;

import java.util.Arrays;
import java.util.Objects;
import java.util.function.Predicate;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.internal.avp.AvpCrypto;
import lol.trq.alts.internal.avp.Tokens;
import lol.trq.alts.internal.avp.Tokens.LinkGrant;
import lol.trq.alts.internal.avp.Tokens.LinkRequest;

/**
 * Owner device linking (AVP SPEC 11.6): the new device's side ({@link #start()}, {@link #request()}, {@link
 * #confirmationCode()}, {@link #finish(LinkGrant)}) and the existing device's ({@link #approve}). No host is
 * involved: the request and the grant travel out of band.
 *
 * <p>The ephemeral key is a secret held until the session finishes, then zeroed. {@link #toString()} names
 * nothing secret.
 *
 * @author trq
 * @since 1.0.0
 */
public final class DeviceLink {

    private final byte[] ephemeral;
    private final LinkRequest request;
    private boolean finished;

    private DeviceLink(byte[] ephemeral) {
        this.ephemeral = ephemeral;
        this.request = new LinkRequest(AvpCrypto.x25519Public(ephemeral));
    }

    /**
     * Starts a session on the new device with a fresh ephemeral X25519 key.
     *
     * @return the session
     */
    public static DeviceLink start() {
        return new DeviceLink(AvpCrypto.randomBytes(32));
    }

    /**
     * The link request to show on the new device.
     *
     * @return the request
     */
    public LinkRequest request() {
        return request;
    }

    /**
     * The 6-digit code the new device shows; the existing device shows the same one.
     *
     * @return the code
     */
    public String confirmationCode() {
        return Tokens.linkConfirmationCode(request.ephemeralPublicKey());
    }

    /**
     * Opens a grant with the ephemeral key, which is then zeroed. A session finishes once.
     *
     * @param grant the grant from the existing device
     * @return the owner's 32-byte mnemonic entropy, which the caller zeroes
     * @throws AltsException of kind {@code CRYPTO} if the grant does not open under {@code avp/owner-link/v1}
     *     with this session's key, and {@code INVALID_INPUT} if the session already finished
     */
    public synchronized byte[] finish(LinkGrant grant) {
        Objects.requireNonNull(grant, "grant");
        if (finished) {
            throw VaultFailures.invalid("this device link already finished");
        }
        byte[] entropy = Tokens.openLinkGrant(grant, ephemeral);
        finished = true;
        Arrays.fill(ephemeral, (byte) 0);
        return entropy;
    }

    /**
     * The existing device's side: shows the request's confirmation code through {@code confirm} and, only if
     * the owner confirms it matches the code on the new device, wraps the entropy to the request's key under
     * {@code avp/owner-link/v1}.
     *
     * @param entropy the owner's 32-byte mnemonic entropy
     * @param request the new device's request
     * @param confirm shows the code and answers whether the owner confirmed it
     * @return the grant
     * @throws AltsException of kind {@code DECLINED} if the owner did not confirm
     */
    public static LinkGrant approve(byte[] entropy, LinkRequest request, Predicate<String> confirm) {
        String code = Tokens.linkConfirmationCode(request.ephemeralPublicKey());
        if (!confirm.test(code)) {
            throw new AltsException(Kind.DECLINED, "Vault: the owner did not confirm the device link code");
        }
        return Tokens.sealLinkGrant(entropy, request.ephemeralPublicKey());
    }

    /**
     * Names the state of the session only.
     *
     * @return a description
     */
    @Override
    public synchronized String toString() {
        return "DeviceLink[finished=" + finished + "]";
    }
}

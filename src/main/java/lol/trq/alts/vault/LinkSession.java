package lol.trq.alts.vault;

import java.util.Arrays;
import java.util.Objects;
import java.util.function.Predicate;
import lol.trq.alts.AltsException;
import lol.trq.alts.internal.vault.DeviceLink;

/**
 * Owner device linking (AVP SPEC 11.6): how a second owner device gets the {@link OwnerIdentity} without the
 * phrase being typed. No host takes part; the request and the grant travel out of band.
 *
 * <ol>
 *   <li>The new device calls {@link #start()} and shows {@link #request()} and {@link #confirmationCode()}.
 *   <li>The existing owner device reads the request and calls {@link #approve}, which shows the code it
 *       computes and continues only if the owner confirms it matches the one on the new device.
 *   <li>The new device passes the grant to {@link #finish(LinkGrant)} and has the owner identity.
 * </ol>
 *
 * <p>A session holds an ephemeral private key until it finishes; {@link #toString()} shows nothing of it.
 *
 * @author trq
 * @since 1.0.0
 */
public final class LinkSession {

    private final DeviceLink link;

    private LinkSession(DeviceLink link) {
        this.link = link;
    }

    /**
     * Starts a session on the new device, with a fresh ephemeral key.
     *
     * @return the session
     * @since 1.0.0
     */
    public static LinkSession start() {
        return new LinkSession(DeviceLink.start());
    }

    /**
     * The request to carry to the existing owner device.
     *
     * @return the request
     * @since 1.0.0
     */
    public LinkRequest request() {
        return new LinkRequest(link.request());
    }

    /**
     * The 6-digit code to show on this device; the existing device shows the same one.
     *
     * @return the code
     * @since 1.0.0
     */
    public String confirmationCode() {
        return link.confirmationCode();
    }

    /**
     * Opens the grant with this session's ephemeral key, which is then destroyed. A session finishes once.
     *
     * @param grant the grant from the existing owner device
     * @return the owner identity
     * @throws AltsException of kind {@code CRYPTO} if the grant was not made for this session's request, and
     *     {@code INVALID_INPUT} if the session already finished
     * @since 1.0.0
     */
    public OwnerIdentity finish(LinkGrant grant) {
        Objects.requireNonNull(grant, "grant");
        byte[] entropy = link.finish(grant.token());
        try {
            return OwnerIdentity.fromEntropy(entropy);
        } finally {
            Arrays.fill(entropy, (byte) 0);
        }
    }

    /**
     * The existing owner device's side: hands {@code confirm} the code this device computes for the request
     * and, only if it answers true (the owner confirmed it matches the code on the new device), wraps the
     * owner's entropy to the request's key under {@code avp/owner-link/v1}.
     *
     * @param owner the owner identity on this device
     * @param request the new device's request
     * @param confirm shows the code to the owner and answers whether they confirmed the two match
     * @return the grant to carry back
     * @throws AltsException of kind {@code DECLINED} if the owner did not confirm; nothing is wrapped. A {@code
     *     confirm} that throws is not caught: its exception reaches the caller as it is, and nothing is
     *     wrapped
     * @since 1.0.0
     */
    public static LinkGrant approve(OwnerIdentity owner, LinkRequest request, Predicate<String> confirm) {
        Objects.requireNonNull(owner, "owner");
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(confirm, "confirm");
        byte[] entropy = owner.entropy();
        try {
            return new LinkGrant(DeviceLink.approve(entropy, request.token(), confirm));
        } finally {
            Arrays.fill(entropy, (byte) 0);
        }
    }

    /**
     * Names the type and the 6-digit {@link #confirmationCode()}, which this device shows anyway and which
     * is no secret; never the ephemeral private key and never the request.
     *
     * @return a description
     * @since 1.0.0
     */
    @Override
    public String toString() {
        return "LinkSession[code " + link.confirmationCode() + "]";
    }
}

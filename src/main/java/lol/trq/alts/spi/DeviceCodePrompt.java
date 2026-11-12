package lol.trq.alts.spi;

import java.time.Instant;

/**
 * Host seam that shows the user a device-code sign-in challenge. The library never opens a browser for
 * this flow and never prints: it hands the host the code and the address, and the host decides how to
 * present them.
 *
 * <p><strong>Phishing.</strong> A device code authorizes whoever <em>started</em> the flow, not whoever
 * types the code, so a code relayed to someone else signs the relayer into that person's account. Start
 * the flow only on an explicit action by the user in front of the host, and always display the
 * verification address exactly as it is given here, so the user can see they are entering the code on
 * the identity provider's own page. Never substitute, shorten, or wrap the address.
 *
 * @author trq
 * @since 0.12.0
 */
@FunctionalInterface
public interface DeviceCodePrompt {

    /**
     * Shows the challenge. Called once per login, off the host's render thread; a host that draws UI
     * marshals to its own thread. It must return promptly — polling starts when it does — and an
     * exception thrown here fails the login.
     *
     * @param userCode the short code the user types at the verification address
     * @param verificationUri the address the user opens to enter the code; show it unmodified
     * @param expiresAt when the code stops being accepted, after which the login fails
     * @since 0.12.0
     */
    void show(String userCode, String verificationUri, Instant expiresAt);
}

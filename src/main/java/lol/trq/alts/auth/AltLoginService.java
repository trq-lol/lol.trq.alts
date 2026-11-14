package lol.trq.alts.auth;

import java.nio.file.Path;
import java.util.concurrent.CompletableFuture;
import lol.trq.alts.model.AltAccount;
import lol.trq.alts.model.LoginMode;
import lol.trq.alts.spi.DeviceCodePrompt;

/**
 * Contract for Minecraft account authentication services. Provides asynchronous methods to log into
 * accounts via Microsoft OAuth, browser cookies, session tokens, refresh tokens, or offline (cracked)
 * identities.
 *
 * <p>No route throws at the caller or completes its future exceptionally. Every failure, a runtime
 * closed before the route started included, is a {@link LoginResult} whose
 * {@link LoginResult#failure()} says what kind it was ({@link lol.trq.alts.AltsFailure.Kind#CANCELLED}
 * for a closed runtime or a refusing executor).
 *
 * <p>Not designed for host implementation; methods may be added in minor releases.
 *
 * @author trq
 * @since 0.1.0
 */
public interface AltLoginService {

    /**
     * Initiates authentication through the official Microsoft OAuth2 flow.
     *
     * @param mode the login mode (whether to add the account to storage)
     * @return a future containing the result of the login attempt
     * @since 0.1.0
     */
    CompletableFuture<LoginResult> loginMicrosoft(LoginMode mode);

    /**
     * Initiates authentication through the OAuth device-authorization grant: the host shows the user a
     * short code and an address through {@code prompt}, the user enters the code in any browser on any
     * device, and the library polls until the sign-in is approved, declined, or expires. It needs no
     * loopback port and no local browser, so it is the interactive route for a headless or locked-down
     * machine. The resulting account carries a refresh token exactly as {@link #loginMicrosoft} does.
     *
     * <p>The library never opens a browser for this flow and never prints the code. Cancelling the
     * returned future stops the polling.
     *
     * <p><strong>Phishing.</strong> A device code signs in whoever started the flow, not whoever types
     * the code. Call this only on an explicit action by the user, and always display the real
     * verification address the prompt is given.
     *
     * <p>The default implementation reports {@code NOT_CONFIGURED}: a login service that offers no
     * device-code sign-in says so as a result, like every other failure, rather than by throwing.
     *
     * @param prompt the host seam that shows the user the code and the verification address
     * @param mode the login mode (whether to add the account to storage)
     * @return a future containing the result of the login attempt
     * @since 0.12.0
     */
    default CompletableFuture<LoginResult> loginDeviceCode(DeviceCodePrompt prompt, LoginMode mode) {
        return CompletableFuture.completedFuture(LoginResult.failure(
                lol.trq.alts.AltsFailure.Kind.NOT_CONFIGURED, "Device code login is not supported"));
    }

    /**
     * Authenticates using raw browser cookie data. Reuses an existing browser session: the cookies,
     * exported from a browser already signed in, sign the account in without asking for its password
     * again.
     *
     * @param cookieData the cookie string in Netscape or mangled format
     * @param mode the login mode
     * @return a future containing the result of the login attempt
     * @since 0.1.0
     */
    CompletableFuture<LoginResult> loginCookie(String cookieData, LoginMode mode);

    /**
     * Authenticates using cookies exported to a file, which is the shape browser extensions produce
     * them in. The file is read off the calling thread; decoding and parsing are handled for the
     * caller, so a host only has to supply a path.
     *
     * @param file the exported cookie file, in Netscape or mangled format
     * @param mode the login mode
     * @return a future containing the result of the login attempt
     * @since 0.7.0
     */
    CompletableFuture<LoginResult> loginCookieFile(Path file, LoginMode mode);

    /**
     * Authenticates using a pre-existing Minecraft access token or session string.
     *
     * @param sessionToken the raw access token or session string
     * @param mode the login mode
     * @return a future containing the result of the login attempt
     * @since 0.1.0
     */
    CompletableFuture<LoginResult> loginSession(String sessionToken, LoginMode mode);

    /**
     * Authenticates using a stored OAuth refresh token, skipping the interactive browser step. The
     * token endpoint issues a rotated refresh token, which is stored on the resulting account.
     *
     * @param refreshToken the OAuth refresh token to redeem
     * @param mode the login mode
     * @return a future containing the result of the login attempt
     * @since 0.6.0
     */
    CompletableFuture<LoginResult> loginRefreshToken(String refreshToken, LoginMode mode);

    /**
     * Authenticates for offline (cracked) play using only a username.
     *
     * @param username the desired offline username
     * @param mode the login mode
     * @return a future containing the result of the login attempt
     * @since 0.1.0
     */
    CompletableFuture<LoginResult> loginOffline(String username, LoginMode mode);

    /**
     * Performs a login operation using an existing {@link AltAccount} data model.
     *
     * @param account the account data to authenticate with
     * @return a future containing the result of the login attempt
     * @since 0.1.0
     */
    CompletableFuture<LoginResult> loginAccount(AltAccount account);

    /**
     * Returns a view of this login service whose every request carries {@code tag} as the
     * {@link lol.trq.alts.net.NetworkScope#routeTag() route tag} its proxy provider sees, on every hop
     * of every route: the token exchange, Xbox Live, XSTS, the Minecraft services login, the profile
     * lookup, the cookie chain, and the renewal behind {@link #loginAccount(AltAccount)}. For a host that
     * pins each account to its own proxy and has to route a new account's first sign-in before any
     * account UUID exists to route on. The view stores, injects and classifies exactly as this service
     * does; only the tag differs.
     *
     * <p>The tag belongs to the sign-in, not to the account it produces. Once the account exists, what
     * is done with it is routed by its UUID like any other: {@code AltsRuntime#accountServices}, a bulk
     * check or refresh, and a later {@code loginAccount} through the service itself carry no tag. A host
     * that wants the account kept on the same proxy maps its UUID to that proxy in its provider.
     *
     * @param tag the host's route tag
     * @return the tagged view
     * @throws NullPointerException if {@code tag} is null
     * @throws IllegalArgumentException if {@code tag} is blank
     * @since 1.0.0
     */
    AltLoginService routed(String tag);
}

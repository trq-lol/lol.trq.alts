package lol.trq.alts.auth;

import java.util.Objects;

/**
 * Microsoft / Xbox Live authentication configuration the host supplies. The {@code clientId} is the
 * host's own Azure application id and is <strong>required</strong> — the library ships no default, so an
 * implementer must register their own app rather than sharing one. The scope, the local redirect path,
 * and every service endpoint default to the public Microsoft / Xbox / Minecraft URLs and are only
 * overridden when an implementer fronts them with a proxy or targets a non-standard deployment.
 *
 * <p>Build the common case with {@link #of(String)} and adjust with the {@code withX} copy methods.
 * A <em>legacy MSA</em> application is a different protocol dialect and comes from
 * {@link #legacyMsa(String)}. A blank optional value always falls back to its default.
 *
 * <p>A final class rather than a record since 1.0.0, so a later setting is an addition and not a break.
 * Two configs are equal when every value is.
 *
 * @author trq
 * @since 0.2.0
 */
public final class MicrosoftAuthConfig {

    /**
     * Default OAuth scope for a Minecraft login.
     *
     * @since 0.2.0
     */
    public static final String DEFAULT_SCOPE = "XboxLive.signin XboxLive.offline_access";

    /**
     * Default loopback callback path — intentionally long to reduce accidental screen-share exposure. The
     * browser sign-in redirects to {@code http://localhost:<port>} followed by this path, so the host's app
     * registration lists it. Changed in 1.0.0: a registration that lists the 0.12 default keeps working by passing that
     * path to {@link #withRedirectPath(String)}.
     *
     * @since 0.2.0
     */
    public static final String DEFAULT_REDIRECT_PATH =
            "/lol_trq_alts_loopback_redirect_long_enough_to_avoid_accidental_leaks_on_screenshare";

    /**
     * Default OAuth authorize endpoint.
     *
     * @since 0.2.0
     */
    public static final String DEFAULT_AUTHORIZE_URL = "https://login.live.com/oauth20_authorize.srf";

    /**
     * Default OAuth token endpoint.
     *
     * @since 0.2.0
     */
    public static final String DEFAULT_TOKEN_URL = "https://login.live.com/oauth20_token.srf";

    /**
     * Default Xbox Live user-authentication endpoint.
     *
     * @since 0.2.0
     */
    public static final String DEFAULT_XBOX_LIVE_AUTH_URL = "https://user.auth.xboxlive.com/user/authenticate";

    /**
     * Default XSTS authorization endpoint.
     *
     * @since 0.2.0
     */
    public static final String DEFAULT_XSTS_AUTH_URL = "https://xsts.auth.xboxlive.com/xsts/authorize";

    /**
     * Default Minecraft services login-with-Xbox endpoint.
     *
     * @since 0.2.0
     */
    public static final String DEFAULT_MINECRAFT_LOGIN_URL =
            "https://api.minecraftservices.com/authentication/login_with_xbox";

    /**
     * Default Minecraft services profile endpoint.
     *
     * @since 0.2.0
     */
    public static final String DEFAULT_MINECRAFT_PROFILE_URL = "https://api.minecraftservices.com/minecraft/profile";

    /**
     * Prefix marking an OAuth 2.0 access token as delegated when it is exchanged at Xbox Live.
     *
     * @since 0.7.0
     */
    public static final String DEFAULT_RPS_TICKET_PREFIX = "d=";

    /**
     * The scope a legacy MSA application authenticates Xbox Live with.
     *
     * @since 0.7.0
     */
    public static final String LEGACY_MSA_SCOPE = "service::user.auth.xboxlive.com::MBI_SSL";

    /**
     * The redirect a legacy MSA application's token grant must declare.
     *
     * @since 0.7.0
     */
    public static final String LEGACY_MSA_REDIRECT_URI = "https://login.live.com/oauth20_desktop.srf";

    /**
     * Prefix marking a legacy MSA access token as an RPS ticket proper.
     *
     * @since 0.7.0
     */
    public static final String LEGACY_MSA_RPS_TICKET_PREFIX = "t=";

    /**
     * Default device-authorization endpoint, on the consumers tenant of the Microsoft identity platform.
     *
     * @since 0.12.0
     */
    public static final String DEFAULT_DEVICE_CODE_URL =
            "https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode";

    /**
     * Default token endpoint the device-code login polls. It is a different endpoint from
     * {@link #DEFAULT_TOKEN_URL}: a device code is redeemed where it was issued.
     *
     * @since 0.12.0
     */
    public static final String DEFAULT_DEVICE_TOKEN_URL =
            "https://login.microsoftonline.com/consumers/oauth2/v2.0/token";

    private final String clientId;
    private final String scope;
    private final String redirectPath;
    private final String authorizeUrl;
    private final String tokenUrl;
    private final String xboxLiveAuthUrl;
    private final String xstsAuthUrl;
    private final String minecraftLoginUrl;
    private final String minecraftProfileUrl;
    private final String redirectUri;
    private final String rpsTicketPrefix;
    private final String deviceCodeUrl;
    private final String deviceTokenUrl;

    private MicrosoftAuthConfig(
            String clientId,
            String scope,
            String redirectPath,
            String authorizeUrl,
            String tokenUrl,
            String xboxLiveAuthUrl,
            String xstsAuthUrl,
            String minecraftLoginUrl,
            String minecraftProfileUrl,
            String redirectUri,
            String rpsTicketPrefix,
            String deviceCodeUrl,
            String deviceTokenUrl) {
        if (clientId == null || clientId.isBlank()) {
            throw new IllegalArgumentException("Microsoft clientId is required (supply your own Azure app id)");
        }
        this.clientId = clientId;
        this.scope = blankToDefault(scope, DEFAULT_SCOPE);
        this.redirectPath = blankToDefault(redirectPath, DEFAULT_REDIRECT_PATH);
        this.authorizeUrl = blankToDefault(authorizeUrl, DEFAULT_AUTHORIZE_URL);
        this.tokenUrl = blankToDefault(tokenUrl, DEFAULT_TOKEN_URL);
        this.xboxLiveAuthUrl = blankToDefault(xboxLiveAuthUrl, DEFAULT_XBOX_LIVE_AUTH_URL);
        this.xstsAuthUrl = blankToDefault(xstsAuthUrl, DEFAULT_XSTS_AUTH_URL);
        this.minecraftLoginUrl = blankToDefault(minecraftLoginUrl, DEFAULT_MINECRAFT_LOGIN_URL);
        this.minecraftProfileUrl = blankToDefault(minecraftProfileUrl, DEFAULT_MINECRAFT_PROFILE_URL);
        this.redirectUri = redirectUri == null || redirectUri.isBlank() ? null : redirectUri;
        this.rpsTicketPrefix = blankToDefault(rpsTicketPrefix, DEFAULT_RPS_TICKET_PREFIX);
        this.deviceCodeUrl = blankToDefault(deviceCodeUrl, DEFAULT_DEVICE_CODE_URL);
        this.deviceTokenUrl = blankToDefault(deviceTokenUrl, DEFAULT_DEVICE_TOKEN_URL);
    }

    /**
     * Creates a config for the given client id with every other value defaulted.
     *
     * @param clientId the host's Azure application client id; required
     * @return a fully-defaulted config
     * @since 0.2.0
     */
    public static MicrosoftAuthConfig of(String clientId) {
        return new MicrosoftAuthConfig(
                clientId, null, null, null, null, null, null, null, null, null, null, null, null);
    }

    /**
     * Creates a config for a <em>legacy MSA</em> application — the pre-Azure registration shape.
     *
     * <p>Three things differ from an OAuth app and all three are load-bearing: the token grant must
     * declare {@link #LEGACY_MSA_REDIRECT_URI}, it must ask for {@link #LEGACY_MSA_SCOPE} instead of
     * the delegated Xbox scopes, and the access token it returns is an RPS ticket that Xbox Live
     * wants prefixed {@code t=} rather than {@code d=}. Sending the OAuth shape to one of these apps
     * is answered with a flat {@code 400}.
     *
     * <p>Refresh tokens are the practical use: the interactive browser flow needs the desktop
     * redirect these apps declare, which the loopback callback server cannot serve.
     *
     * @param clientId the legacy application id; required
     * @return a config speaking the legacy MSA dialect
     * @since 0.7.0
     */
    public static MicrosoftAuthConfig legacyMsa(String clientId) {
        return new MicrosoftAuthConfig(
                clientId,
                LEGACY_MSA_SCOPE,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                LEGACY_MSA_REDIRECT_URI,
                LEGACY_MSA_RPS_TICKET_PREFIX,
                null,
                null);
    }

    /**
     * Returns a copy targeting a different application, keeping the dialect and endpoints.
     *
     * @param value the new client id; required
     * @return a copy with the client id replaced
     * @since 0.7.0
     */
    public MicrosoftAuthConfig withClientId(String value) {
        return new MicrosoftAuthConfig(
                value,
                scope,
                redirectPath,
                authorizeUrl,
                tokenUrl,
                xboxLiveAuthUrl,
                xstsAuthUrl,
                minecraftLoginUrl,
                minecraftProfileUrl,
                redirectUri,
                rpsTicketPrefix,
                deviceCodeUrl,
                deviceTokenUrl);
    }

    /**
     * Returns a copy with the OAuth scope replaced.
     *
     * @param value the new scope, or null/blank to keep the default
     * @return a copy with the scope replaced
     * @since 0.2.0
     */
    public MicrosoftAuthConfig withScope(String value) {
        return new MicrosoftAuthConfig(
                clientId,
                value,
                redirectPath,
                authorizeUrl,
                tokenUrl,
                xboxLiveAuthUrl,
                xstsAuthUrl,
                minecraftLoginUrl,
                minecraftProfileUrl,
                redirectUri,
                rpsTicketPrefix,
                deviceCodeUrl,
                deviceTokenUrl);
    }

    /**
     * Returns a copy with the local redirect path replaced.
     *
     * @param value the new redirect path, or null/blank to keep the default
     * @return a copy with the redirect path replaced
     * @since 0.2.0
     */
    public MicrosoftAuthConfig withRedirectPath(String value) {
        return new MicrosoftAuthConfig(
                clientId,
                scope,
                value,
                authorizeUrl,
                tokenUrl,
                xboxLiveAuthUrl,
                xstsAuthUrl,
                minecraftLoginUrl,
                minecraftProfileUrl,
                redirectUri,
                rpsTicketPrefix,
                deviceCodeUrl,
                deviceTokenUrl);
    }

    /**
     * Returns a copy with all six service endpoints replaced (each null/blank argument keeps its
     * default). For implementers fronting Microsoft / Xbox / Minecraft services with their own proxy.
     *
     * @param authorizeUrl the OAuth authorize endpoint
     * @param tokenUrl the OAuth token endpoint
     * @param xboxLiveAuthUrl the Xbox Live user-authentication endpoint
     * @param xstsAuthUrl the XSTS authorization endpoint
     * @param minecraftLoginUrl the Minecraft services login-with-Xbox endpoint
     * @param minecraftProfileUrl the Minecraft services profile endpoint
     * @return a copy with the endpoints replaced
     * @since 0.2.0
     */
    public MicrosoftAuthConfig withEndpoints(
            String authorizeUrl,
            String tokenUrl,
            String xboxLiveAuthUrl,
            String xstsAuthUrl,
            String minecraftLoginUrl,
            String minecraftProfileUrl) {
        return new MicrosoftAuthConfig(
                clientId,
                scope,
                redirectPath,
                authorizeUrl,
                tokenUrl,
                xboxLiveAuthUrl,
                xstsAuthUrl,
                minecraftLoginUrl,
                minecraftProfileUrl,
                redirectUri,
                rpsTicketPrefix,
                deviceCodeUrl,
                deviceTokenUrl);
    }

    /**
     * Returns a copy with the two device-code endpoints replaced (each null/blank argument keeps its
     * default). Kept apart from {@link #withEndpoints} so that method's signature is unchanged.
     *
     * @param deviceCodeUrl the device-authorization endpoint
     * @param deviceTokenUrl the token endpoint the device-code login polls
     * @return a copy with the device-code endpoints replaced
     * @since 0.12.0
     */
    public MicrosoftAuthConfig withDeviceCodeEndpoints(String deviceCodeUrl, String deviceTokenUrl) {
        return new MicrosoftAuthConfig(
                clientId,
                scope,
                redirectPath,
                authorizeUrl,
                tokenUrl,
                xboxLiveAuthUrl,
                xstsAuthUrl,
                minecraftLoginUrl,
                minecraftProfileUrl,
                redirectUri,
                rpsTicketPrefix,
                deviceCodeUrl,
                deviceTokenUrl);
    }

    /**
     * Returns the host's Azure application (OAuth) client id.
     *
     * @return the client id
     * @since 0.2.0
     */
    public String clientId() {
        return clientId;
    }

    /**
     * Returns the OAuth scope to request.
     *
     * @return the value, defaulted when none was given
     * @since 0.2.0
     */
    public String scope() {
        return scope;
    }

    /**
     * Returns the local callback path the loopback redirect server listens on.
     *
     * @return the value, defaulted when none was given
     * @since 0.2.0
     */
    public String redirectPath() {
        return redirectPath;
    }

    /**
     * Returns the OAuth authorize endpoint.
     *
     * @return the value, defaulted when none was given
     * @since 0.2.0
     */
    public String authorizeUrl() {
        return authorizeUrl;
    }

    /**
     * Returns the OAuth token endpoint.
     *
     * @return the value, defaulted when none was given
     * @since 0.2.0
     */
    public String tokenUrl() {
        return tokenUrl;
    }

    /**
     * Returns the Xbox Live user-authentication endpoint.
     *
     * @return the value, defaulted when none was given
     * @since 0.2.0
     */
    public String xboxLiveAuthUrl() {
        return xboxLiveAuthUrl;
    }

    /**
     * Returns the XSTS authorization endpoint.
     *
     * @return the value, defaulted when none was given
     * @since 0.2.0
     */
    public String xstsAuthUrl() {
        return xstsAuthUrl;
    }

    /**
     * Returns the Minecraft services login-with-Xbox endpoint.
     *
     * @return the value, defaulted when none was given
     * @since 0.2.0
     */
    public String minecraftLoginUrl() {
        return minecraftLoginUrl;
    }

    /**
     * Returns the Minecraft services profile endpoint.
     *
     * @return the value, defaulted when none was given
     * @since 0.2.0
     */
    public String minecraftProfileUrl() {
        return minecraftProfileUrl;
    }

    /**
     * Returns the {@code redirect_uri} the refresh grant must carry; the authorization-code grant ignores this and uses the address the callback server actually served.
     *
     * @return the redirect URI, or {@code null} to omit it
     * @since 0.7.0
     */
    public String redirectUri() {
        return redirectUri;
    }

    /**
     * Returns the prefix the Microsoft access token carries into the Xbox Live RPS ticket.
     *
     * @return the value, defaulted when none was given
     * @since 0.7.0
     */
    public String rpsTicketPrefix() {
        return rpsTicketPrefix;
    }

    /**
     * Returns the device-authorization endpoint the device-code login starts at.
     *
     * @return the value, defaulted when none was given
     * @since 0.12.0
     */
    public String deviceCodeUrl() {
        return deviceCodeUrl;
    }

    /**
     * Returns the token endpoint the device-code login polls.
     *
     * @return the value, defaulted when none was given
     * @since 0.12.0
     */
    public String deviceTokenUrl() {
        return deviceTokenUrl;
    }

    /**
     * Returns a copy with the {@code redirect_uri} the refresh grant carries replaced. An OAuth app's
     * refresh grant carries none; a legacy MSA app's declares {@link #LEGACY_MSA_REDIRECT_URI}.
     *
     * @param value the redirect URI, or null/blank to omit it
     * @return a copy with the redirect URI replaced
     * @since 1.0.0
     */
    public MicrosoftAuthConfig withRedirectUri(String value) {
        return new MicrosoftAuthConfig(
                clientId,
                scope,
                redirectPath,
                authorizeUrl,
                tokenUrl,
                xboxLiveAuthUrl,
                xstsAuthUrl,
                minecraftLoginUrl,
                minecraftProfileUrl,
                value,
                rpsTicketPrefix,
                deviceCodeUrl,
                deviceTokenUrl);
    }

    /**
     * Returns a copy with the RPS ticket prefix replaced.
     *
     * @param value the prefix, or null/blank to keep the default ({@link #DEFAULT_RPS_TICKET_PREFIX})
     * @return a copy with the prefix replaced
     * @since 1.0.0
     */
    public MicrosoftAuthConfig withRpsTicketPrefix(String value) {
        return new MicrosoftAuthConfig(
                clientId,
                scope,
                redirectPath,
                authorizeUrl,
                tokenUrl,
                xboxLiveAuthUrl,
                xstsAuthUrl,
                minecraftLoginUrl,
                minecraftProfileUrl,
                redirectUri,
                value,
                deviceCodeUrl,
                deviceTokenUrl);
    }

    /**
     * Returns whether {@code o} is a config with every value equal to this one's.
     *
     * @param o the object to compare
     * @return true when every value is equal
     * @since 0.2.0
     */
    @Override
    public boolean equals(Object o) {
        return o instanceof MicrosoftAuthConfig other
                && Objects.equals(clientId, other.clientId)
                && Objects.equals(scope, other.scope)
                && Objects.equals(redirectPath, other.redirectPath)
                && Objects.equals(authorizeUrl, other.authorizeUrl)
                && Objects.equals(tokenUrl, other.tokenUrl)
                && Objects.equals(xboxLiveAuthUrl, other.xboxLiveAuthUrl)
                && Objects.equals(xstsAuthUrl, other.xstsAuthUrl)
                && Objects.equals(minecraftLoginUrl, other.minecraftLoginUrl)
                && Objects.equals(minecraftProfileUrl, other.minecraftProfileUrl)
                && Objects.equals(redirectUri, other.redirectUri)
                && Objects.equals(rpsTicketPrefix, other.rpsTicketPrefix)
                && Objects.equals(deviceCodeUrl, other.deviceCodeUrl)
                && Objects.equals(deviceTokenUrl, other.deviceTokenUrl);
    }

    /**
     * Returns a hash over every value, consistent with {@link #equals(Object)}.
     *
     * @return the hash
     * @since 0.2.0
     */
    @Override
    public int hashCode() {
        return Objects.hash(
                clientId,
                scope,
                redirectPath,
                authorizeUrl,
                tokenUrl,
                xboxLiveAuthUrl,
                xstsAuthUrl,
                minecraftLoginUrl,
                minecraftProfileUrl,
                redirectUri,
                rpsTicketPrefix,
                deviceCodeUrl,
                deviceTokenUrl);
    }

    /**
     * Returns every value, in the form the record printed them. The config holds no secret.
     *
     * @return a description
     * @since 0.2.0
     */
    @Override
    public String toString() {
        return "MicrosoftAuthConfig[clientId=" + clientId + ", scope=" + scope + ", redirectPath=" + redirectPath
                + ", authorizeUrl=" + authorizeUrl + ", tokenUrl=" + tokenUrl + ", xboxLiveAuthUrl=" + xboxLiveAuthUrl
                + ", xstsAuthUrl=" + xstsAuthUrl + ", minecraftLoginUrl=" + minecraftLoginUrl + ", minecraftProfileUrl="
                + minecraftProfileUrl + ", redirectUri=" + redirectUri + ", rpsTicketPrefix=" + rpsTicketPrefix
                + ", deviceCodeUrl=" + deviceCodeUrl + ", deviceTokenUrl=" + deviceTokenUrl + "]";
    }

    private static String blankToDefault(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }
}

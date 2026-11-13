package lol.trq.alts.auth;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;
import lol.trq.alts.auth.AltLoginCallback.FailureReason;
import lol.trq.alts.auth.MicrosoftAuthUtil.AuthFlowException;
import lol.trq.alts.net.HttpTransport;
import lol.trq.alts.net.NetworkScope;

/**
 * Authenticates Minecraft accounts using browser session cookies.
 *
 * <p>Supports both standard Netscape cookie file formats and "mangled" formats resulting from
 * inconsistent copy-pasting. Simulates the browser redirect chain required to convert Microsoft
 * session cookies into an XSTS token and finally a Minecraft access token.
 *
 * @author trq
 * @since 0.1.0
 */
public final class CookieAuthUtil {

    /**
     * The browser the redirect chain presents itself as. The sign-in pages answer an obviously stale
     * browser differently, so this is the one place to bump when it ages.
     */
    private static final String USER_AGENT =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36";

    /** The only site whose cookies this flow has any use for, and the only one they are ever sent to. */
    private static final String COOKIE_SITE = "live.com";

    /** Marks an HttpOnly cookie's line in a Netscape export; it is a prefix on the domain, not a comment. */
    private static final String HTTP_ONLY_PREFIX = "#HttpOnly_";

    /** The longest redirect chain that is followed before the sign-in is treated as going nowhere. */
    private static final int MAX_HOPS = 8;

    private static final Pattern LINE_BREAK = Pattern.compile("\\r?\\n");
    private static final Pattern WHITESPACE = Pattern.compile("\\s+");
    private static final Pattern NUMERIC = Pattern.compile("^[\\d.]+$");
    private static final Pattern LIVE_LOGIN_SEGMENT = Pattern.compile("(?=(?:\\.?)login\\.live\\.com)");

    /**
     * Known cookie names required for Microsoft/Xbox Live authentication. Ordered by length to ensure
     * precise matching during mangled parsing.
     */
    private static final String[] KNOWN_COOKIE_NAMES = {
        "MicrosoftApplicationsTelemetryDeviceId",
        "__Host-MSAAUTHP",
        "MSPRequ",
        "MSPPre",
        "MSPCID",
        "MSPVis",
        "MSPOK",
        "OParams",
        "SDIDC",
        "JSHP",
        "MSCC",
        "uaid"
    };

    private final HttpTransport http;
    private final AccountNetworkUtil profiles;

    /**
     * Creates the cookie chain over a transport: every hop goes through it.
     *
     * @param http the runtime's transport
     * @since 1.0.0
     */
    public CookieAuthUtil(HttpTransport http) {
        this.http = Objects.requireNonNull(http, "http");
        this.profiles = new AccountNetworkUtil(http);
    }

    /** Where the sign-in starts: the Xbox Live SISU endpoint, asked to land on the Minecraft login page. */
    private static final String SISU_START =
            "https://sisu.xboxlive.com/connect/XboxLive/?state=login&cobrandId=8058f65d-ce06-4c30-9559-473c9275a65d&tid=896928775&ru=https://www.minecraft.net/en-us/login&aid=1142970254&as=0";

    /** The query or fragment parameter the last redirect carries the token bundle in. */
    private static final String ACCESS_TOKEN_PARAM = "accessToken=";

    /**
     * The only host whose redirect may end the chain with a token bundle: the one the chain starts at.
     * Derived from the start address so the two cannot drift apart.
     */
    private static final String TOKEN_ISSUER_HOST = URI.create(SISU_START).getHost();

    /** The relying party whose XSTS token Minecraft services accept. */
    private static final String MINECRAFT_RELYING_PARTY = "rp://api.minecraftservices.com/";

    /**
     * Executes the full cookie-based authentication flow.
     *
     * <p>The chain is a series of redirects. SISU hands off to the Microsoft identity platform, which
     * hands off to {@code login.live.com}; that is where the session cookies sign the user in, and it
     * answers with a code for SISU, which SISU then turns into the redirect that carries the token.
     *
     * <p>Three rules bound what the cookies can reach. Only cookies whose domain is {@code live.com} or
     * a subdomain are kept, so a whole-browser export does not hand every other site's session to this
     * flow. A kept cookie is attached only to an HTTPS request whose host its domain covers, exactly as
     * a browser would, so the SISU hops and the identity platform hop carry none. And every hop must be
     * HTTPS: a redirect anywhere else ends the flow rather than being followed.
     *
     * @param cookieData the raw string containing cookie information
     * @param config the host's Microsoft authentication configuration, whose Minecraft services
     *     endpoints are used; {@code null} for the public defaults
     * @param account a scope naming the account the requests are for, or {@code null} for none
     * @return a {@link MinecraftProfile} containing the authenticated session data
     * @throws Exception if parsing fails or the redirect chain is interrupted; a failure the flow could
     *     classify is an {@link AuthFlowException}
     * @since 0.12.0
     */
    public MinecraftProfile authenticate(String cookieData, MicrosoftAuthConfig config, NetworkScope account)
            throws Exception {
        List<Cookie> cookies = parseCookieList(cookieData);
        NetworkScope auth = scope(NetworkScope.Purpose.AUTH, account);

        String landing = followChain(cookies, (url, cookieHeader) -> followRedirect(url, cookieHeader, auth));

        return completeFromLanding(landing, config, account);
    }

    /**
     * Turns the chain's last redirect into a session: reads the token bundle out of it, exchanges that
     * at Minecraft services, and resolves the profile. Both requests go to the endpoints the host
     * configured and carry the account, like every other route's.
     *
     * <p>Package-private so the tail of the flow can be tested against a loopback server.
     *
     * @param landing the redirect target carrying the token bundle
     * @param config the host's Microsoft authentication configuration, or {@code null} for the defaults
     * @param account a scope naming the account the requests are for, or {@code null} for none
     * @return the authenticated profile
     */
    MinecraftProfile completeFromLanding(String landing, MicrosoftAuthConfig config, NetworkScope account) {
        XstsTokenData xstsData = extractXstsFromRedirect(landing);
        String loginUrl = config != null ? config.minecraftLoginUrl() : MicrosoftAuthConfig.DEFAULT_MINECRAFT_LOGIN_URL;
        String profileUrl =
                config != null ? config.minecraftProfileUrl() : MicrosoftAuthConfig.DEFAULT_MINECRAFT_PROFILE_URL;
        String mcToken = authenticateWithMinecraft(xstsData, loginUrl, scope(NetworkScope.Purpose.AUTH, account));

        return getMinecraftProfile(mcToken, profileUrl, scope(NetworkScope.Purpose.PROFILE, account));
    }

    /**
     * One request of the redirect chain: fetch a URL and report where it redirects to.
     *
     * <p>Package-private so the chain's rules can be tested against a scripted set of hops.
     */
    @FunctionalInterface
    interface RedirectFetcher {

        /**
         * Fetches one hop.
         *
         * @param url the HTTPS URL to request
         * @param cookieHeader the Cookie header to send, or {@code null} to send none
         * @return the redirect target
         * @throws Exception if the hop did not redirect or could not be reached
         */
        String location(String url, String cookieHeader) throws Exception;
    }

    /**
     * Follows the sign-in chain from SISU to the redirect that carries the token bundle, however many
     * hops that takes. The chain has changed length before, so it is followed to its end rather than
     * counted.
     *
     * @param cookies the cookies kept from the export
     * @param fetcher performs each hop
     * @return the last redirect target, which carries the token bundle
     * @throws Exception if a hop fails, leaves HTTPS, or the chain never produces a token
     */
    static String followChain(List<Cookie> cookies, RedirectFetcher fetcher) throws Exception {
        String url = SISU_START;
        for (int hop = 0; hop < MAX_HOPS; hop++) {
            // The services put raw spaces in the URLs they redirect to, which no URI parser accepts.
            url = url.replace(" ", "%20");
            URI target = httpsTarget(url);
            String next = fetcher.location(url, cookieHeaderFor(target.getHost(), cookies));
            if (next == null || next.isBlank()) {
                throw new AuthFlowException("Cookie sign-in did not redirect", FailureReason.INVALID_TOKEN);
            }
            if (next.contains(ACCESS_TOKEN_PARAM)) {
                // The bundle is only as good as whoever handed it over. The chain passes through hosts
                // that take a return address as a parameter, so "some hop redirected to an address with
                // a token in it" proves nothing; the service that started the sign-in is the one that
                // ends it.
                if (!TOKEN_ISSUER_HOST.equalsIgnoreCase(target.getHost())) {
                    throw new AuthFlowException(
                            "Cookie sign-in produced a token from an unexpected host", FailureReason.UNKNOWN);
                }
                return next;
            }
            // Resolved against the address that answered, whatever form the redirect took: absolute,
            // rooted at the host, or relative to the current path.
            try {
                url = target.resolve(next.replace(" ", "%20")).toString();
            } catch (IllegalArgumentException unparseable) {
                throw new AuthFlowException(
                        "Cookie sign-in redirected to an unreadable address", FailureReason.UNKNOWN);
            }
        }
        // The usual cause is cookies that no longer sign in: the chain loops through the sign-in page.
        throw new AuthFlowException("Cookie sign-in never produced a token", FailureReason.INVALID_TOKEN);
    }

    /**
     * Parses a hop's URL and insists it is HTTPS. The message deliberately omits the URL, which carries
     * the sign-in's codes in its query.
     *
     * @param url the URL to check
     * @return the parsed URL
     */
    private static URI httpsTarget(String url) {
        URI target;
        try {
            target = URI.create(url);
        } catch (IllegalArgumentException unparseable) {
            throw new AuthFlowException("Cookie sign-in redirected to an unreadable address", FailureReason.UNKNOWN);
        }
        if (!"https".equalsIgnoreCase(target.getScheme()) || target.getHost() == null) {
            throw new AuthFlowException("Cookie sign-in was redirected off HTTPS", FailureReason.UNKNOWN);
        }
        return target;
    }

    /**
     * Builds the Cookie header for a request to {@code host}: the cookies whose domain covers it, and
     * nothing at all when the host is not under {@code live.com}.
     *
     * @param host the request's host
     * @param cookies the cookies kept from the export
     * @return the header value, or {@code null} when no cookie belongs on this request
     */
    static String cookieHeaderFor(String host, List<Cookie> cookies) {
        if (!withinSite(host)) {
            return null;
        }
        String normalizedHost = host.toLowerCase(Locale.ROOT);
        List<Cookie> matching = new ArrayList<>();
        for (Cookie cookie : cookies) {
            if (cookie.domain() == null || covers(normalizedDomain(cookie.domain()), normalizedHost)) {
                matching.add(cookie);
            }
        }
        return matching.isEmpty() ? null : header(matching);
    }

    /** {@return whether {@code domain} is {@code live.com} or one of its subdomains} */
    private static boolean withinSite(String domain) {
        return domain != null && covers(COOKIE_SITE, normalizedDomain(domain));
    }

    /** {@return whether a cookie set for {@code domain} would be sent to {@code host}} */
    private static boolean covers(String domain, String host) {
        return host.equals(domain) || host.endsWith("." + domain);
    }

    private static String normalizedDomain(String domain) {
        String lower = domain.trim().toLowerCase(Locale.ROOT);
        return lower.startsWith(".") ? lower.substring(1) : lower;
    }

    private static String header(List<Cookie> cookies) {
        StringBuilder builder = new StringBuilder();
        for (Cookie cookie : cookies) {
            builder.append(cookie.name()).append("=").append(cookie.value()).append("; ");
        }
        return builder.toString().trim();
    }

    private static NetworkScope scope(NetworkScope.Purpose purpose, NetworkScope account) {
        return account == null
                ? NetworkScope.of(purpose)
                : NetworkScope.forAccount(purpose, account.accountUuid(), account.accountUsername());
    }

    /**
     * One cookie from an export.
     *
     * @param domain the domain the export recorded for it, or {@code null} when the export's shape
     *     carries none
     * @param name the cookie name
     * @param value the cookie value
     */
    record Cookie(String domain, String name, String value) {

        // The value is a live session credential.
        @Override
        public String toString() {
            return "Cookie[domain=" + domain + ", name=" + name + ", value=<redacted>]";
        }
    }

    /** How deep a JSON export is walked before it is treated as hostile rather than merely nested. */
    private static final int MAX_JSON_DEPTH = 32;

    /**
     * Parses cookie data into the Cookie header a {@code live.com} request would carry.
     *
     * <p>Package-private so the shapes can be tested without a network round.
     *
     * @param cookieData the input string
     * @return a formatted HTTP Cookie header string
     * @throws IllegalArgumentException if no usable cookie could be identified
     */
    static String parseCookies(String cookieData) {
        return header(parseCookieList(cookieData));
    }

    /**
     * High-level entry point for parsing cookie data from an ambiguous string. Three shapes are
     * recognised, in the order a real export is cheapest to identify: a JSON array or object, the
     * tab-separated Netscape format, and text that has been through a copy-paste and lost its structure.
     *
     * <p>Whatever the shape, a cookie the export attributes to a domain outside {@code live.com} is
     * dropped here, before anything is sent anywhere. Exporting "all cookies" is the path of least
     * resistance in every browser extension, and without this the whole browser's sessions rode along.
     * A cookie whose export records no domain at all is kept, since there is nothing to judge it by.
     *
     * @param cookieData the input string
     * @return the cookies worth sending, never empty
     * @throws IllegalArgumentException if no usable cookie could be identified
     */
    static List<Cookie> parseCookieList(String cookieData) {
        String trimmed = cookieData.trim();
        if (trimmed.startsWith("[") || trimmed.startsWith("{")) {
            List<Cookie> json = parseJsonCookies(trimmed);
            if (!json.isEmpty()) return json;
        }
        if (cookieData.contains("\n") && cookieData.split("\n").length > 3) {
            List<Cookie> result = parseDelimitedCookies(cookieData);
            if (!result.isEmpty()) return result;
        }
        return parseMangledCookies(cookieData);
    }

    /**
     * Parses the JSON export the common cookie-editor extensions produce: an array of objects each
     * carrying at least a {@code name} and a {@code value}. Wrappers vary (some tools nest the array
     * under a key, some export one object per domain), so the tree is walked rather than assumed.
     *
     * <p>Without this, a JSON export fell through to the mangled parser, which found the cookie names it
     * knows and took the rest of the surrounding JSON as their values. That produced a Cookie header the
     * service rejected, and a failure that read as bad cookies rather than an unread file.
     *
     * @param data the trimmed JSON text
     * @return the cookies found, empty if the text held no cookie objects
     */
    private static List<Cookie> parseJsonCookies(String data) {
        List<Cookie> cookies = new ArrayList<>();
        try {
            collectJsonCookies(JsonParser.parseString(data), cookies, 0);
        } catch (RuntimeException notJson) {
            return List.of();
        }
        return cookies;
    }

    /**
     * Walks a parsed export, collecting every object that looks like a cookie.
     *
     * @param element the element to walk
     * @param out the cookies collected so far
     * @param depth the current nesting depth
     */
    private static void collectJsonCookies(JsonElement element, List<Cookie> out, int depth) {
        if (element == null || depth > MAX_JSON_DEPTH) {
            return;
        }
        if (element.isJsonArray()) {
            for (JsonElement child : element.getAsJsonArray()) {
                collectJsonCookies(child, out, depth + 1);
            }
            return;
        }
        if (!element.isJsonObject()) {
            return;
        }

        JsonObject object = element.getAsJsonObject();
        String name = stringField(object, "name");
        String value = stringField(object, "value");
        if (name != null && value != null) {
            String domain = stringField(object, "domain");
            if (domain == null) {
                domain = stringField(object, "host");
            }
            if (isValidCookie(name) && (domain == null || withinSite(domain))) {
                out.add(new Cookie(domain, name, value));
            }
            return;
        }
        for (Map.Entry<String, JsonElement> entry : object.entrySet()) {
            collectJsonCookies(entry.getValue(), out, depth + 1);
        }
    }

    /**
     * Reads a string member, treating a missing, null, or non-string value as absent.
     *
     * @param object the object to read from
     * @param key the member name
     * @return the string value, or null
     */
    private static String stringField(JsonObject object, String key) {
        JsonElement element = object.get(key);
        return element != null
                        && element.isJsonPrimitive()
                        && element.getAsJsonPrimitive().isString()
                ? element.getAsString()
                : null;
    }

    /**
     * Parses cookies from a standard Netscape/tab-separated format, whose first column is the domain.
     *
     * @param cookieData the tab-separated cookie string
     * @return the {@code live.com} cookies found
     */
    private static List<Cookie> parseDelimitedCookies(String cookieData) {
        List<Cookie> cookies = new ArrayList<>();

        for (String line : LINE_BREAK.split(cookieData)) {
            line = line.trim();
            if (line.startsWith(HTTP_ONLY_PREFIX)) {
                line = line.substring(HTTP_ONLY_PREFIX.length());
            }
            if (line.isEmpty() || line.startsWith("#")) continue;

            String[] parts = WHITESPACE.split(line);
            if (parts.length >= 7) {
                String domain = parts[0];
                String name = parts[parts.length - 2];
                String value = parts[parts.length - 1];
                if (isValidCookie(name) && withinSite(domain)) {
                    cookies.add(new Cookie(domain, name, value));
                }
            }
        }
        return cookies;
    }

    /**
     * Robust parser for cookie data that has been smashed or poorly formatted. Splits data based on
     * the Microsoft login domain and extracts known keys, so everything it finds belongs to that
     * domain by construction.
     *
     * @param data the mangled input string
     * @return the cookies found, never empty
     * @throws IllegalArgumentException if no valid cookies could be identified
     */
    private static List<Cookie> parseMangledCookies(String data) {
        List<Cookie> cookies = new ArrayList<>();

        for (String segment : LIVE_LOGIN_SEGMENT.split(data)) {
            if (segment.isBlank()) continue;

            for (String key : KNOWN_COOKIE_NAMES) {
                int keyIndex = segment.indexOf(key);
                if (keyIndex != -1) {
                    String rawValue = segment.substring(keyIndex + key.length()).trim();
                    if (!rawValue.isEmpty()) {
                        cookies.add(new Cookie("login.live.com", key, rawValue));
                    }
                    break;
                }
            }
        }

        if (cookies.isEmpty()) {
            throw new IllegalArgumentException("Could not parse valid cookies from data.");
        }
        return cookies;
    }

    /**
     * Filters out non-cookie metadata fields often found in cookie exports.
     *
     * @param name the potential cookie name
     * @return true if the name appears to be a valid cookie key
     */
    private static boolean isValidCookie(String name) {
        return !name.contains(".com")
                && !name.equals("/")
                && !name.equalsIgnoreCase("true")
                && !name.equalsIgnoreCase("false")
                && !NUMERIC.matcher(name).matches();
    }

    /**
     * Performs a GET request to a URL and returns the {@code Location} header for redirection.
     *
     * <p>Goes through {@link HttpTransport} like every other request the library makes, which is what gives
     * this chain the finite timeouts, the refusal to follow redirects on its own, and the host's proxy.
     * Opening its own connection meant it had none of the three.
     *
     * @param urlString the URL to request
     * @param cookies the cookies to send with the request, or {@code null} for none
     * @param scope what the request is for, and on whose behalf
     * @return the target redirection URL
     * @throws AuthFlowException if the server does not return a redirect or cannot be reached
     */
    private String followRedirect(String urlString, String cookies, NetworkScope scope) {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8");
        headers.put("Accept-Encoding", "*");
        headers.put("Accept-Language", "en-US;q=0.8,en;q=0.7");
        // Only the Location header is wanted; the sign-in pages behind these URLs are large.
        headers.put("Range", "bytes=0-0");
        headers.put("User-Agent", USER_AGENT);
        if (cookies != null && !cookies.isEmpty()) {
            headers.put("Cookie", cookies);
        }

        HttpTransport.HeaderResponse response;
        try {
            response = http.getHeader(urlString, headers, "Location", scope);
        } catch (Exception transportFailure) {
            throw MicrosoftAuthUtil.unreachable("Cookie sign-in", transportFailure);
        }

        if (response.value() == null) {
            if (response.status() >= 400) {
                throw MicrosoftAuthUtil.stepFailure("Cookie sign-in", response.status());
            }
            // A page instead of a redirect is the sign-in form: the cookies no longer sign anyone in.
            throw new AuthFlowException("Cookie sign-in did not redirect", FailureReason.INVALID_TOKEN);
        }
        return response.value();
    }

    /**
     * Extracts XSTS authentication data from the final redirect URI.
     *
     * <p>The token bundle is a Base64 JSON array of relying-party and token pairs, percent-encoded into
     * the URL. It is decoded and parsed rather than cut apart as text, so neither the encoding of its
     * padding nor the order of its fields decides whether a login works.
     *
     * <p>Package-private so the decoding can be tested without a network round.
     *
     * @param redirectUrl the URL containing the encoded access token
     * @return a record containing the XSTS token and user hash
     * @throws AuthFlowException if the token is missing or incorrectly encoded
     */
    static XstsTokenData extractXstsFromRedirect(String redirectUrl) {
        if (redirectUrl == null || !redirectUrl.contains(ACCESS_TOKEN_PARAM)) {
            throw new AuthFlowException("Invalid redirect: No accessToken", FailureReason.INVALID_TOKEN);
        }

        String raw = redirectUrl.substring(redirectUrl.indexOf(ACCESS_TOKEN_PARAM) + ACCESS_TOKEN_PARAM.length());
        int end = indexOfAny(raw, '&', '#');
        if (end != -1) raw = raw.substring(0, end);

        JsonArray bundle;
        try {
            // Not URLDecoder: that is for form bodies and would turn a Base64 '+' into a space.
            String encoded = percentDecode(raw);
            byte[] bytes;
            try {
                bytes = Base64.getDecoder().decode(encoded);
            } catch (IllegalArgumentException notStandard) {
                bytes = Base64.getUrlDecoder().decode(encoded);
            }
            bundle = JsonParser.parseString(new String(bytes, StandardCharsets.UTF_8))
                    .getAsJsonArray();
        } catch (RuntimeException malformed) {
            throw new AuthFlowException(
                    "Invalid redirect: accessToken could not be decoded", FailureReason.INVALID_TOKEN);
        }

        try {
            for (JsonElement element : bundle) {
                JsonObject entry = element.getAsJsonObject();
                if (!MINECRAFT_RELYING_PARTY.equals(entry.get("Item1").getAsString())) continue;

                JsonObject item = entry.getAsJsonObject("Item2");
                String token = item.get("Token").getAsString();
                String uhs = item.getAsJsonObject("DisplayClaims")
                        .getAsJsonArray("xui")
                        .get(0)
                        .getAsJsonObject()
                        .get("uhs")
                        .getAsString();
                return new XstsTokenData(token, uhs);
            }
        } catch (RuntimeException malformed) {
            throw new AuthFlowException(
                    "Invalid redirect: accessToken is not a token bundle", FailureReason.INVALID_TOKEN);
        }

        throw new AuthFlowException("Invalid redirect: No Minecraft token in accessToken", FailureReason.INVALID_TOKEN);
    }

    /** {@return the first index of either character in {@code text}, or -1 if it holds neither} */
    private static int indexOfAny(String text, char first, char second) {
        int a = text.indexOf(first);
        int b = text.indexOf(second);
        if (a == -1) return b;
        if (b == -1) return a;
        return Math.min(a, b);
    }

    /**
     * Decodes {@code %XX} escapes and nothing else.
     *
     * @param text the percent-encoded text
     * @return the decoded text
     * @throws IllegalArgumentException if an escape is truncated or not hexadecimal
     */
    private static String percentDecode(String text) {
        if (text.indexOf('%') == -1) return text;

        ByteArrayOutputStream out = new ByteArrayOutputStream(text.length());
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c != '%') {
                out.write(c);
                continue;
            }
            if (i + 2 >= text.length()) throw new IllegalArgumentException("truncated escape");
            out.write(Integer.parseInt(text.substring(i + 1, i + 3), 16));
            i += 2;
        }
        return out.toString(StandardCharsets.UTF_8);
    }

    /**
     * Exchanges the XSTS token for a Minecraft services access token.
     *
     * @param xstsData the extracted XSTS data
     * @param loginUrl the Minecraft services login-with-Xbox endpoint
     * @param scope what the request is for, and on whose behalf
     * @return the Minecraft services bearer token
     * @throws AuthFlowException if Minecraft services reject the identity token or cannot be reached
     */
    private String authenticateWithMinecraft(XstsTokenData xstsData, String loginUrl, NetworkScope scope) {
        JsonObject body = new JsonObject();
        body.addProperty("identityToken", "XBL3.0 x=" + xstsData.uhs() + ";" + xstsData.token());
        body.addProperty("ensureLegacyEnabled", true);

        HttpTransport.HttpResponse response;
        try {
            response = http.sendForStatus(
                    "POST",
                    loginUrl,
                    "application/json",
                    null,
                    body.toString().getBytes(StandardCharsets.UTF_8),
                    scope);
        } catch (Exception transportFailure) {
            throw MicrosoftAuthUtil.unreachable("Minecraft services auth", transportFailure);
        }
        if (!response.successful()) {
            throw MicrosoftAuthUtil.stepFailure("Minecraft services auth", response);
        }
        JsonObject json = response.body();
        if (json == null
                || !json.has("access_token")
                || !json.get("access_token").isJsonPrimitive()) {
            throw MicrosoftAuthUtil.unexpected("Minecraft services auth", null);
        }
        return json.get("access_token").getAsString();
    }

    /**
     * Fetches the Minecraft profile data (username and UUID) for the given token.
     *
     * @param mcToken the Minecraft services access token
     * @param profileUrl the Minecraft services profile endpoint
     * @param scope what the request is for, and on whose behalf
     * @return the populated {@link MinecraftProfile}
     * @throws AuthFlowException if the profile could not be retrieved
     */
    private MinecraftProfile getMinecraftProfile(String mcToken, String profileUrl, NetworkScope scope) {
        AccountNetworkUtil.ProfileLookup lookup;
        try {
            lookup = profiles.fetchProfile(mcToken, profileUrl, scope);
        } catch (Exception transportFailure) {
            throw MicrosoftAuthUtil.unreachable("Profile fetch", transportFailure);
        }
        if (lookup.missingProfile()) {
            throw new AuthFlowException("This account has no Minecraft profile", FailureReason.NOT_ENTITLED);
        }
        if (!lookup.found()) {
            throw lookup.status() >= 200 && lookup.status() < 300
                    ? MicrosoftAuthUtil.unexpected("Profile fetch", null)
                    : MicrosoftAuthUtil.stepFailure("Profile fetch", lookup.status());
        }
        return new MinecraftProfile(lookup.username(), AuthFormats.dashedUuid(lookup.uuid()), mcToken, null, 0L);
    }

    /** Internal data structure for XSTS token information. */
    record XstsTokenData(String token, String uhs) {

        // Together these are the identity token Minecraft services accept.
        @Override
        public String toString() {
            return "XstsTokenData[token=<redacted>, uhs=<redacted>]";
        }
    }
}

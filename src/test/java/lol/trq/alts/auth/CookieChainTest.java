package lol.trq.alts.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import lol.trq.alts.auth.AltLoginCallback.FailureReason;
import lol.trq.alts.auth.MicrosoftAuthUtil.AuthFlowException;
import lol.trq.alts.net.HttpUtil;
import lol.trq.alts.net.NetTestHooks;
import lol.trq.alts.net.NetworkScope;
import lol.trq.alts.net.ProxyRoute;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * What the cookie route does with the cookies it is handed. An export is usually the whole browser's
 * jar, so the route has to decide which cookies to keep and which requests they may ride on, rather than
 * sending everything to wherever each redirect points.
 */
class CookieChainTest {

    private static final String FULL_BROWSER_EXPORT = """
            # Netscape HTTP Cookie File
            .login.live.com\tTRUE\t/\tTRUE\t0\tMSPOK\tlive-one
            .example.net\tTRUE\t/\tTRUE\t0\tsessionid\tother-site-session
            .live.com\tTRUE\t/\tTRUE\t0\tMSPCID\tlive-two
            #HttpOnly_login.live.com\tFALSE\t/\tTRUE\t0\t__Host-MSAAUTHP\tlive-three
            bank.example\tFALSE\t/\tTRUE\t0\tauth\tbank-session
            notlive.com\tFALSE\t/\tTRUE\t0\ttrick\tsuffix-trick
            live.com.evil.example\tFALSE\t/\tTRUE\t0\ttrick2\tprefix-trick
            """;

    private static final String LANDING = "https://www.minecraft.net/en-us/login#state=login&accessToken=";

    private static final String BUNDLE =
            "[{\"Item1\":\"rp://api.minecraftservices.com/\",\"Item2\":{\"Token\":\"xsts-token\","
                    + "\"DisplayClaims\":{\"xui\":[{\"uhs\":\"hash\"}]}}}]";

    @AfterEach
    void tearDown() {
        // Static, so leaving a provider installed would route every later test through it.
        NetTestHooks.resetHttp();
    }

    private static String landing() {
        return LANDING + Base64.getEncoder().encodeToString(BUNDLE.getBytes(StandardCharsets.UTF_8));
    }

    /** A scripted chain: each URL maps to where it redirects, and every request is recorded. */
    private static final class ScriptedHops implements CookieAuthUtil.RedirectFetcher {
        private final Map<String, String> redirects = new LinkedHashMap<>();
        private final Map<String, String> cookiesSent = new LinkedHashMap<>();
        private final List<String> fetched = new ArrayList<>();
        private String firstHopTarget;

        @Override
        public String location(String url, String cookieHeader) {
            fetched.add(url);
            cookiesSent.put(url, cookieHeader);
            // The first hop is the library's own SISU address; everything after is scripted.
            return fetched.size() == 1 ? firstHopTarget : redirects.get(url);
        }
    }

    @Test
    void onlyLiveComCookiesSurviveAFullBrowserExport() {
        String header = CookieAuthUtil.parseCookies(FULL_BROWSER_EXPORT);

        assertTrue(header.contains("MSPOK=live-one"), header);
        assertTrue(header.contains("MSPCID=live-two"), header);
        assertFalse(header.contains("other-site-session"), "another site's session must not be sent: " + header);
        assertFalse(header.contains("bank-session"), header);
        assertFalse(header.contains("suffix-trick"), "notlive.com is not a subdomain of live.com: " + header);
        assertFalse(header.contains("prefix-trick"), "live.com.evil.example is not live.com: " + header);
    }

    @Test
    void anHttpOnlyLineIsACookieNotAComment() {
        String header = CookieAuthUtil.parseCookies(FULL_BROWSER_EXPORT);

        assertTrue(header.contains("__Host-MSAAUTHP=live-three"), header);
    }

    @Test
    void aJsonExportIsFilteredByItsDomainFieldToo() {
        String json = """
                [{"domain":".login.live.com","name":"MSPOK","value":"live-one"},
                 {"domain":".example.net","name":"sessionid","value":"other-site-session"},
                 {"host":"shop.example","name":"cart","value":"shop-session"}]
                """;

        String header = CookieAuthUtil.parseCookies(json);

        assertEquals("MSPOK=live-one;", header);
    }

    @Test
    void anExportHoldingNoLiveComCookieIsRejectedRatherThanSent() {
        String others = """
                # Netscape HTTP Cookie File
                .example.net\tTRUE\t/\tTRUE\t0\tsessionid\tone
                .example.org\tTRUE\t/\tTRUE\t0\tsessionid\ttwo
                bank.example\tFALSE\t/\tTRUE\t0\tauth\tthree
                """;

        assertThrows(IllegalArgumentException.class, () -> CookieAuthUtil.parseCookies(others));
    }

    @Test
    void cookiesAreOnlyAttachedToHostsTheirDomainCovers() {
        List<CookieAuthUtil.Cookie> cookies = CookieAuthUtil.parseCookieList(FULL_BROWSER_EXPORT);

        assertNull(CookieAuthUtil.cookieHeaderFor("sisu.xboxlive.com", cookies));
        assertNull(CookieAuthUtil.cookieHeaderFor("login.microsoftonline.com", cookies));
        assertNull(CookieAuthUtil.cookieHeaderFor("login.live.com.evil.example", cookies));
        assertNull(CookieAuthUtil.cookieHeaderFor("notlive.com", cookies));

        String login = CookieAuthUtil.cookieHeaderFor("login.live.com", cookies);
        assertTrue(login.contains("MSPOK=live-one") && login.contains("MSPCID=live-two"), login);

        String sibling = CookieAuthUtil.cookieHeaderFor("account.live.com", cookies);
        assertEquals("MSPCID=live-two;", sibling, "a login.live.com cookie is not sent to a sibling host");
    }

    @Test
    void theChainIsFollowedToTheRedirectThatCarriesTheToken() throws Exception {
        ScriptedHops hops = new ScriptedHops();
        hops.firstHopTarget = "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize?x=a b";
        hops.redirects.put(
                "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize?x=a%20b",
                "https://login.live.com/oauth20_authorize.srf?y=1");
        hops.redirects.put(
                "https://login.live.com/oauth20_authorize.srf?y=1", "https://sisu.xboxlive.com/callback?code=abc");
        hops.redirects.put("https://sisu.xboxlive.com/callback?code=abc", landing());

        String result = CookieAuthUtil.followChain(CookieAuthUtil.parseCookieList(FULL_BROWSER_EXPORT), hops);

        assertEquals(landing(), result);
        assertEquals(4, hops.fetched.size(), "all four hops are requested: " + hops.fetched);
        assertTrue(hops.fetched.get(0).startsWith("https://sisu.xboxlive.com/"), hops.fetched.get(0));

        assertNull(hops.cookiesSent.get(hops.fetched.get(0)), "SISU gets no cookies on the way in");
        assertNull(hops.cookiesSent.get(hops.fetched.get(1)), "the identity platform is not live.com");
        assertTrue(hops.cookiesSent.get(hops.fetched.get(2)).contains("MSPOK=live-one"), "live.com signs in");
        assertNull(hops.cookiesSent.get(hops.fetched.get(3)), "SISU gets no cookies on the way out");
    }

    @Test
    void aShorterOrLongerChainStillEndsAtTheToken() throws Exception {
        ScriptedHops shorter = new ScriptedHops();
        shorter.firstHopTarget = "https://sisu.xboxlive.com/callback?code=abc";
        shorter.redirects.put("https://sisu.xboxlive.com/callback?code=abc", landing());

        assertEquals(landing(), CookieAuthUtil.followChain(List.of(), shorter));
        assertEquals(2, shorter.fetched.size());
    }

    @Test
    void aTokenIsAcceptedOnlyFromTheServiceThatStartedTheSignIn() {
        ScriptedHops hops = new ScriptedHops();
        hops.firstHopTarget = "https://login.live.com/a";
        hops.redirects.put("https://login.live.com/a", "https://elsewhere.example/open-redirect");
        hops.redirects.put("https://elsewhere.example/open-redirect", landing());

        AuthFlowException failure =
                assertThrows(AuthFlowException.class, () -> CookieAuthUtil.followChain(List.of(), hops));

        assertFalse(
                failure.getMessage().contains("accessToken"),
                "a bundle handed over by a host that is not the issuer is refused, and not quoted");

        ScriptedHops live = new ScriptedHops();
        live.firstHopTarget = "https://login.live.com/a";
        live.redirects.put("https://login.live.com/a", landing());

        assertThrows(
                AuthFlowException.class,
                () -> CookieAuthUtil.followChain(List.of(), live),
                "not even a host the chain legitimately visits may end it");
    }

    @Test
    void aRedirectRelativeToTheCurrentPathIsResolvedAgainstIt() throws Exception {
        ScriptedHops hops = new ScriptedHops();
        hops.firstHopTarget = "https://login.live.com/oauth/start?x=1";
        hops.redirects.put("https://login.live.com/oauth/start?x=1", "continue?step=2");
        hops.redirects.put("https://login.live.com/oauth/continue?step=2", "../finish");
        hops.redirects.put("https://login.live.com/finish", "//sisu.xboxlive.com/callback?code=abc");
        hops.redirects.put("https://sisu.xboxlive.com/callback?code=abc", landing());

        assertEquals(landing(), CookieAuthUtil.followChain(List.of(), hops));
        assertEquals(
                List.of(
                        "https://login.live.com/oauth/start?x=1",
                        "https://login.live.com/oauth/continue?step=2",
                        "https://login.live.com/finish",
                        "https://sisu.xboxlive.com/callback?code=abc"),
                hops.fetched.subList(1, hops.fetched.size()),
                "a Location is relative to the address that sent it, with or without a leading slash");
    }

    @Test
    void aRedirectOffHttpsStopsTheChainBeforeAnythingIsSentThere() {
        ScriptedHops hops = new ScriptedHops();
        hops.firstHopTarget = "https://login.live.com/a";
        hops.redirects.put("https://login.live.com/a", "http://login.live.com/downgraded");

        AuthFlowException failure = assertThrows(
                AuthFlowException.class,
                () -> CookieAuthUtil.followChain(CookieAuthUtil.parseCookieList(FULL_BROWSER_EXPORT), hops));

        assertFalse(hops.fetched.contains("http://login.live.com/downgraded"), "the plain-HTTP hop is never requested");
        assertFalse(failure.getMessage().contains("downgraded"), "the message does not carry the address");
    }

    @Test
    void aChainThatNeverProducesATokenIsARejectedCredential() {
        CookieAuthUtil.RedirectFetcher loop = (url, cookies) -> "https://login.live.com/signin";

        AuthFlowException failure =
                assertThrows(AuthFlowException.class, () -> CookieAuthUtil.followChain(List.of(), loop));

        assertEquals(FailureReason.INVALID_TOKEN, failure.reason());
    }

    @Test
    void theTailOfTheFlowUsesTheConfiguredEndpointsAndCarriesTheAccount() throws Exception {
        List<NetworkScope> scopes = new ArrayList<>();
        HttpUtil.bind(scope -> {
            scopes.add(scope);
            return ProxyRoute.direct();
        });

        try (AuthChainServer chain = new AuthChainServer()) {
            NetworkScope account = NetworkScope.forAccount(NetworkScope.Purpose.AUTH, AuthChainServer.UUID, "Alex");

            MinecraftProfile profile = CookieAuthUtil.completeFromLanding(landing(), chain.config(), account);

            assertEquals("Alex", profile.username());
            assertEquals(AuthChainServer.UUID, profile.uuid());
            assertEquals("mc-access", profile.accessToken(), "the token came from the configured login endpoint");
            assertEquals(1, chain.profileCalls(), "the profile came from the configured profile endpoint");
        }

        assertEquals(2, scopes.size());
        assertEquals(NetworkScope.Purpose.AUTH, scopes.get(0).purpose());
        assertEquals(NetworkScope.Purpose.PROFILE, scopes.get(1).purpose());
        for (NetworkScope scope : scopes) {
            assertEquals(AuthChainServer.UUID, scope.accountUuid());
        }
    }

    @Test
    void theTailClassifiesAnOutageAndAThrottleApartFromARefusal() throws Exception {
        try (AuthChainServer chain = new AuthChainServer()) {
            chain.fail("/mclogin", 503);
            assertEquals(FailureReason.NETWORK, tailFailure(chain).reason());

            chain.fail("/mclogin", 429);
            assertEquals(FailureReason.RATE_LIMITED, tailFailure(chain).reason());

            chain.fail("/mclogin", 401);
            assertEquals(FailureReason.INVALID_TOKEN, tailFailure(chain).reason());

            chain.fail("/mclogin", 200);
            chain.fail("/mcprofile", 404);
            assertEquals(FailureReason.NOT_ENTITLED, tailFailure(chain).reason());
        }
    }

    private static AuthFlowException tailFailure(AuthChainServer chain) {
        return assertThrows(
                AuthFlowException.class, () -> CookieAuthUtil.completeFromLanding(landing(), chain.config(), null));
    }

    @Test
    void theRecordsHoldingCredentialsDoNotPrintThem() {
        String cookie = new CookieAuthUtil.Cookie("login.live.com", "MSPOK", "live-one").toString();
        String xsts = new CookieAuthUtil.XstsTokenData("xsts-token", "user-hash").toString();

        assertFalse(cookie.contains("live-one"), cookie);
        assertFalse(xsts.contains("xsts-token") || xsts.contains("user-hash"), xsts);
    }
}

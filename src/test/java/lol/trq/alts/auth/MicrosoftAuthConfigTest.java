package lol.trq.alts.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class MicrosoftAuthConfigTest {

    @Test
    void ofFillsEveryDefault() {
        MicrosoftAuthConfig config = MicrosoftAuthConfig.of("my-azure-app");

        assertEquals("my-azure-app", config.clientId());
        assertEquals(MicrosoftAuthConfig.DEFAULT_SCOPE, config.scope());
        assertEquals(MicrosoftAuthConfig.DEFAULT_REDIRECT_PATH, config.redirectPath());
        assertEquals(MicrosoftAuthConfig.DEFAULT_AUTHORIZE_URL, config.authorizeUrl());
        assertEquals(MicrosoftAuthConfig.DEFAULT_TOKEN_URL, config.tokenUrl());
        assertEquals(MicrosoftAuthConfig.DEFAULT_XBOX_LIVE_AUTH_URL, config.xboxLiveAuthUrl());
        assertEquals(MicrosoftAuthConfig.DEFAULT_XSTS_AUTH_URL, config.xstsAuthUrl());
        assertEquals(MicrosoftAuthConfig.DEFAULT_MINECRAFT_LOGIN_URL, config.minecraftLoginUrl());
        assertEquals(MicrosoftAuthConfig.DEFAULT_MINECRAFT_PROFILE_URL, config.minecraftProfileUrl());
    }

    /**
     * The default loopback path is pinned literally: an Azure app registration lists it as a redirect, so a
     * change breaks every host that relies on the default, and it names no product or tool.
     */
    @Test
    void theDefaultRedirectPathIsTheNeutralOne() {
        assertEquals(
                "/lol_trq_alts_loopback_redirect_long_enough_to_avoid_accidental_leaks_on_screenshare",
                MicrosoftAuthConfig.DEFAULT_REDIRECT_PATH);
        assertEquals(
                MicrosoftAuthConfig.DEFAULT_REDIRECT_PATH,
                MicrosoftAuthConfig.of("app").redirectPath(),
                "of() listens on the default path");
    }

    @Test
    void requiresClientId() {
        assertThrows(IllegalArgumentException.class, () -> MicrosoftAuthConfig.of(null));
        assertThrows(IllegalArgumentException.class, () -> MicrosoftAuthConfig.of("  "));
    }

    @Test
    void blankOptionalsFallBackToDefaults() {
        MicrosoftAuthConfig config = MicrosoftAuthConfig.of("app")
                .withScope("  ")
                .withRedirectPath(null)
                .withRedirectUri("  ")
                .withRpsTicketPrefix("  ");
        assertEquals(MicrosoftAuthConfig.DEFAULT_SCOPE, config.scope());
        assertEquals(MicrosoftAuthConfig.DEFAULT_REDIRECT_PATH, config.redirectPath());
        assertEquals(MicrosoftAuthConfig.DEFAULT_RPS_TICKET_PREFIX, config.rpsTicketPrefix());
        assertNull(config.redirectUri(), "a blank redirect uri must normalize to absent, not to empty");
    }

    @Test
    void ofTargetsAModernOAuthApp() {
        MicrosoftAuthConfig config = MicrosoftAuthConfig.of("my-azure-app");

        assertNull(config.redirectUri(), "the OAuth refresh grant carries no redirect uri");
        assertEquals(MicrosoftAuthConfig.DEFAULT_RPS_TICKET_PREFIX, config.rpsTicketPrefix());
    }

    @Test
    void legacyMsaFillsTheLegacyDefaults() {
        MicrosoftAuthConfig config = MicrosoftAuthConfig.legacyMsa("legacy-app-id");

        assertEquals("legacy-app-id", config.clientId());
        assertEquals(MicrosoftAuthConfig.LEGACY_MSA_SCOPE, config.scope());
        assertEquals(MicrosoftAuthConfig.LEGACY_MSA_REDIRECT_URI, config.redirectUri());
        assertEquals(MicrosoftAuthConfig.LEGACY_MSA_RPS_TICKET_PREFIX, config.rpsTicketPrefix());
        assertEquals(
                MicrosoftAuthConfig.DEFAULT_TOKEN_URL,
                config.tokenUrl(),
                "a legacy app still redeems at the standard endpoint");
    }

    @Test
    void withClientIdKeepsEverythingElse() {
        MicrosoftAuthConfig config = MicrosoftAuthConfig.legacyMsa("first").withClientId("second");

        assertEquals("second", config.clientId());
        assertEquals(MicrosoftAuthConfig.LEGACY_MSA_SCOPE, config.scope());
        assertEquals(MicrosoftAuthConfig.LEGACY_MSA_REDIRECT_URI, config.redirectUri());
        assertEquals(MicrosoftAuthConfig.LEGACY_MSA_RPS_TICKET_PREFIX, config.rpsTicketPrefix());
    }

    @Test
    void withScopeAndRedirectPathOverride() {
        MicrosoftAuthConfig config =
                MicrosoftAuthConfig.of("app").withScope("custom.scope").withRedirectPath("/cb");
        assertEquals("custom.scope", config.scope());
        assertEquals("/cb", config.redirectPath());
        assertEquals("app", config.clientId());
    }

    @Test
    void theRefreshGrantRedirectAndTicketPrefixHaveTheirOwnCopies() {
        MicrosoftAuthConfig config = MicrosoftAuthConfig.of("app")
                .withRedirectUri(MicrosoftAuthConfig.LEGACY_MSA_REDIRECT_URI)
                .withRpsTicketPrefix(MicrosoftAuthConfig.LEGACY_MSA_RPS_TICKET_PREFIX)
                .withScope(MicrosoftAuthConfig.LEGACY_MSA_SCOPE);

        assertEquals(MicrosoftAuthConfig.legacyMsa("app"), config, "the legacy dialect, built by hand");
        assertEquals(MicrosoftAuthConfig.legacyMsa("app").hashCode(), config.hashCode());
        assertNull(config.withRedirectUri(null).redirectUri());
        assertEquals("app", config.withRpsTicketPrefix("x=").clientId());
        assertEquals("x=", config.withRpsTicketPrefix("x=").rpsTicketPrefix());
    }

    @Test
    void aConfigIsAValueOverEveryField() {
        MicrosoftAuthConfig config = MicrosoftAuthConfig.of("app");

        assertEquals(MicrosoftAuthConfig.of("app"), config);
        assertNotEquals(config, config.withClientId("other"));
        assertNotEquals(config, config.withDeviceCodeEndpoints("https://id.example/code", null));
        assertTrue(config.toString().startsWith("MicrosoftAuthConfig[clientId=app, scope="), config::toString);
        assertTrue(
                config.toString().endsWith(", deviceTokenUrl=" + MicrosoftAuthConfig.DEFAULT_DEVICE_TOKEN_URL + "]"),
                config::toString);
    }

    @Test
    void withEndpointsOverridesAllSix() {
        MicrosoftAuthConfig config = MicrosoftAuthConfig.of("app").withEndpoints("a", "t", "xbl", "xsts", "mcl", "mcp");
        assertEquals("a", config.authorizeUrl());
        assertEquals("t", config.tokenUrl());
        assertEquals("xbl", config.xboxLiveAuthUrl());
        assertEquals("xsts", config.xstsAuthUrl());
        assertEquals("mcl", config.minecraftLoginUrl());
        assertEquals("mcp", config.minecraftProfileUrl());
    }
}

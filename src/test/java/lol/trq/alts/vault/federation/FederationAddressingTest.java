package lol.trq.alts.vault.federation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import lol.trq.alts.vault.MemberPublicKey;
import org.junit.jupiter.api.Test;

class FederationAddressingTest {

    @Test
    void repoAddressRoundTripsThroughUri() {
        RepoAddress address = new RepoAddress("vault.example:8443", "11111111-2222-3333-4444-555555555555");
        assertEquals("avp://vault.example:8443/11111111-2222-3333-4444-555555555555", address.toUri());
        assertEquals(address, RepoAddress.parse(address.toUri()));
    }

    @Test
    void repoAddressRejectsMalformed() {
        assertThrows(IllegalArgumentException.class, () -> RepoAddress.parse("https://host/repo"));
        assertThrows(IllegalArgumentException.class, () -> RepoAddress.parse("avp://hostonly"));
        assertThrows(IllegalArgumentException.class, () -> RepoAddress.parse("avp:///repo"));
        assertThrows(IllegalArgumentException.class, () -> RepoAddress.parse("avp://host/"));
        assertThrows(IllegalArgumentException.class, () -> new RepoAddress("", "repo"));
    }

    @Test
    void inviteRequestRoundTripsAsToken() {
        MemberPublicKey member = new MemberPublicKey("ed25519-b64", "x25519-b64");
        InviteRequest invite = InviteRequest.forMember(member);

        InviteRequest decoded = InviteRequest.decode(invite.encode());

        assertEquals(InviteRequest.VERSION, decoded.version());
        assertEquals(member, decoded.toMemberPublicKey());
    }

    @Test
    void inviteRequestRejectsMalformedToken() {
        assertThrows(IllegalArgumentException.class, () -> InviteRequest.decode("!!!not-base64!!!"));
        assertThrows(
                IllegalArgumentException.class,
                () -> InviteRequest.decode(java.util.Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString("{\"v\":1}".getBytes(java.nio.charset.StandardCharsets.UTF_8))));
    }

    @Test
    void repoLocatorRoundTripsAndYieldsAddress() {
        RepoAddress address = new RepoAddress("vault.example", "repo-9");
        RepoLocator locator = RepoLocator.of(address, "X25519-HKDF-SHA256-AESGCM-v1", 3L, "https://idp.example/jwks");

        RepoLocator decoded = RepoLocator.decode(locator.encode());

        assertEquals(address, decoded.toRepoAddress());
        assertEquals("X25519-HKDF-SHA256-AESGCM-v1", decoded.schemeId());
        assertEquals(3L, decoded.keyEpoch());
        assertEquals("https://idp.example/jwks", decoded.issuerJwksUrl());
    }

    @Test
    void repoLocatorAllowsNullIssuer() {
        RepoLocator locator = RepoLocator.of(new RepoAddress("h", "r"), "scheme", 0L, null);
        RepoLocator decoded = RepoLocator.decode(locator.encode());
        assertNull(decoded.issuerJwksUrl());
        assertEquals("avp://h/r", decoded.toRepoAddress().toUri());
    }

    @Test
    void repoAddressRejectsUserinfoInTheHost() {
        // A naive resolver would connect to evil.example while the address reads as good.example.
        assertThrows(IllegalArgumentException.class, () -> RepoAddress.parse("avp://good.example@evil.example/x"));
        assertThrows(IllegalArgumentException.class, () -> new RepoAddress("good.example@evil.example", "x"));
        assertThrows(IllegalArgumentException.class, () -> new RepoAddress("user:pw@vault.example", "x"));
    }

    @Test
    void repoAddressRejectsHostsThatAreNotAPlainAuthority() {
        for (String host : new String[] {
            " ",
            "vault.example ",
            "vault example",
            "vault..example",
            ".vault.example",
            "vault.example.",
            "-vault.example",
            "vault-.example",
            "vault_host.example",
            "vault.example?x=1",
            "vault.example#frag",
            "vault.example\\evil.example",
            "vault.example%2e",
            "vault.example:",
            "vault.example:0",
            "vault.example:65536",
            "vault.example:80:80",
            "vault.example:8o",
            "[::1",
            "[]",
            "[vault.example]",
            "[::1]8443",
            "[::1]:",
            "b\u00fccher.example",
            "vault.example\n"
        }) {
            assertThrows(IllegalArgumentException.class, () -> new RepoAddress(host, "repo"), host);
        }
    }

    @Test
    void repoAddressAcceptsNamesAddressesAndPorts() {
        for (String host : new String[] {
            "h",
            "localhost",
            "vault.example",
            "Vault.Example",
            "xn--bcher-kva.example",
            "a-b.c-d.example:1",
            "vault.example:65535",
            "192.0.2.10",
            "192.0.2.10:8443",
            "[::1]",
            "[2001:db8::1]:8443",
            "[::ffff:192.0.2.10]"
        }) {
            assertEquals(host, RepoAddress.parse("avp://" + host + "/repo").host());
        }
    }

    @Test
    void repoAddressValidatesTheRepoIdSegment() {
        for (String repoId : new String[] {
            " ", "a b", "a/b", "..", ".", "a?b", "a#b", "a@b", "a%2fb", "a\\b", "a\tb", "r\u00e9po", "x".repeat(257)
        }) {
            assertThrows(IllegalArgumentException.class, () -> new RepoAddress("vault.example", repoId), repoId);
        }
        assertThrows(IllegalArgumentException.class, () -> RepoAddress.parse("avp://vault.example/a/b"));
        assertEquals("Repo_9.v2~x-1", new RepoAddress("vault.example", "Repo_9.v2~x-1").repoId());
        assertEquals("x".repeat(256), new RepoAddress("vault.example", "x".repeat(256)).repoId());
    }

    @Test
    void repoLocatorRejectsATokenNamingAnUnsafeHost() {
        String json = "{\"v\":1,\"host\":\"good.example@evil.example\",\"repoId\":\"x\",\"keyEpoch\":0}";
        String token = java.util.Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(json.getBytes(java.nio.charset.StandardCharsets.UTF_8));

        assertThrows(IllegalArgumentException.class, () -> RepoLocator.decode(token));
    }
}

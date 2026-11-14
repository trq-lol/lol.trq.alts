package lol.trq.alts.internal.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.net.URI;
import org.junit.jupiter.api.Test;

/** The origin a cached token is bound to besides the host key (SPEC 3.3). */
class HostClientOriginTest {

    private static String origin(String url) {
        return HostClient.origin(URI.create(url));
    }

    @Test
    void theOriginIsLowerCasedWithTheDefaultPortSpelledOut() {
        assertEquals("http://vault.example:80", origin("HTTP://Vault.Example"));
        assertEquals("https://vault.example:443", origin("https://vault.example"));
        assertEquals("https://vault.example:443", origin("https://vault.example:443/"));
        assertEquals("http://vault.example:8787", origin("http://vault.example:8787"));
    }

    @Test
    void anIpv6LiteralKeepsItsBrackets() {
        assertEquals("http://[fe80::1]:9000", origin("http://[FE80::1]:9000"));
        assertEquals("https://[::1]:443", origin("https://[::1]"));
    }

    @Test
    void thePathQueryAndUserInfoDoNotCount() {
        assertEquals("https://vault.example:8443", origin("https://vault.example:8443/base/path?q=1#f"));
        assertEquals("http://vault.example:81", origin("http://user:secret@vault.example:81/x"));
    }
}

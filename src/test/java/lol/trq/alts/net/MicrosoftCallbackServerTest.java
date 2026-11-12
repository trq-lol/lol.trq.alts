package lol.trq.alts.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import lol.trq.alts.auth.AltLoginCallback.FailureReason;
import lol.trq.alts.auth.MicrosoftAuthConfig;
import lol.trq.alts.auth.MicrosoftAuthUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The loopback redirect listener. Any page open in the user's browser can send a request to a loopback
 * port, so what matters here is which requests are allowed to decide a pending login: only one carrying
 * the state that login generated.
 */
class MicrosoftCallbackServerTest {

    private static final String STATE = "expected-state";
    private static final String PATH = "/callback";

    private MicrosoftCallbackServer server;
    private CompletableFuture<String> code;
    private final AtomicReference<String> opened = new AtomicReference<>();

    @BeforeEach
    void setUp() {
        MicrosoftAuthConfig config = MicrosoftAuthConfig.of("test-client-id").withRedirectPath(PATH);
        server = new MicrosoftCallbackServer(STATE, config, "challenge-value", opened::set);
        code = server.start();
    }

    @AfterEach
    void tearDown() {
        server.stop();
    }

    private int port() {
        return URI.create(server.redirectUri()).getPort();
    }

    private int get(String query) throws IOException {
        String url = "http://127.0.0.1:" + port() + PATH + (query == null ? "" : "?" + query);
        HttpURLConnection connection =
                (HttpURLConnection) URI.create(url).toURL().openConnection();
        connection.setConnectTimeout(5_000);
        connection.setReadTimeout(5_000);
        try {
            return connection.getResponseCode();
        } finally {
            connection.disconnect();
        }
    }

    @Test
    void theMatchingRedirectCompletesTheLoginWithTheDecodedCode() throws Exception {
        assertEquals(200, get("code=M.C5%2B1_abc%3D&state=" + STATE));

        assertEquals("M.C5+1_abc=", code.get(5, TimeUnit.SECONDS), "the code is decoded exactly once");
    }

    @Test
    void aRequestWithTheWrongStateIsRefusedAndTheLoginKeepsWaiting() throws Exception {
        assertEquals(400, get("code=attacker-code&state=guessed"));

        assertFalse(code.isDone(), "a request without this login's state must not decide it");

        assertEquals(200, get("code=real-code&state=" + STATE));
        assertEquals("real-code", code.get(5, TimeUnit.SECONDS));
    }

    @Test
    void aRequestWithNoParametersIsRefusedAndTheLoginKeepsWaiting() throws Exception {
        assertEquals(400, get(null));
        assertEquals(400, get(""));
        assertEquals(400, get("state="));

        assertFalse(code.isDone());

        assertEquals(200, get("code=real-code&state=" + STATE));
        assertEquals("real-code", code.get(5, TimeUnit.SECONDS));
    }

    @Test
    void aMatchingStateWithoutACodeIsRefusedAndTheLoginKeepsWaiting() throws Exception {
        assertEquals(400, get("state=" + STATE));
        assertEquals(400, get("code=&state=" + STATE));

        assertFalse(code.isDone());
    }

    @Test
    void anErrorCodeParameterIsNotMistakenForTheCode() throws Exception {
        assertEquals(400, get("error_code=12345&state=" + STATE));
        assertFalse(code.isDone(), "error_code= is a different parameter from code=");

        assertEquals(200, get("error_code=12345&code=real-code&state=" + STATE));
        assertEquals("real-code", code.get(5, TimeUnit.SECONDS));
    }

    @Test
    void aStatedRefusalVouchedForByTheStateFailsTheLoginAsDeclined() throws Exception {
        assertEquals(400, get("error=access_denied&error_description=nope&state=" + STATE));

        ExecutionException failure = assertThrows(ExecutionException.class, () -> code.get(5, TimeUnit.SECONDS));
        MicrosoftAuthUtil.AuthFlowException classified =
                assertInstanceOf(MicrosoftAuthUtil.AuthFlowException.class, failure.getCause());
        assertEquals(FailureReason.DECLINED, classified.reason());
    }

    @Test
    void aRefusalWithoutTheStateCannotFailTheLogin() throws Exception {
        assertEquals(400, get("error=access_denied&state=guessed"));

        assertFalse(code.isDone());
    }

    @Test
    void theQueryIsParsedIntoWholeDecodedParameters() {
        Map<String, String> params =
                MicrosoftCallbackServer.parseQuery("error_code=1&code=a%26b&state=s%20t&flag&code=second&=x");

        assertEquals("a&b", params.get("code"), "an encoded ampersand stays inside its value");
        assertEquals("s t", params.get("state"));
        assertEquals("1", params.get("error_code"));
        assertEquals("", params.get("flag"));
        assertTrue(MicrosoftCallbackServer.parseQuery(null).isEmpty());
        assertTrue(MicrosoftCallbackServer.parseQuery("").isEmpty());
        assertFalse(MicrosoftCallbackServer.parseQuery("code=%zz&state=ok").containsKey("code"));
    }

    @Test
    void theAuthorizationAddressCarriesThePkceChallengeAndTheState() {
        String url = opened.get();

        assertTrue(url.startsWith(MicrosoftAuthConfig.DEFAULT_AUTHORIZE_URL + "?"), url);
        assertTrue(url.contains("code_challenge=challenge-value"), url);
        assertTrue(url.contains("code_challenge_method=S256"), url);
        assertTrue(url.contains("state=" + STATE), url);
        assertEquals(url, server.authorizationUrl());
    }

    /**
     * The redirect names localhost, and the browser decides which address that is. Whichever it picks,
     * the request has to reach this server rather than nothing, or some other program on that port.
     */
    @Test
    void theRedirectReachesTheServerOnEveryAddressLocalhostResolvesTo() throws Exception {
        for (InetAddress address : InetAddress.getAllByName("localhost")) {
            String host = address instanceof java.net.Inet6Address
                    ? "[" + address.getHostAddress() + "]"
                    : address.getHostAddress();
            HttpURLConnection connection = (HttpURLConnection)
                    URI.create("http://" + host + ":" + port() + PATH).toURL().openConnection(java.net.Proxy.NO_PROXY);
            connection.setConnectTimeout(5_000);
            connection.setReadTimeout(5_000);
            try {
                assertEquals(400, connection.getResponseCode(), "no answer from the callback server on " + address);
            } finally {
                connection.disconnect();
            }
        }
    }

    @Test
    void theIpv6LoopbackCarriesTheRedirectToo() throws Exception {
        InetAddress v6 = InetAddress.getByName("::1");
        try (java.net.ServerSocket probe = new java.net.ServerSocket()) {
            probe.bind(new InetSocketAddress(v6, 0));
        } catch (IOException noIpv6) {
            assumeTrue(false, "this system has no IPv6 loopback");
        }

        HttpURLConnection connection =
                (HttpURLConnection) URI.create("http://[::1]:" + port() + PATH + "?code=real-code&state=" + STATE)
                        .toURL()
                        .openConnection(java.net.Proxy.NO_PROXY);
        connection.setConnectTimeout(5_000);
        connection.setReadTimeout(5_000);

        assertEquals(200, connection.getResponseCode());
        assertEquals("real-code", code.get(5, TimeUnit.SECONDS));
    }

    @Test
    void theListenerIsBoundToLoopbackOnly() throws Exception {
        InetAddress external = firstNonLoopbackAddress();
        assumeTrue(external != null, "needs a non-loopback interface to prove the listener is not on it");

        assertThrows(IOException.class, () -> {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(external, port()), 2_000);
            }
        });
    }

    @Test
    void cancellingTheFutureStopsTheServerAndReleasesThePort() throws Exception {
        int port = port();
        assertFalse(canBind(port), "the port is held while the login is pending");

        assertTrue(code.cancel(true));

        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (!canBind(port)) {
            assertTrue(System.nanoTime() < deadline, "the port was still held long after cancellation");
            Thread.sleep(10);
        }
    }

    @Test
    void completingTheLoginAlsoReleasesThePort() throws Exception {
        int port = port();
        assertEquals(200, get("code=real-code&state=" + STATE));
        code.get(5, TimeUnit.SECONDS);

        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (!canBind(port)) {
            assertTrue(System.nanoTime() < deadline, "the port was still held after the code arrived");
            Thread.sleep(10);
        }
    }

    private static boolean canBind(int port) {
        try (ServerSocket socket = new ServerSocket(port, 1, InetAddress.getLoopbackAddress())) {
            return true;
        } catch (IOException inUse) {
            return false;
        }
    }

    private static InetAddress firstNonLoopbackAddress() throws IOException {
        for (NetworkInterface nic : Collections.list(NetworkInterface.getNetworkInterfaces())) {
            if (!nic.isUp() || nic.isLoopback()) {
                continue;
            }
            for (InetAddress address : Collections.list(nic.getInetAddresses())) {
                if (address instanceof java.net.Inet4Address && !address.isLoopbackAddress()) {
                    return address;
                }
            }
        }
        return null;
    }
}

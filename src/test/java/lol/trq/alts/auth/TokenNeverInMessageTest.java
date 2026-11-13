package lol.trq.alts.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import com.sun.net.httpserver.HttpServer;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import lol.trq.alts.model.AccountType;
import lol.trq.alts.model.AltAccount;
import lol.trq.alts.model.LoginMode;
import lol.trq.alts.net.TestTransports;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * A failure message goes to the host's UI and its log, so no token may ever be part of one. The case
 * that used to break this is the most ordinary one there is: a token pasted with a line break in it.
 */
class TokenNeverInMessageTest {

    private static final String HEAD = "eyJhbGciOiJIUzI1NiJ9.secret-head";
    private static final String TAIL = "secret-tail.signature";

    @TempDir
    Path vaultDir;

    private AccountStoreTestSupport localStore;

    private HttpServer server;
    private MicrosoftAuthConfig config;
    private final List<String> authorizations = new CopyOnWriteArrayList<>();

    @BeforeEach
    void setUp() throws Exception {
        localStore = AccountStoreTestSupport.openIn(vaultDir);
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", exchange -> {
            authorizations.add(String.valueOf(exchange.getRequestHeaders().getFirst("Authorization")));
            byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(401, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
        String base = "http://" + InetAddress.getLoopbackAddress().getHostAddress() + ":"
                + server.getAddress().getPort();
        config = MicrosoftAuthConfig.of("test-client-id")
                .withEndpoints(
                        base + "/authorize",
                        base + "/token",
                        base + "/xbl",
                        base + "/xsts",
                        base + "/mclogin",
                        base + "/mcprofile");
    }

    @AfterEach
    void tearDown() {
        localStore.close();
        server.stop(0);
    }

    private static void assertNoToken(String message) {
        assertFalse(String.valueOf(message).contains("secret-"), "a token reached a message: " + message);
    }

    @Test
    void aSessionTokenPastedWithALineBreakNeverReachesTheResultMessage() throws Exception {
        for (String breaker : new String[] {"\n", "\r\n", " \n ", "\t"}) {
            LoginResult result = new AltLoginServiceImpl(
                            localStore.store(), session -> {}, config, TestTransports.direct())
                    .loginSession(HEAD + breaker + TAIL, LoginMode.ADD)
                    .get();

            assertFalse(result.success());
            assertNoToken(result.message());
        }
    }

    @Test
    void aTokenWrappedAcrossLinesIsSentAsTheOneTokenItIs() throws Exception {
        new AltLoginServiceImpl(localStore.store(), session -> {}, config, TestTransports.direct())
                .loginSession("Bearer " + HEAD + "\r\n" + TAIL + "\n", LoginMode.ADD)
                .get();

        assertEquals(
                List.of("Bearer " + HEAD + TAIL), authorizations, "the break belongs to the paste, not to the token");
    }

    @Test
    void aStoredTokenHoldingALineBreakNeverReachesTheStatusMessage() throws Exception {
        AltAccount account =
                AltAccount.of("00000000-0000-4000-8000-0000000000e1", "Alex", HEAD + "\n" + TAIL, AccountType.SESSION);

        AccountStatus status = new AltAccountServiceImpl(
                        localStore.store(), config, TestTransports.direct(), Clock.systemUTC())
                .check(account)
                .get();

        assertFalse(status.usable());
        assertNoToken(status.message());
        assertEquals(List.of(), authorizations, "and no request is sent with a header a line break could split");
    }

    @Test
    void aRefreshTokenPastedWithALineBreakNeverReachesTheResultMessage() throws Exception {
        LoginResult result = new AltLoginServiceImpl(localStore.store(), session -> {}, config, TestTransports.direct())
                .loginRefreshToken("M.C5_secret-head\nsecret-tail", LoginMode.ADD)
                .get();

        assertFalse(result.success());
        assertNoToken(result.message());
    }
}

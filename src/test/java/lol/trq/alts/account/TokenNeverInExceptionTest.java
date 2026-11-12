package lol.trq.alts.account;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The account services are built over a token the caller supplies as is. Whatever is wrong with that
 * token, no exception they throw may carry it: not in its message and not anywhere down its cause chain.
 */
class TokenNeverInExceptionTest {

    private static final String TOKEN = "eyJhbGciOiJIUzI1NiJ9.secret-head\nsecret-tail.signature";

    private LoopbackServices server;
    private AccountServices services;

    @BeforeEach
    void start() throws Exception {
        server = new LoopbackServices();
        services = AccountServices.of(TOKEN, "11111111-2222-3333-4444-555555555555", server.endpoints());
    }

    @AfterEach
    void stop() {
        server.close();
    }

    private static void assertNoToken(Throwable failure) {
        for (Throwable link = failure; link != null; link = link.getCause()) {
            assertFalse((link.getMessage() + " " + link).contains("secret-"), "a token reached an exception: " + link);
        }
    }

    @Test
    void aReadWithATokenHoldingALineBreakFailsWithoutQuotingIt() {
        assertNoToken(
                assertThrows(AccountException.class, () -> services.profile().fetch()));
        assertNoToken(assertThrows(
                AccountException.class, () -> services.entitlements().fetch()));
        assertNoToken(assertThrows(AccountException.class, () -> services.name().eligibility()));
        assertEquals(0, server.requests().size(), "nothing is sent with a header a line break could split");
    }

    @Test
    void aNameChangeWithSuchATokenFailsWithoutQuotingIt() {
        assertNoToken(assertThrows(AccountException.class, () -> services.name().change("Alex")));
        assertEquals(0, server.requests().size());
    }
}

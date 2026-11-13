package lol.trq.alts.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Optional;
import lol.trq.alts.AltsFailure;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.model.AccountType;
import lol.trq.alts.model.AltAccount;
import org.junit.jupiter.api.Test;

/** A sign-in result is exactly one of a success carrying its account or a failure carrying its kind. */
class LoginResultReasonTest {

    private static final AltAccount ACCOUNT = AltAccount.of("u", "Alex", "tok", AccountType.MICROSOFT);

    @Test
    void successCarriesNoFailure() {
        LoginResult result = LoginResult.success(ACCOUNT);

        assertTrue(result.success());
        assertEquals(Optional.empty(), result.failure());
        assertEquals(ACCOUNT, result.account());
    }

    @Test
    void aFailureCarriesItsKindAndNoAccount() {
        LoginResult result = LoginResult.failure(Kind.REAUTH_REQUIRED, "refresh token rejected");

        assertFalse(result.success());
        assertNull(result.account());
        assertEquals(Kind.REAUTH_REQUIRED, result.failure().orElseThrow().kind());
        assertEquals(result.failure().orElseThrow().message(), result.message(), "the message is the failure's");
    }

    @Test
    void aResultIsNeverBothOrNeither() {
        AltsFailure failure = AltsFailure.of(Kind.UNKNOWN, "m");
        assertThrows(IllegalArgumentException.class, () -> new LoginResult(ACCOUNT, Optional.of(failure)));
        assertThrows(NullPointerException.class, () -> new LoginResult(null, Optional.empty()));
        assertThrows(NullPointerException.class, () -> new LoginResult(ACCOUNT, null));
    }
}

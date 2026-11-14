package lol.trq.alts.bulk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Optional;
import lol.trq.alts.AltsFailure;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.model.AccountType;
import lol.trq.alts.model.AltAccount;
import org.junit.jupiter.api.Test;

/** A result is a success with its account or a failure without one, and a value over every field. */
class BulkEntryResultTest {

    private static final AltAccount ALEX = AltAccount.builder(
                    "00000000-0000-4000-8000-0000000000e1", "Alex", "secret-access", AccountType.MICROSOFT)
            .build();

    @Test
    void aSuccessCarriesItsAccountAndNoFailure() {
        BulkEntryResult ok = BulkEntryResult.success(2, ALEX, "valid", 1);

        assertTrue(ok.success());
        assertEquals(Optional.empty(), ok.failure());
        assertEquals("Alex", ok.label());
        assertEquals(ALEX, ok.account());
        assertNull(ok.entitlements());
        assertThrows(NullPointerException.class, () -> BulkEntryResult.success(0, null, "valid", 1));
    }

    @Test
    void aFailureCarriesItsMessageAndNoAccount() {
        AltsFailure failure = AltsFailure.of(Kind.NETWORK, "Check: the service is unreachable");
        BulkEntryResult failed = BulkEntryResult.failure(3, BulkEntryResult.positionalLabel(3), failure, 2);

        assertFalse(failed.success());
        assertEquals(Optional.of(failure), failed.failure());
        assertEquals(failure.message(), failed.message());
        assertEquals("entry 4", failed.label());
        assertNull(failed.account());
        assertEquals(2, failed.attempts());
        assertThrows(NullPointerException.class, () -> BulkEntryResult.failure(0, "entry 1", null, 1));
    }

    @Test
    void aResultIsAValueWhoseDescriptionKeepsTheTokenOut() {
        BulkEntryResult ok = BulkEntryResult.success(2, ALEX, "valid", 1);

        assertEquals(BulkEntryResult.success(2, ALEX, "valid", 1), ok);
        assertEquals(BulkEntryResult.success(2, ALEX, "valid", 1).hashCode(), ok.hashCode());
        assertNotEquals(BulkEntryResult.success(2, ALEX, "valid", 2), ok);
        assertTrue(ok.toString().startsWith("BulkEntryResult[index=2, label=Alex, account=AltAccount["));
        assertFalse(ok.toString().contains("secret-access"), ok::toString);
    }
}

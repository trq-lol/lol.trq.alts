package lol.trq.alts.internal.account;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.concurrent.atomic.AtomicBoolean;
import lol.trq.alts.account.AccountEndpoints;
import lol.trq.alts.account.AccountServices;
import lol.trq.alts.account.ProfileLookupService;
import lol.trq.alts.internal.ChildFirstLoader;
import lol.trq.alts.net.HttpTransport;
import org.junit.jupiter.api.Test;

/**
 * The account bridge sees every access token the runtime builds services over, so only the account
 * package's own bridge may be installed: a foreign one, one of the right name from another loader, and a
 * second install are all refused.
 */
class AccountAccessTest {

    @Test
    void aForeignBridgeIsRefused() {
        AtomicBoolean reached = new AtomicBoolean();
        AccountAccess.Bridge foreign = new AccountAccess.Bridge() {
            @Override
            public AccountServices services(
                    HttpTransport transport, String token, String accountUuid, AccountEndpoints endpoints) {
                reached.set(true);
                return null;
            }

            @Override
            public ProfileLookupService profileLookup(HttpTransport transport, AccountEndpoints endpoints) {
                reached.set(true);
                return null;
            }
        };

        // Refused as foreign, not merely as late: the check does not depend on what was installed first.
        assertThrows(IllegalArgumentException.class, () -> AccountAccess.install(foreign));
        assertNotSame(foreign, AccountAccess.bridge());
        assertFalse(reached.get());
    }

    @Test
    void aBridgeOfTheRightNameFromAnotherClassLoaderIsRefused() {
        String bridgeName = "lol.trq.alts.account.AccountBridge";
        ClassLoader foreign = new ChildFirstLoader(AccountAccessTest.class.getClassLoader(), bridgeName);

        ExceptionInInitializerError refused =
                assertThrows(ExceptionInInitializerError.class, () -> Class.forName(bridgeName, true, foreign));

        assertInstanceOf(IllegalArgumentException.class, refused.getCause());
        assertNotSame(foreign, AccountAccess.bridge().getClass().getClassLoader());
    }

    @Test
    void theLibrarysOwnBridgeIsNotInstalledTwice() {
        AccountAccess.Bridge installed = AccountAccess.bridge();

        assertThrows(IllegalStateException.class, () -> AccountAccess.install(installed));
    }
}

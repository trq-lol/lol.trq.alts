package lol.trq.alts.bulk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import lol.trq.alts.AltsRuntime;
import lol.trq.alts.model.AccountType;
import lol.trq.alts.model.AltAccount;
import lol.trq.alts.model.LoginMode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * An import resolves and stores credentials without moving the live session, and so without moving the
 * store's current account either: that pointer is what a host shows as "the account you are on". It
 * belongs to the host's own sign-ins, including one the user makes while an import is running, which an
 * import must neither overwrite nor "restore" away when it ends. Nor does an import stamp an account as
 * used: nobody played on it.
 */
@org.junit.jupiter.api.Timeout(value = 60, unit = TimeUnit.SECONDS)
class ImportCurrentAccountTest {

    @TempDir
    Path dir;

    private AltsRuntime<Object> runtime() {
        return new AltsRuntime.Builder<Object>()
                .sessionInjector(session -> {})
                .vaultDirectory(() -> dir)
                .mainThread(Runnable::run)
                .toastSink((level, title, description, durationMs) -> {})
                .build();
    }

    private static String offlineUuid(String name) {
        return UUID.nameUUIDFromBytes(("OfflinePlayer:" + name).getBytes(StandardCharsets.UTF_8))
                .toString();
    }

    @Test
    void aSignInTheUserMakesWhileAnImportRunsIsStillCurrentWhenItEnds() throws Exception {
        try (AltsRuntime<Object> alts = runtime()) {
            AltAccount chosen = AltAccount.of(
                    "00000000-0000-4000-8000-00000000c0de", "Chosen", "chosen-access", AccountType.MICROSOFT);
            List<Optional<AltAccount>> seenDuringTheRun = new CopyOnWriteArrayList<>();
            BulkProgress userSignsInMidway = new BulkProgress() {
                @Override
                public void started(int index, int total, String label) {
                    if (index == 0) {
                        // The user picks an account in the host while the import works through its list.
                        alts.store().useAccount(chosen);
                    }
                }

                @Override
                public void completed(int index, int total, BulkEntryResult result) {
                    seenDuringTheRun.add(alts.store().currentAccount());
                }
            };

            BulkReport report = alts.bulk()
                    .importCredentials(
                            List.of("Alex", "Steve", "Notch"),
                            LoginMode.ADD,
                            BulkOptions.defaults().withConcurrency(1),
                            userSignsInMidway)
                    .report()
                    .get(30, TimeUnit.SECONDS);

            assertEquals(3, report.succeeded());
            assertEquals(3, alts.store().accounts().size(), "the import stored what it resolved");
            for (Optional<AltAccount> current : seenDuringTheRun) {
                assertEquals(chosen.uuid(), current.map(AltAccount::uuid).orElse(null), "never moved by the import");
            }
            assertEquals(
                    chosen.uuid(),
                    alts.store().currentAccount().map(AltAccount::uuid).orElse(null),
                    "the user's choice is current when the import ends, not what was current before it");
        }
    }

    @Test
    void anImportNeitherMakesAnAccountCurrentNorStampsItAsUsed() throws Exception {
        try (AltsRuntime<Object> alts = runtime()) {
            AltAccount saved = AltAccount.of(offlineUuid("Alex"), "Alex", "", AccountType.OFFLINE);
            alts.store().addAccount(saved);
            Thread.sleep(25);

            BulkReport report = alts.bulk()
                    .importCredentials(List.of("Alex"), LoginMode.ADD, BulkOptions.defaults(), BulkProgress.NONE)
                    .report()
                    .get(30, TimeUnit.SECONDS);

            assertEquals(1, report.succeeded());
            assertTrue(alts.store().currentAccount().isEmpty(), "an import makes nothing current");
            AltAccount stored = alts.store().accounts().get(0);
            assertEquals(saved.lastUsed(), stored.lastUsed(), "importing a saved account again is not using it");
        }
    }
}

package lol.trq.alts;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.List;
import lol.trq.alts.model.AccountType;
import lol.trq.alts.model.AltAccount;
import lol.trq.alts.net.NetTestHooks;
import lol.trq.alts.spi.StoreKeyProvider;
import lol.trq.alts.store.StoreTestHooks;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * A runtime built with a store key seals both of its stores under it, and never leaves either readable
 * under the machine-derived key, except through the explicit one-launch migration.
 */
class AltsRuntimeStoreKeyTest {

    private static final String UUID = "00000000-0000-4000-8000-0000000000d1";
    private static final StoreKeyProvider HOST_KEY = () -> "0123456789abcdef0123456789abcdef".getBytes();

    @TempDir
    Path dir;

    @AfterEach
    void resetNetworkStatics() {
        NetTestHooks.resetHttp();
        NetTestHooks.resetExecutor();
    }

    private AltsRuntime.Builder<Object> builder() {
        return new AltsRuntime.Builder<Object>()
                .sessionInjector(session -> {})
                .vaultDirectory(() -> dir)
                .mainThread(Runnable::run)
                .toastSink((level, title, description, durationMs) -> {});
    }

    private static boolean holds(AltsRuntime<?> alts, String uuid) {
        return alts.store().accounts().stream().anyMatch(account -> uuid.equals(account.uuid()));
    }

    @Test
    void bothStoresAreSealedUnderTheHostKey() throws Exception {
        try (AltsRuntime<Object> alts = builder().storeKeyProvider(HOST_KEY).build()) {
            alts.store().addAccount(AltAccount.of(UUID, "Alex", "access", AccountType.MICROSOFT));
            alts.secrets().put("feature.api-key", "value");
        }

        assertEquals(
                List.of(),
                StoreTestHooks.filesOpeningUnderMachineKey(dir, "lol.trq.alts"),
                "no account file may come out sealed under the machine key");
        assertEquals(List.of(), StoreTestHooks.filesOpeningUnderMachineKey(dir, "lol.trq.alts.secrets"));

        try (AltsRuntime<Object> alts = builder().storeKeyProvider(HOST_KEY).build()) {
            assertTrue(alts.store().loadError().isEmpty());
            assertTrue(holds(alts, UUID));
            assertEquals("value", alts.secrets().get("feature.api-key"));
        }
    }

    @Test
    void storesFromBeforeTheKeyProviderMigrateOnlyWhenTheHostOptsIn() throws Exception {
        try (AltsRuntime<Object> alts = builder().build()) {
            alts.store().addAccount(AltAccount.of(UUID, "Alex", "access", AccountType.MICROSOFT));
            alts.secrets().put("feature.api-key", "value");
        }

        try (AltsRuntime<Object> alts = builder().storeKeyProvider(HOST_KEY).build()) {
            assertTrue(
                    alts.store().loadError().isPresent(), "without the opt-in a machine-keyed store is not accepted");
            assertTrue(alts.secrets().loadError().isPresent());
            assertFalse(holds(alts, UUID));
        }

        try (AltsRuntime<Object> alts =
                builder().storeKeyProvider(HOST_KEY).migrateFromMachineKey(true).build()) {
            alts.store().flush();
            alts.secrets().flush();

            assertTrue(alts.store().loadError().isEmpty());
            assertTrue(holds(alts, UUID), "the upgrade launch carries the accounts over");
            assertEquals("value", alts.secrets().get("feature.api-key"));
        }
        assertEquals(List.of(), StoreTestHooks.filesOpeningUnderMachineKey(dir, "lol.trq.alts"));
        assertEquals(List.of(), StoreTestHooks.filesOpeningUnderMachineKey(dir, "lol.trq.alts.secrets"));
    }
}

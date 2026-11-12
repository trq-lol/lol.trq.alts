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
import lol.trq.alts.store.AltStore;
import lol.trq.alts.store.SecretStore;
import lol.trq.alts.store.StoreTestHooks;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The store key is process-wide, like the stores themselves. Building a runtime must never leave either
 * store readable or writable under the machine-derived key once a host has supplied its own.
 */
class AltsRuntimeStoreKeyTest {

    private static final String UUID = "00000000-0000-4000-8000-0000000000d1";
    private static final String OTHER_UUID = "00000000-0000-4000-8000-0000000000d2";
    private static final StoreKeyProvider HOST_KEY = () -> "0123456789abcdef0123456789abcdef".getBytes();

    @TempDir
    Path dir;

    @BeforeEach
    void startClean() {
        StoreTestHooks.reset();
    }

    @AfterEach
    void settle() {
        AltStore.flush();
        AltStore.writeDelay(null);
        SecretStore.flush();
        SecretStore.writeDelay(null);
        StoreTestHooks.reset();
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

    private static boolean holds(String uuid) {
        return AltStore.accounts().stream().anyMatch(account -> uuid.equals(account.uuid()));
    }

    @Test
    void aSecondRuntimeWithoutAKeyProviderDoesNotRewriteTheStoreUnderTheMachineKey() throws Exception {
        builder().storeKeyProvider(HOST_KEY).build();
        AltStore.addAccount(AltAccount.of(UUID, "Alex", "access", AccountType.MICROSOFT));
        SecretStore.put("feature.api-key", "value");
        AltStore.flush();
        SecretStore.flush();

        builder().build();

        assertTrue(AltStore.loadError().isEmpty(), "the second runtime still reads the host-keyed store");
        assertTrue(SecretStore.loadError().isEmpty());
        assertTrue(holds(UUID));

        AltStore.addAccount(AltAccount.of(OTHER_UUID, "Steve", "b", AccountType.OFFLINE));
        SecretStore.put("feature.other-key", "value");
        AltStore.flush();
        SecretStore.flush();

        assertEquals(
                List.of(),
                StoreTestHooks.filesOpeningUnderMachineKey(dir, "lol.trq.alts"),
                "no account file may come out sealed under the machine key");
        assertEquals(List.of(), StoreTestHooks.filesOpeningUnderMachineKey(dir, "lol.trq.alts.secrets"));
    }

    @Test
    void storesFromBeforeTheKeyProviderMigrateOnlyWhenTheHostOptsIn() throws Exception {
        builder().build();
        AltStore.addAccount(AltAccount.of(UUID, "Alex", "access", AccountType.MICROSOFT));
        SecretStore.put("feature.api-key", "value");
        AltStore.flush();
        SecretStore.flush();
        StoreTestHooks.reset();

        builder().storeKeyProvider(HOST_KEY).build();

        assertTrue(AltStore.loadError().isPresent(), "without the opt-in a machine-keyed store is not accepted");
        assertTrue(SecretStore.loadError().isPresent());
        assertFalse(holds(UUID));

        StoreTestHooks.reset();
        builder().storeKeyProvider(HOST_KEY).migrateFromMachineKey(true).build();
        AltStore.flush();
        SecretStore.flush();

        assertTrue(AltStore.loadError().isEmpty());
        assertTrue(holds(UUID), "the upgrade launch carries the accounts over");
        assertEquals("value", SecretStore.get("feature.api-key"));
        assertEquals(List.of(), StoreTestHooks.filesOpeningUnderMachineKey(dir, "lol.trq.alts"));
        assertEquals(List.of(), StoreTestHooks.filesOpeningUnderMachineKey(dir, "lol.trq.alts.secrets"));
    }
}

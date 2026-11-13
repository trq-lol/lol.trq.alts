package lol.trq.alts.auth;

import java.nio.file.Path;
import lol.trq.alts.model.AltAccount;
import lol.trq.alts.store.AccountStore;

/**
 * An {@link AccountStore} of a test's own, in a scratch directory, so login tests can hand it to the
 * service under test and assert on what was persisted. Writes are synchronous. Close it after the test:
 * it holds its store file locked.
 */
final class AccountStoreTestSupport implements AutoCloseable {

    private final AccountStore store;

    private AccountStoreTestSupport(AccountStore store) {
        this.store = store;
    }

    static AccountStoreTestSupport openIn(Path directory) {
        AccountStore store = AccountStore.open(directory);
        store.load();
        return new AccountStoreTestSupport(store);
    }

    AccountStore store() {
        return store;
    }

    void seed(AltAccount account) {
        store.addAccount(account);
    }

    /**
     * Re-reads the encrypted store from disk before looking the account up, so an assertion can tell a
     * persisted change from one that only ever touched the in-memory list.
     */
    AltAccount reloadFromDiskAndFind(String uuid) {
        store.accounts().clear();
        store.load();
        return find(uuid);
    }

    AltAccount find(String uuid) {
        return store.accounts().stream()
                .filter(a -> a.uuid().equals(uuid))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no stored account with uuid " + uuid));
    }

    @Override
    public void close() {
        store.close();
    }
}

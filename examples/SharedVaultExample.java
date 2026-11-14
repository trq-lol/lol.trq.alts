import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CompletionException;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure;
import lol.trq.alts.AltsRuntime;
import lol.trq.alts.model.AltAccount;
import lol.trq.alts.store.HostSecrets;
import lol.trq.alts.vault.InviteToken;
import lol.trq.alts.vault.OwnerIdentity;
import lol.trq.alts.vault.RepoLocator;
import lol.trq.alts.vault.SharedVault;
import lol.trq.alts.vault.SyncReport;
import lol.trq.alts.vault.VaultHost;
import lol.trq.alts.vault.VaultIdentity;
import lol.trq.alts.vault.VaultMember;
import lol.trq.alts.vault.VaultSnapshot;

/**
 * The AVP 0.5 shared vault, end to end: the owner creates a repository, a member joins it through two
 * pasted tokens, and both sync. Illustrative only, nothing here is executed; each method blocks on its
 * futures, so a host runs it off its main thread. The host-secret keys are the host's own choice.
 *
 * <p>Compiled by the {@code examples} source set with {@code -Xlint:deprecation -Werror}, so it cannot drift
 * from the library API or teach a deprecated one.
 */
public final class SharedVaultExample {

    private static final String OWNER_ENTROPY = "vault.owner.entropy";
    private static final String SNAPSHOT = "vault.snapshot";

    private SharedVaultExample() {}

    /**
     * The owner creates a repository on its home host, keeps the owner key and the snapshot in the host
     * secrets, and returns the repo locator text to give a joiner.
     *
     * @param alts the runtime
     * @param homeHost the owner's home host, {@code host} or {@code host:port}
     * @return the repo locator text
     */
    public static String createRepository(AltsRuntime<?> alts, String homeHost) {
        HostSecrets secrets = alts.secrets();
        OwnerIdentity owner = OwnerIdentity.generate();
        showOnce(owner.phrase()); // the owner writes it down: it is the only way back to the owner key
        byte[] entropy = owner.entropy();
        try {
            secrets.put(OWNER_ENTROPY, Base64.getEncoder().encodeToString(entropy));
        } finally {
            Arrays.fill(entropy, (byte) 0);
        }

        // A first contact: nobody vouched for this host's key yet, so show it to compare out of band. From
        // here on the snapshot and every token carry it, and each later connection pins it.
        VaultHost home = alts.vault().connectFirstContact(homeHost).join();
        showOnce("Vault host key: " + home.hostKey());
        SharedVault vault = SharedVault.create(home, owner).join();
        secrets.put(SNAPSHOT, vault.snapshot().toJson());
        return vault.locator().text();
    }

    /**
     * The joiner's first step: from the pasted repo locator, ask the owner's home host to carry the
     * repository for this member, and return the invite token text to give the owner.
     *
     * @param alts the runtime
     * @param member this device's identity
     * @param pastedLocator the repo locator text the owner sent
     * @return the invite token text
     */
    public static String requestInvite(AltsRuntime<?> alts, VaultIdentity member, String pastedLocator) {
        RepoLocator locator = RepoLocator.parse(pastedLocator);
        VaultHost home = alts.vault().connect(locator).join(); // matched by the locator's host key
        InviteToken token = SharedVault.prepareJoin(home, member, locator).join();
        return token.text();
    }

    /**
     * The owner invites the member whose invite token was pasted, after comparing its fingerprint with the
     * one the member's device shows.
     *
     * @param alts the runtime
     * @param pastedInvite the invite token text the joiner sent
     * @param fingerprintTheMemberSees the fingerprint the joiner read out
     */
    public static void invite(AltsRuntime<?> alts, String pastedInvite, String fingerprintTheMemberSees) {
        InviteToken token = InviteToken.parse(pastedInvite);
        if (!token.fingerprint().equals(fingerprintTheMemberSees)) {
            return; // not the person the owner meant to invite
        }
        SharedVault vault = resumeOwner(alts);
        vault.invite(token).join();
        alts.secrets().put(SNAPSHOT, vault.snapshot().toJson());
    }

    /**
     * The joiner's last step, once invited: join, read the accounts, and keep the snapshot.
     *
     * @param alts the runtime
     * @param member this device's identity
     * @param pastedLocator the repo locator text the owner sent
     * @return the shared accounts
     */
    public static List<AltAccount> join(AltsRuntime<?> alts, VaultIdentity member, String pastedLocator) {
        RepoLocator locator = RepoLocator.parse(pastedLocator);
        VaultHost home = alts.vault().connect(locator).join();
        SharedVault vault = SharedVault.join(home, member, locator).join();
        alts.secrets().put(SNAPSHOT, vault.snapshot().toJson());
        return vault.accounts();
    }

    /**
     * The owner, on a later run: resume from the snapshot, share a new account, renew the tokens of one it
     * shares, sync, and act on what the sync reports. {@code update} edits the account as the copy holds it
     * when the write runs, so a field another member changed meanwhile is never reverted.
     *
     * @param alts the runtime
     * @param account a new account to share
     * @param renewed an account the repository holds, freshly renewed
     */
    public static void shareAndSync(AltsRuntime<?> alts, AltAccount account, AltAccount renewed) {
        SharedVault vault = resumeOwner(alts);
        try {
            vault.put(account).join();
            vault.update(
                            renewed.uuid(),
                            held -> held.withTokens(renewed.accessToken(), renewed.refreshToken(), renewed.expiresAt()))
                    .join();
            SyncReport report = vault.sync().join();
            if (report.policyTurnedOn()) {
                showOnce("This repository now shares refresh tokens.");
            }
            report.divergedAt().ifPresent(seq -> showOnce("Two owner devices diverged at state " + seq));
            List<VaultMember> leaving = vault.processLeaves().join();
            leaving.forEach(m -> showOnce("Removed " + m.fingerprint() + ", who left"));
        } catch (CompletionException e) {
            AltsFailure failure = ((AltsException) e.getCause()).failure();
            if (failure.kind() == AltsFailure.Kind.PROTOCOL) {
                showOnce("The vault host served something that does not verify: " + failure.message());
            }
        } finally {
            alts.secrets().put(SNAPSHOT, vault.snapshot().toJson());
        }
    }

    private static SharedVault resumeOwner(AltsRuntime<?> alts) {
        HostSecrets secrets = alts.secrets();
        byte[] entropy = Base64.getDecoder().decode(secrets.get(OWNER_ENTROPY));
        OwnerIdentity owner;
        try {
            owner = OwnerIdentity.fromEntropy(entropy);
        } finally {
            Arrays.fill(entropy, (byte) 0);
        }
        VaultSnapshot snapshot = VaultSnapshot.fromJson(secrets.get(SNAPSHOT));
        VaultHost home = alts.vault().connect(snapshot).join(); // the home host, by the key it had
        return SharedVault.resume(home, owner, snapshot).join();
    }

    /** Stand-in for the host's own UI. */
    private static void showOnce(String text) {}
}

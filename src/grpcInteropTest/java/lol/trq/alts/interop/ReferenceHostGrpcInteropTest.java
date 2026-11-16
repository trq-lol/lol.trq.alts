package lol.trq.alts.interop;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.net.URI;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import lol.trq.alts.AltsRuntime;
import lol.trq.alts.model.AccountType;
import lol.trq.alts.model.AltAccount;
import lol.trq.alts.vault.InviteToken;
import lol.trq.alts.vault.OwnerIdentity;
import lol.trq.alts.vault.RepoLocator;
import lol.trq.alts.vault.SharedVault;
import lol.trq.alts.vault.VaultHost;
import lol.trq.alts.vault.VaultIdentity;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The library against a running AVP reference host over the gRPC profile, through a grpc-java channel:
 * create, push, pull and prepareJoin. Skipped unless {@code AVP_GRPC_URL} names the host
 * ({@code grpc://127.0.0.1:<port>}), as the AVP harness's {@code run-hosts.sh} exports it.
 */
class ReferenceHostGrpcInteropTest {

    private static final String UUID_A = "0b5e7f2a-5d1c-4a6e-9c1e-1f0d4a7b3c21";

    @TempDir
    Path dir;

    private static <T> T await(CompletableFuture<T> f) throws Exception {
        return f.get(60, TimeUnit.SECONDS);
    }

    private AltsRuntime<Object> runtime(String name, GrpcJavaChannel channel) {
        return new AltsRuntime.Builder<Object>()
                .sessionInjector(session -> {})
                .vaultDirectory(() -> dir.resolve(name))
                .mainThread(Runnable::run)
                .toastSink((level, title, description, durationMs) -> {})
                .vaultHostAddress(locator -> URI.create("grpc://" + locator))
                .vaultRpcChannel(uri -> channel)
                .build();
    }

    @Test
    void createPushPullAndPrepareJoinOverGrpc() throws Exception {
        String url = System.getenv("AVP_GRPC_URL");
        assumeTrue(url != null && !url.isBlank(), "AVP_GRPC_URL is not set");
        URI target = URI.create(url.strip());
        assumeTrue("127.0.0.1".equals(target.getHost()), "loopback reference hosts only");
        String locator = target.getHost() + ":" + target.getPort();

        try (GrpcJavaChannel channel = new GrpcJavaChannel(target);
                AltsRuntime<Object> ownerSide = runtime("owner", channel);
                AltsRuntime<Object> memberSide = runtime("member", channel)) {
            VaultHost home = await(ownerSide.vault().connectFirstContact(locator));
            OwnerIdentity ownerId = OwnerIdentity.generate();
            SharedVault owner = await(SharedVault.create(home, ownerId));
            await(owner.put(AltAccount.builder(UUID_A, "Steve", "access-token-value", AccountType.MICROSOFT)
                    .build()));
            await(owner.sync());
            assertEquals(
                    List.of(UUID_A),
                    owner.accounts().stream().map(AltAccount::uuid).toList());

            VaultIdentity member = VaultIdentity.create("correct horse".toCharArray());
            RepoLocator repo = RepoLocator.parse(owner.locator().text());
            VaultHost memberHome = await(memberSide.vault().connect(repo));
            InviteToken invite = await(SharedVault.prepareJoin(memberHome, member, repo));
            await(owner.invite(invite));
            SharedVault joined = await(SharedVault.join(memberHome, member, repo));
            assertTrue(joined.account(UUID_A).isPresent(), "the member pulls what the owner pushed");

            SharedVault reopened =
                    await(SharedVault.open(await(ownerSide.vault().connect(repo)), ownerId, owner.repoId()));
            assertEquals(owner.accounts(), reopened.accounts());
        }
    }
}

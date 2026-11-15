package lol.trq.alts.internal.vault;

import static lol.trq.alts.internal.vault.VaultFixture.await;
import static lol.trq.alts.internal.vault.VaultFixture.failure;
import static lol.trq.alts.internal.vault.VaultFixture.field;
import static lol.trq.alts.internal.vault.VaultFixture.newOwner;
import static lol.trq.alts.internal.vault.VaultFixture.set;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.internal.avp.AvpBytes;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** The whole client over the gRPC wire, through a gateway channel in front of the honest test host. */
class VaultGrpcFlowTest {

    private VaultFixture fx;
    private GrpcGatewayChannel channel;

    @BeforeEach
    void start() throws Exception {
        fx = new VaultFixture();
        channel = new GrpcGatewayChannel(fx.host);
    }

    @AfterEach
    void stop() {
        channel.close();
        fx.close();
    }

    private HostClient grpc() {
        URI target = URI.create("grpc://127.0.0.1:" + fx.host.base().getPort());
        return HostClient.connect(
                fx.transport,
                new GrpcWire(fx.transport, target, channel),
                "127.0.0.1:" + fx.host.base().getPort(),
                null,
                fx.tokens,
                fx.clock);
    }

    private static Set<String> ids(List<byte[]> ids) {
        return ids.stream().map(AvpBytes::base64).collect(Collectors.toSet());
    }

    @Test
    void createPushPullRemoveAndLeaveOverGrpc() {
        VaultFixture.Owner o = newOwner();
        VaultEngine owner = await(VaultEngine.create(grpc(), o.keys(), fx.clock));
        set(owner, "username", "alice-alt");

        MemberKeys bobKeys = MemberKeys.generate();
        HostClient bobHome = grpc();
        await(owner.invite(await(VaultEngine.prepareJoin(bobHome, bobKeys, owner.repoId()))));
        VaultEngine bob = await(VaultEngine.join(bobHome, bobKeys, owner.locator(), fx.clock));
        assertEquals("alice-alt", field(bob.payload(), "username"));
        set(bob, "note", "from bob");
        await(owner.pull());
        assertEquals("from bob", field(owner.payload(), "note"));
        assertEquals(ids(fx.host.heads(owner.repoId())), ids(owner.heads()));

        MemberKeys carolKeys = MemberKeys.generate();
        HostClient carolHome = grpc();
        await(owner.invite(await(VaultEngine.prepareJoin(carolHome, carolKeys, owner.repoId()))));
        VaultEngine carol = await(VaultEngine.join(carolHome, carolKeys, owner.locator(), fx.clock));
        await(carol.leave());
        await(owner.pull());
        assertEquals(1, await(owner.processLeaves()).size());
        assertFalse(owner.tip().state().hasMember(carolKeys.ed25519Public()));

        await(owner.remove(bobKeys.ed25519Public()));
        assertEquals(Kind.UNAUTHORIZED, failure(bob.pull()).kind());

        // Everything written over gRPC reads back over HTTP/JSON with the same values.
        VaultEngine overHttp = await(VaultEngine.open(fx.connect(), o.member(), owner.repoId(), fx.clock));
        assertEquals("alice-alt", field(overHttp.payload(), "username"));
        assertEquals("from bob", field(overHttp.payload(), "note"));
        assertArrayEquals(owner.tipHash(), overHttp.tipHash());
        assertEquals(ids(owner.heads()), ids(overHttp.heads()));

        for (String rpc : List.of(
                "GetHostInfo",
                "Challenge",
                "Token",
                "CreateRepo",
                "Pull",
                "Push",
                "PublishManifest",
                "Leave",
                "PrepareJoin")) {
            assertTrue(channel.count("avp.Vault/" + rpc) > 0, rpc + " went over the channel");
        }
    }

    @Test
    void aRefusedTokenIsDroppedAndRemintedOnceOverGrpc() {
        VaultEngine owner = await(VaultEngine.create(grpc(), newOwner().keys(), fx.clock));
        long challenges = channel.count("avp.Vault/Challenge");
        AtomicInteger refusals = new AtomicInteger();
        fx.host.interceptor = (req, honest) -> req.header("Authorization") != null && refusals.getAndIncrement() == 0
                ? TestAvpHost.Response.error(401, "unauthorized", "forgotten")
                : honest.apply(req);
        set(owner, "username", "alice-alt");
        assertTrue(refusals.get() > 1, "the refused call was sent again");
        assertEquals(challenges + 1, channel.count("avp.Vault/Challenge"), "one extra challenge");
        assertEquals("alice-alt", field(owner.payload(), "username"));
    }

    @Test
    void missingParentsIsRetriedOverGrpc() {
        VaultEngine owner = await(VaultEngine.create(grpc(), newOwner().keys(), fx.clock));
        AtomicInteger pushes = new AtomicInteger();
        fx.host.interceptor = (req, honest) -> req.path().endsWith("/push") && pushes.getAndIncrement() == 0
                ? TestAvpHost.Response.error(422, "missing_parents", "fetching")
                : honest.apply(req);
        long before = channel.count("avp.Vault/Push");
        set(owner, "username", "alice-alt");
        assertEquals(2, channel.count("avp.Vault/Push") - before);
        assertEquals(ids(fx.host.heads(owner.repoId())), ids(owner.heads()));
    }
}

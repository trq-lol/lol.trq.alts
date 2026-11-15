package lol.trq.alts.internal.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import lol.trq.alts.internal.vault.HostWire.Answer;
import lol.trq.alts.internal.vault.HostWire.Op;
import org.junit.jupiter.api.Test;

/** The HTTP/JSON wire: every operation on its SPEC 10.2 route, the bearer only where it belongs. */
class HttpWireTest {

    private static final String REPO = "AAAAAAAAAAAAAAAAAAAAAA";

    @Test
    void routesEveryOpToItsSpecPath() throws Exception {
        try (VaultFixture fx = new VaultFixture()) {
            HttpWire wire = new HttpWire(fx.transport, fx.host.base());
            for (Op op : Op.values()) {
                String repo =
                        switch (op) {
                            case PULL, PUSH, PUBLISH_MANIFEST, LEAVE -> "a/b+c=";
                            default -> null;
                        };
                wire.call(op, repo, op == Op.DISCOVERY ? null : new JsonObject(), null);
            }
            List<String> seen = fx.host.requests().stream()
                    .map(r -> r.method() + " " + r.path())
                    .toList();
            assertEquals(
                    List.of(
                            "GET /.well-known/avp",
                            "POST /api/auth/keypair/challenge",
                            "POST /api/auth/keypair/token",
                            "POST /v1/repos",
                            "POST /v1/repos/a%2Fb%2Bc%3D/pull",
                            "POST /v1/repos/a%2Fb%2Bc%3D/push",
                            "POST /v1/repos/a%2Fb%2Bc%3D/manifest",
                            "POST /v1/repos/a%2Fb%2Bc%3D/leave",
                            "POST /v1/prepare-join"),
                    seen);
            assertEquals(HostClient.origin(fx.host.base()), wire.origin());
        }
    }

    @Test
    void sendsTheBearerOnlyOnAuthenticatedOps() throws Exception {
        try (VaultFixture fx = new VaultFixture()) {
            HttpWire wire = new HttpWire(fx.transport, fx.host.base());
            wire.call(Op.DISCOVERY, null, null, null);
            wire.call(Op.CHALLENGE, null, new JsonObject(), null);
            wire.call(Op.PULL, REPO, new JsonObject(), "tok-1");
            wire.call(Op.PREPARE_JOIN, null, new JsonObject(), "tok-2");
            List<TestAvpHost.Request> r = fx.host.requests();
            assertNull(r.get(0).header("Authorization"));
            assertNull(r.get(1).header("Authorization"));
            assertEquals("Bearer tok-1", r.get(2).header("Authorization"));
            assertEquals("Bearer tok-2", r.get(3).header("Authorization"));
        }
    }

    @Test
    void aBareErrorKeepsItsStatusWithoutACode() throws Exception {
        try (VaultFixture fx = new VaultFixture()) {
            fx.host.interceptor = (req, honest) -> new TestAvpHost.Response(400, "not json".getBytes(), Map.of());
            Answer a = new HttpWire(fx.transport, fx.host.base()).call(Op.PUSH, REPO, new JsonObject(), "t");
            assertEquals(400, a.status());
            assertEquals(Optional.empty(), a.code());
            assertEquals(JsonNull.INSTANCE, a.body());
        }
    }

    @Test
    void aCodedRefusalCarriesItsCodeAndWait() throws Exception {
        try (VaultFixture fx = new VaultFixture()) {
            fx.host.interceptor = (req, honest) -> new TestAvpHost.Response(
                    429, "{\"error\":\"slow\",\"code\":\"quota_exceeded\"}".getBytes(), Map.of("Retry-After", "7"));
            Answer a = new HttpWire(fx.transport, fx.host.base()).call(Op.PUSH, REPO, new JsonObject(), "t");
            assertEquals(429, a.status());
            assertEquals(Optional.of("quota_exceeded"), a.code());
            assertEquals(7, a.retryAfter().toSeconds());
            assertTrue(a.body().isJsonNull());
        }
    }
}

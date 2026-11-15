package lol.trq.alts.internal.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.internal.net.HttpTransport;
import lol.trq.alts.internal.net.TestTransports;
import lol.trq.alts.internal.vault.HostWire.Answer;
import lol.trq.alts.internal.vault.HostWire.Op;
import lol.trq.alts.internal.vault.rpc.ProtoJson;
import lol.trq.alts.net.ProxyRoute;
import lol.trq.alts.spi.VaultRpcChannel;
import lol.trq.alts.spi.VaultRpcChannel.Reply;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/** The gRPC wire against a scripted channel: framing, the status mapping, and every way a channel fails. */
class GrpcWireTest {

    private static final URI TARGET = URI.create("grpcs://vault.example");
    private static final String REPO = "AAAAAAAAAAAAAAAAAAAAAA";

    /** One call the wire made. */
    record Call(String method, byte[] request, Map<String, String> metadata, Duration deadline, Thread thread) {}

    /** A channel that records its calls and answers each with the next scripted future. */
    static final class Scripted implements VaultRpcChannel {
        final List<Call> calls = new ArrayList<>();
        volatile Supplier<CompletableFuture<Reply>> answer;
        volatile CompletableFuture<Reply> last;

        Scripted(Supplier<CompletableFuture<Reply>> answer) {
            this.answer = answer;
        }

        @Override
        public CompletableFuture<Reply> unary(
                String method, byte[] request, Map<String, String> metadata, Duration deadline) {
            synchronized (calls) {
                calls.add(new Call(method, request, Map.copyOf(metadata), deadline, Thread.currentThread()));
            }
            CompletableFuture<Reply> f = answer.get();
            last = f;
            return f;
        }

        Call only() {
            synchronized (calls) {
                assertEquals(1, calls.size());
                return calls.get(0);
            }
        }
    }

    private final HttpTransport transport = TestTransports.direct();

    @AfterEach
    void close() {
        transport.close();
    }

    private static Supplier<CompletableFuture<Reply>> replying(Reply r) {
        return () -> CompletableFuture.completedFuture(r);
    }

    private static Supplier<CompletableFuture<Reply>> okWith(String message, JsonObject json) {
        return replying(Reply.ok(ProtoJson.encode(message, json)));
    }

    private static JsonObject pushResponse() {
        JsonObject o = new JsonObject();
        o.addProperty("accepted", true);
        o.add("heads", new JsonArray());
        return o;
    }

    private static JsonObject pushBody() {
        JsonObject commit = new JsonObject();
        commit.addProperty("repoId", REPO);
        JsonObject body = new JsonObject();
        body.add("commit", commit);
        return body;
    }

    private GrpcWire wire(VaultRpcChannel channel) {
        return new GrpcWire(transport, TARGET, channel);
    }

    @Test
    void theBearerTravelsAsAuthorizationMetadata() {
        Scripted ch = new Scripted(okWith("avp.PushResponse", pushResponse()));
        GrpcWire w = wire(ch);
        Answer a = w.call(Op.PUSH, REPO, pushBody(), "tok-1");
        assertEquals(200, a.status());
        assertEquals(pushResponse(), a.body());
        assertEquals(Map.of("authorization", "Bearer tok-1"), ch.calls.get(0).metadata());

        ch.answer = okWith("avp.AuthChallenge", new JsonObject());
        JsonObject ask = new JsonObject();
        ask.addProperty("ed25519PublicKey", "AAAA");
        w.call(Op.CHALLENGE, null, ask, null);
        assertEquals(Map.of(), ch.calls.get(1).metadata());
        assertEquals(Duration.ofSeconds(30), ch.calls.get(1).deadline());
    }

    @Test
    void pullCarriesTheRepoIdInTheMessage() {
        JsonObject empty = new JsonObject();
        empty.add("manifests", new JsonArray());
        empty.add("heads", new JsonArray());
        empty.add("leaves", new JsonArray());
        Scripted ch = new Scripted(okWith("avp.PullResponse", empty));
        JsonObject body = new JsonObject();
        body.addProperty("sinceManifestSeq", 3);
        body.add("knownHeads", new JsonArray());
        Answer a = wire(ch).call(Op.PULL, REPO, body, "tok");
        assertEquals(empty, a.body());
        JsonObject sent = ProtoJson.decode("avp.PullRequest", ch.only().request());
        assertEquals(REPO, sent.get("repoId").getAsString());
        assertEquals(3, sent.get("sinceManifestSeq").getAsLong());
        assertTrue(!body.has("repoId"), "the caller's body is not changed");
    }

    @Test
    void mapsEveryAvpCodeToTheHttpStatusTheFailuresUse() {
        Object[][] table = {
            {"bad_request", 3, 400},
            {"unauthorized", 16, 401},
            {"forbidden", 7, 403},
            {"policy_denied", 7, 403},
            {"not_hosted", 7, 403},
            {"not_found", 5, 404},
            {"duplicate_repo", 6, 409},
            {"too_many_heads", 9, 409},
            {"manifest_conflict", 9, 409},
            {"missing_parents", 9, 422},
            {"quota_exceeded", 8, 429},
            {"too_large", 8, 413},
        };
        assertEquals(VaultFailures.CODES.size(), table.length);
        for (Object[] row : table) {
            String code = (String) row[0];
            Scripted ch = new Scripted(replying(Reply.status((int) row[1], code, Map.of("avp-error-detail", "x"))));
            Answer a = wire(ch).call(Op.PUSH, REPO, pushBody(), "tok");
            assertEquals((int) row[2], a.status(), code);
            assertEquals(Optional.of(code), a.code(), code);
            assertTrue(a.body().isJsonNull(), code);
        }
    }

    @Test
    void aStatusWithoutAnAvpCodeFallsBackToItsCanonicalStatus() {
        int[][] table = {{16, 401}, {7, 403}, {5, 404}, {6, 409}, {9, 409}, {8, 429}, {3, 400}};
        for (int[] row : table) {
            Scripted ch = new Scripted(replying(Reply.status(row[0], "nope", Map.of())));
            Answer a = wire(ch).call(Op.PUSH, REPO, pushBody(), "tok");
            assertEquals(row[1], a.status(), "grpc status " + row[0]);
            assertEquals(Optional.empty(), a.code());
        }
    }

    @Test
    void theRetryAfterTrailerIsTheStatedWait() {
        Scripted ch = new Scripted(replying(Reply.status(8, "quota_exceeded", Map.of("retry-after", "12"))));
        assertEquals(
                Duration.ofSeconds(12),
                wire(ch).call(Op.PUSH, REPO, pushBody(), "t").retryAfter());
        ch.answer = replying(Reply.status(8, "quota_exceeded", Map.of("retry-after", "soon")));
        assertEquals(null, wire(ch).call(Op.PUSH, REPO, pushBody(), "t").retryAfter());
    }

    @Test
    void unavailableAndDeadlineAreNetwork() {
        for (int code : new int[] {14, 4, 1}) {
            Scripted ch = new Scripted(replying(Reply.status(code, "upstream connect error", Map.of())));
            AltsException e = assertThrows(AltsException.class, () -> wire(ch).call(Op.PUSH, REPO, pushBody(), "t"));
            assertEquals(Kind.NETWORK, e.kind(), "grpc status " + code);
        }
    }

    @Test
    void anUnmappedStatusIsProtocol() {
        for (int code : new int[] {2, 12, 13, 15, 10, 11}) {
            Scripted ch = new Scripted(replying(Reply.status(code, "internal", Map.of())));
            AltsException e = assertThrows(AltsException.class, () -> wire(ch).call(Op.PUSH, REPO, pushBody(), "t"));
            assertEquals(Kind.PROTOCOL, e.kind(), "grpc status " + code);
        }
    }

    @Test
    void aReplyOverTheBodyCapIsProtocol() {
        Scripted ch = new Scripted(replying(Reply.ok(new byte[HostClient.MAX_BODY_BYTES + 1])));
        AltsException e = assertThrows(AltsException.class, () -> wire(ch).call(Op.PUSH, REPO, pushBody(), "t"));
        assertEquals(Kind.PROTOCOL, e.kind());
    }

    @Test
    void aGarbledReplyIsProtocol() {
        Scripted ch = new Scripted(replying(Reply.ok(new byte[] {0x08, 0x01})));
        AltsException e = assertThrows(AltsException.class, () -> wire(ch).call(Op.DISCOVERY, null, null, null));
        assertEquals(Kind.PROTOCOL, e.kind());
        ch.answer = replying(Reply.ok(new byte[] {0x12, 0x05, 0x61}));
        e = assertThrows(AltsException.class, () -> wire(ch).call(Op.PUSH, REPO, pushBody(), "t"));
        assertEquals(Kind.PROTOCOL, e.kind());
    }

    @Test
    void aFailedFutureIsNetwork() {
        Scripted ch = new Scripted(() -> CompletableFuture.failedFuture(new IOException("connection reset")));
        AltsException e = assertThrows(AltsException.class, () -> wire(ch).call(Op.PUSH, REPO, pushBody(), "t"));
        assertEquals(Kind.NETWORK, e.kind());
        assertTrue(!e.getMessage().contains("connection reset"), "the channel's text is never quoted");
    }

    @Test
    void aChannelThatThrowsIsNetworkAndANullFutureOrReplyIsProtocol() {
        Scripted throwing = new Scripted(() -> {
            throw new IllegalStateException("channel shut down");
        });
        assertEquals(
                Kind.NETWORK,
                assertThrows(AltsException.class, () -> wire(throwing).call(Op.PUSH, REPO, pushBody(), "t"))
                        .kind());
        Scripted nullFuture = new Scripted(() -> null);
        assertEquals(
                Kind.PROTOCOL,
                assertThrows(AltsException.class, () -> wire(nullFuture).call(Op.PUSH, REPO, pushBody(), "t"))
                        .kind());
        Scripted nullReply = new Scripted(() -> CompletableFuture.completedFuture(null));
        assertEquals(
                Kind.PROTOCOL,
                assertThrows(AltsException.class, () -> wire(nullReply).call(Op.PUSH, REPO, pushBody(), "t"))
                        .kind());
    }

    @Test
    void aClosedRuntimeIsCancelled() throws Exception {
        Scripted ch = new Scripted(CompletableFuture::new);
        CompletableFuture.runAsync(
                transport::close,
                CompletableFuture.delayedExecutor(150, TimeUnit.MILLISECONDS, TestTransports.EXECUTOR));
        long start = System.nanoTime();
        AltsException e = assertThrows(AltsException.class, () -> wire(ch).call(Op.PUSH, REPO, pushBody(), "t"));
        assertEquals(Kind.CANCELLED, e.kind());
        assertTrue(ch.last.isCancelled(), "the pending future is cancelled");
        assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) < 5_000, "ended at the close");

        Scripted after = new Scripted(CompletableFuture::new);
        assertEquals(
                Kind.CANCELLED,
                assertThrows(AltsException.class, () -> wire(after).call(Op.PUSH, REPO, pushBody(), "t"))
                        .kind());
        assertEquals(0, after.calls.size(), "nothing is sent once the runtime is closed");
    }

    @Test
    void anInterruptCancelsTheChannelFuture() throws Exception {
        Scripted ch = new Scripted(CompletableFuture::new);
        CompletableFuture<AltsException> outcome = new CompletableFuture<>();
        Thread t = Thread.ofVirtual().start(() -> {
            try {
                wire(ch).call(Op.PUSH, REPO, pushBody(), "t");
                outcome.complete(null);
            } catch (AltsException e) {
                outcome.complete(Thread.currentThread().isInterrupted() ? e : null);
            }
        });
        while (ch.last == null) {
            Thread.onSpinWait();
        }
        t.interrupt();
        AltsException e = outcome.get(5, TimeUnit.SECONDS);
        assertNotNull(e, "fails with the interrupt flag set again");
        assertEquals(Kind.CANCELLED, e.kind());
        assertTrue(ch.last.isCancelled());
    }

    @Test
    void theDeadlineCancelsTheChannelFuture() {
        Scripted ch = new Scripted(CompletableFuture::new);
        GrpcWire w = new GrpcWire(transport, TARGET, ch, Duration.ofMillis(200));
        long start = System.nanoTime();
        AltsException e = assertThrows(AltsException.class, () -> w.call(Op.PUSH, REPO, pushBody(), "t"));
        long took = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
        assertEquals(Kind.NETWORK, e.kind());
        assertTrue(ch.last.isCancelled());
        assertEquals(Duration.ofMillis(200), ch.only().deadline());
        assertTrue(took >= 1_150 && took < 5_000, "waits the deadline plus one second: " + took + " ms");
    }

    @Test
    void aOneThreadExecutorDoesNotDeadlock() throws Exception {
        ExecutorService one = Executors.newSingleThreadExecutor();
        try (HttpTransport single = TestTransports.on(scope -> ProxyRoute.direct(), one)) {
            // A channel completes on its own threads, as a gRPC runtime does, never on the library's executor.
            Scripted ch = new Scripted(() -> CompletableFuture.supplyAsync(
                    () -> Reply.ok(ProtoJson.encode("avp.PushResponse", pushResponse())),
                    CompletableFuture.delayedExecutor(50, TimeUnit.MILLISECONDS, TestTransports.EXECUTOR)));
            GrpcWire w = new GrpcWire(single, TARGET, ch);
            Thread[] worker = new Thread[1];
            Answer a = CompletableFuture.supplyAsync(
                            () -> {
                                worker[0] = Thread.currentThread();
                                return w.call(Op.PUSH, REPO, pushBody(), "t");
                            },
                            one)
                    .get(5, TimeUnit.SECONDS);
            assertEquals(200, a.status());
            assertSame(worker[0], ch.only().thread(), "unary runs on the calling thread, no second task");
        } finally {
            one.shutdownNow();
        }
    }

    @Test
    void theMethodNameHasNoLeadingSlash() {
        Map<Op, String> methods = Map.of(
                Op.DISCOVERY, "avp.Vault/GetHostInfo",
                Op.CHALLENGE, "avp.Vault/Challenge",
                Op.TOKEN, "avp.Vault/Token",
                Op.CREATE_REPO, "avp.Vault/CreateRepo",
                Op.PULL, "avp.Vault/Pull",
                Op.PUSH, "avp.Vault/Push",
                Op.PUBLISH_MANIFEST, "avp.Vault/PublishManifest",
                Op.LEAVE, "avp.Vault/Leave",
                Op.PREPARE_JOIN, "avp.Vault/PrepareJoin");
        for (Op op : Op.values()) {
            Scripted ch = new Scripted(replying(Reply.status(5, "not_found", Map.of())));
            wire(ch).call(op, op == Op.PULL ? REPO : null, new JsonObject(), op == Op.DISCOVERY ? null : "t");
            assertEquals(methods.get(op), ch.only().method(), op.name());
        }
    }

    @Test
    void theOriginSpellsOutTheGrpcDefaultPorts() {
        Scripted ch = new Scripted(CompletableFuture::new);
        assertEquals("grpcs://vault.example:443", new GrpcWire(transport, TARGET, ch).origin());
        assertEquals(
                "grpc://vault.example:80", new GrpcWire(transport, URI.create("grpc://Vault.Example"), ch).origin());
        assertEquals(
                "grpc://127.0.0.1:7447", new GrpcWire(transport, URI.create("grpc://127.0.0.1:7447"), ch).origin());
        assertEquals("grpc", new GrpcWire(transport, TARGET, ch).describe());
    }
}

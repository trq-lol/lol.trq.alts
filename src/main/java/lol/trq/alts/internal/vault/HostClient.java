package lol.trq.alts.internal.vault;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.LongSupplier;
import lol.trq.alts.AltsException;
import lol.trq.alts.internal.avp.AvpBytes;
import lol.trq.alts.internal.avp.AvpJson;
import lol.trq.alts.internal.avp.Challenge;
import lol.trq.alts.internal.avp.Commits;
import lol.trq.alts.internal.avp.Commits.Commit;
import lol.trq.alts.internal.avp.Manifest;
import lol.trq.alts.internal.avp.Manifest.SignedManifest;
import lol.trq.alts.internal.avp.Tokens;
import lol.trq.alts.internal.avp.Tokens.Acceptance;
import lol.trq.alts.internal.avp.Tokens.LeaveRequest;
import lol.trq.alts.internal.net.HttpTransport;
import lol.trq.alts.net.NetworkScope;

/**
 * A connection to one AVP host, matched by its host key (SPEC 3.3, 11.7), over a {@link HostWire}: the
 * HTTP/JSON profile ({@link HttpWire}, SPEC 10.2) or the gRPC profile (SPEC 10.3).
 *
 * <p>Over HTTP every request goes through the runtime's {@link HttpTransport} under {@link
 * NetworkScope.Purpose#VAULT}, so the host's proxy, the timeouts and the header rules apply on every hop, and
 * every answer is read up to {@link #MAX_BODY_BYTES}. The host key comes from discovery and, when the caller knows the key it expects
 * (from a token or a manifest's {@code hosts}), must equal it. Bearer tokens are minted by the challenge of
 * SPEC 3.3, signed over the domain-separated transcript for this host's key (never over the raw nonce), and
 * kept in a {@link TokenCache} under this host's key, so a token goes to no other host.
 *
 * <p>An answer is untrusted input, parsed strictly. A non-2xx answer is reported by its status and its SPEC
 * 10.4 code alone ({@link VaultFailures#refused}); the host's {@code error} text is never read. The request
 * methods block: run them on the transport's executor.
 *
 * @author trq
 * @since 1.0.0
 */
public final class HostClient {

    /** The largest answer read from a vault host: 16 MiB, as the reference client reads. */
    public static final int MAX_BODY_BYTES = 16 << 20;

    /** How often a request is retried on {@code 422 missing_parents}, the one retryable error. */
    static final int MISSING_PARENTS_RETRIES = 40;

    /** The pause between those tries, while the host fetches from its peers. */
    static final long RETRY_PAUSE_MILLIS = 100;

    private final HttpTransport transport;
    private final HostWire wire;
    private final String origin;
    private final String locator;
    private final byte[] key;
    private final TokenCache tokens;
    private final LongSupplier clock;
    private final ReentrantLock tokenLock = new ReentrantLock();

    private HostClient(
            HttpTransport transport, HostWire wire, String locator, byte[] key, TokenCache tokens, LongSupplier clock) {
        this.transport = transport;
        this.wire = wire;
        this.origin = wire.origin();
        this.locator = locator;
        this.key = key.clone();
        this.tokens = tokens;
        this.clock = clock;
    }

    /**
     * Connects to the host at {@code base} and learns its host key from {@code GET /.well-known/avp}. Blocks.
     *
     * @param transport the runtime's transport
     * @param base the host's base URL, {@code http(s)://host[:port]}
     * @param expectedKey the 32-byte key the host must have, or {@code null} to take the key discovery serves
     * @param tokens the token cache, shared by every connection of one runtime
     * @param clock epoch milliseconds
     * @return the connection
     * @throws AltsException of kind {@code PROTOCOL} if discovery serves no key or another key than expected,
     *     {@code NETWORK} if the host cannot be reached, or the refusal's kind
     */
    public static HostClient connect(
            HttpTransport transport, URI base, byte[] expectedKey, TokenCache tokens, LongSupplier clock) {
        return connect(transport, base, null, expectedKey, tokens, clock);
    }

    /**
     * Connects to the host at {@code base} as {@link #connect(HttpTransport, URI, byte[], TokenCache,
     * LongSupplier)} does, under a locator of the caller's: the one a token or a manifest names, when the
     * address it is reached at is mapped from it.
     *
     * @param transport the runtime's transport
     * @param base the host's base URL, {@code http(s)://host[:port]}
     * @param locator the locator to name the host by, or {@code null} for {@code host[:port]} of {@code base}
     * @param expectedKey the 32-byte key the host must have, or {@code null} to take the key discovery serves
     * @param tokens the token cache, shared by every connection of one runtime
     * @param clock epoch milliseconds
     * @return the connection
     */
    public static HostClient connect(
            HttpTransport transport,
            URI base,
            String locator,
            byte[] expectedKey,
            TokenCache tokens,
            LongSupplier clock) {
        Objects.requireNonNull(transport, "transport");
        HttpWire wire = new HttpWire(transport, base);
        String named = locator != null ? locator : base.getHost() + (base.getPort() == -1 ? "" : ":" + base.getPort());
        return connect(transport, wire, named, expectedKey, tokens, clock);
    }

    /**
     * Connects to a host over a given wire and learns its host key from discovery. Blocks.
     *
     * @param transport the runtime's transport: its executor, its delays and whether it is closed
     * @param wire how the host is reached
     * @param locator the locator to name the host by, {@code host[:port]}
     * @param expectedKey the 32-byte key the host must have, or {@code null} to take the key discovery serves
     * @param tokens the token cache, shared by every connection of one runtime
     * @param clock epoch milliseconds
     * @return the connection
     * @throws AltsException of kind {@code PROTOCOL} if discovery serves no key or another key than expected,
     *     {@code NETWORK} if the host cannot be reached, or the refusal's kind
     */
    public static HostClient connect(
            HttpTransport transport,
            HostWire wire,
            String locator,
            byte[] expectedKey,
            TokenCache tokens,
            LongSupplier clock) {
        Objects.requireNonNull(transport, "transport");
        Objects.requireNonNull(wire, "wire");
        Objects.requireNonNull(locator, "locator");
        Objects.requireNonNull(tokens, "tokens");
        Objects.requireNonNull(clock, "clock");
        HostWire.Answer answer = wire.call(HostWire.Op.DISCOVERY, null, null, null);
        if (answer.status() != 200) {
            throw refused(answer, "discovery");
        }
        JsonObject discovery = AvpJson.object(answer.body(), "the discovery answer");
        byte[] key = AvpJson.bytes(discovery, "hostKey", 32);
        if (expectedKey != null && !AvpBytes.same(key, expectedKey)) {
            throw VaultFailures.protocol("the host's discovery key is not the key it was expected to have");
        }
        return new HostClient(transport, wire, locator, key, tokens, clock);
    }

    /**
     * The origin a token is bound to besides the host key: {@code scheme://host:port}, lower-cased, with the
     * default port spelled out, so two spellings of one address share their tokens and no other address does.
     *
     * @param base the host's base URL
     * @return the origin
     */
    static String origin(URI base) {
        String scheme = base.getScheme().toLowerCase(java.util.Locale.ROOT);
        int port = base.getPort() != -1 ? base.getPort() : scheme.equals("https") ? 443 : 80;
        return scheme + "://" + base.getHost().toLowerCase(java.util.Locale.ROOT) + ":" + port;
    }

    /**
     * The host key this connection matched the host by.
     *
     * @return a copy of the 32-byte key
     */
    public byte[] key() {
        return key.clone();
    }

    /**
     * The locator ({@code host} or {@code host:port}) this connection dials, the hint that travels beside the
     * key in a manifest's {@code hosts} and in tokens.
     *
     * @return the locator
     */
    public String locator() {
        return locator;
    }

    /**
     * The transport this connection sends on.
     *
     * @return the transport
     */
    HttpTransport transport() {
        return transport;
    }

    // --- Requests --------------------------------------------------------------------------------

    private static AltsException refused(HostWire.Answer answer, String what) {
        return VaultFailures.refused(answer.status(), answer.code().orElse(null), answer.retryAfter(), what);
    }

    private JsonObject postOpen(HostWire.Op op, JsonObject body, String what) {
        HostWire.Answer answer = wire.call(op, null, body, null);
        if (answer.status() != 200) {
            throw refused(answer, what);
        }
        return AvpJson.object(answer.body(), "the " + what + " answer");
    }

    /** A bearer token for {@code me}: the cached one for this host, or a fresh one from the challenge. */
    private String token(MemberKeys me) {
        tokenLock.lock();
        try {
            byte[] subject = me.ed25519Public();
            Optional<String> cached = tokens.get(key, origin, subject, clock.getAsLong());
            if (cached.isPresent()) {
                return cached.get();
            }
            JsonObject ask = new JsonObject();
            ask.addProperty("ed25519PublicKey", AvpBytes.base64(subject));
            JsonObject challenge = postOpen(HostWire.Op.CHALLENGE, ask, "the sign-in challenge");
            String nonceText = AvpJson.string(challenge, "nonce");
            byte[] nonce = AvpBytes.fromBase64(nonceText, "the field nonce");
            // The transcript CE(avp/challenge/v1, hostKey, key, nonce) for the key this host was matched by,
            // never the host's bytes on their own (SPEC 3.3).
            byte[] signature = Challenge.sign(key, me.seedRef(), nonce);
            JsonObject redeem = new JsonObject();
            redeem.addProperty("ed25519PublicKey", AvpBytes.base64(subject));
            redeem.addProperty("nonce", nonceText);
            redeem.addProperty("signature", AvpBytes.base64(signature));
            JsonObject minted = postOpen(HostWire.Op.TOKEN, redeem, "the sign-in");
            String value = AvpJson.string(minted, "token");
            if (!headerSafe(value)) {
                throw VaultFailures.protocol("the host minted a token that is not a header value");
            }
            long expiresAt = AvpJson.int64(minted, "expiresAt");
            tokens.put(key, origin, subject, value, expiresAt);
            return value;
        } finally {
            tokenLock.unlock();
        }
    }

    /** Whether a host-minted token can travel in a header: not empty, printable ASCII without spaces. */
    static boolean headerSafe(String token) {
        if (token.isEmpty()) {
            return false;
        }
        for (int i = 0; i < token.length(); i++) {
            char c = token.charAt(i);
            if (c <= 0x20 || c >= 0x7f) {
                return false;
            }
        }
        return true;
    }

    /**
     * An authenticated JSON POST as {@code me}. A {@code 401} drops the cached token and tries once more with
     * a fresh one.
     *
     * @param me the caller
     * @param op the operation
     * @param repoId the repository of a repository-scoped operation, else {@code null}
     * @param body the request body
     * @param what what is asked, a fixed phrase for failure messages
     * @return the parsed 2xx answer
     */
    JsonElement post(MemberKeys me, HostWire.Op op, String repoId, JsonObject body, String what) {
        boolean fresh = false;
        while (true) {
            String token = token(me);
            HostWire.Answer answer = wire.call(op, repoId, body, token);
            if (answer.ok()) {
                return answer.body();
            }
            if (answer.status() == 401 && !fresh) {
                tokens.drop(key, origin, me.ed25519Public());
                fresh = true;
                continue;
            }
            throw refused(answer, what);
        }
    }

    /** A request that the host may answer {@code 422 missing_parents} while it fetches from its peers. */
    @FunctionalInterface
    interface Call<T> {
        T run();
    }

    /**
     * Runs {@code call} again while the host answers {@code 422 missing_parents} (SPEC 10.4, the only
     * retryable error), up to {@link #MISSING_PARENTS_RETRIES} times, pausing {@link #RETRY_PAUSE_MILLIS}
     * between tries through {@link HttpTransport#delay}, so a {@code close()} during a pause ends the
     * operation at once with {@code CANCELLED}.
     *
     * <p>The pause's completion runs on the transport's executor, which may be a host's bounded pool whose
     * threads are all busy (this thread among them). The wait is therefore bounded: once the pause has
     * passed with no completion and the transport is still open, the next try goes ahead.
     *
     * @param transport the transport whose close ends the wait
     * @param call the request
     * @param <T> its result
     * @return the result
     */
    static <T> T retryMissingParents(HttpTransport transport, Call<T> call) {
        int tries = 0;
        while (true) {
            try {
                return call.run();
            } catch (AltsException e) {
                if (!VaultFailures.hasCode(e, "missing_parents") || tries >= MISSING_PARENTS_RETRIES) {
                    throw e;
                }
                tries++;
                pause(transport);
            }
        }
    }

    private static void pause(HttpTransport transport) {
        CompletableFuture<Void> wait = transport.delay(Duration.ofMillis(RETRY_PAUSE_MILLIS));
        try {
            wait.get(RETRY_PAUSE_MILLIS * 2, TimeUnit.MILLISECONDS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw VaultFailures.cancelled("interrupted", interrupted);
        } catch (ExecutionException closed) {
            throw VaultFailures.cancelled("the runtime is closed", closed.getCause());
        } catch (TimeoutException busy) {
            // The executor had no thread for the completion; the pause has passed all the same.
        }
        if (transport.isClosed()) {
            throw VaultFailures.cancelled("the runtime is closed", null);
        }
    }

    /**
     * The path of a repository route, {@code repoId} percent-encoded as a path segment (SPEC 10.2, 12.4).
     *
     * @param repoId the repository
     * @param op the route's last segment
     * @return the path
     */
    static String repoPath(String repoId, String op) {
        StringBuilder seg = new StringBuilder();
        for (byte b : repoId.getBytes(StandardCharsets.UTF_8)) {
            char c = (char) (b & 0xff);
            boolean unreserved = (c >= 'a' && c <= 'z')
                    || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9')
                    || c == '-'
                    || c == '_'
                    || c == '.'
                    || c == '~';
            if (unreserved) {
                seg.append(c);
            } else {
                seg.append('%').append(String.format("%02X", b & 0xff));
            }
        }
        return "/v1/repos/" + seg + "/" + op;
    }

    // --- Routes (SPEC 10.2) ----------------------------------------------------------------------

    /**
     * {@code createRepo}: the genesis state with its first commit.
     *
     * @param me the owner
     * @param genesis the genesis state
     * @param first the empty first commit
     */
    void createRepo(MemberKeys me, SignedManifest genesis, Commit first) {
        JsonObject body = new JsonObject();
        body.add("manifest", Manifest.toJson(genesis));
        body.add("commit", Commits.toJson(first));
        post(me, HostWire.Op.CREATE_REPO, null, body, "the new repository");
    }

    /**
     * A pull answer, each item decoded on its own.
     *
     * @param manifests the states, as served
     * @param heads the head commits that decoded
     * @param leaves the leave requests that decoded
     * @param malformed how many head or leave items did not decode
     */
    record PullAnswer(List<SignedManifest> manifests, List<Commit> heads, List<LeaveRequest> leaves, int malformed) {}

    /**
     * {@code pull} with {@code knownHeads: []}, so the host answers with every current head: that is how the
     * client learns which of the heads it merged are still heads.
     *
     * @param me the member
     * @param repoId the repository
     * @param since the pinned seq, or {@code 0} for the whole chain
     * @return the answer; a state that does not decode fails it, since the chain cannot be checked without it
     */
    PullAnswer pull(MemberKeys me, String repoId, long since) {
        JsonObject body = new JsonObject();
        body.addProperty("sinceManifestSeq", since);
        body.add("knownHeads", new JsonArray());
        JsonObject answer = AvpJson.object(post(me, HostWire.Op.PULL, repoId, body, "the pull"), "the pull answer");
        List<SignedManifest> manifests = new ArrayList<>();
        for (JsonElement m : AvpJson.array(AvpJson.required(answer, "manifests"), "manifests")) {
            manifests.add(Manifest.signedFromJson(m));
        }
        int malformed = 0;
        List<Commit> heads = new ArrayList<>();
        for (JsonElement c : AvpJson.array(AvpJson.required(answer, "heads"), "heads")) {
            try {
                heads.add(Commits.fromJson(c));
            } catch (AltsException bad) {
                malformed++;
            }
        }
        List<LeaveRequest> leaves = new ArrayList<>();
        for (JsonElement l : AvpJson.array(AvpJson.required(answer, "leaves"), "leaves")) {
            try {
                leaves.add(Tokens.leaveFromJson(AvpJson.object(l, "a leave request")));
            } catch (AltsException bad) {
                malformed++;
            }
        }
        return new PullAnswer(manifests, heads, leaves, malformed);
    }

    /**
     * {@code push} of one commit, retried on {@code 422 missing_parents}.
     *
     * @param me the author
     * @param repoId the repository
     * @param commit the commit
     */
    void push(MemberKeys me, String repoId, Commit commit) {
        JsonObject body = new JsonObject();
        body.add("commit", Commits.toJson(commit));
        retryMissingParents(transport, () -> post(me, HostWire.Op.PUSH, repoId, body, "the write"));
    }

    /**
     * {@code publishManifest}: a new owner-signed state, with its rotation commit when it raises the epoch,
     * retried on {@code 422 missing_parents}.
     *
     * @param me the owner
     * @param repoId the repository
     * @param state the state
     * @param commit the commit published with it, or {@code null}
     */
    void publish(MemberKeys me, String repoId, SignedManifest state, Commit commit) {
        JsonObject body = new JsonObject();
        body.add("manifest", Manifest.toJson(state));
        if (commit != null) {
            body.add("commit", Commits.toJson(commit));
        }
        retryMissingParents(
                transport, () -> post(me, HostWire.Op.PUBLISH_MANIFEST, repoId, body, "the manifest change"));
    }

    /**
     * {@code leave}: a signed leave request.
     *
     * @param me the leaving member
     * @param request the request
     */
    void leave(MemberKeys me, LeaveRequest request) {
        post(me, HostWire.Op.LEAVE, request.repoId(), Tokens.toJson(request), "the leave request");
    }

    /**
     * {@code prepareJoin}: asks this host to carry a repository for {@code me}, and checks the acceptance it
     * signs (SPEC 8.2): it verifies under this host's key and names this host, the repository and the member.
     *
     * @param me the joining member
     * @param repoId the repository
     * @return the acceptance
     * @throws AltsException of kind {@code PROTOCOL} if the acceptance does not check
     */
    Acceptance prepareJoin(MemberKeys me, String repoId) {
        JsonObject body = new JsonObject();
        body.addProperty("repoId", repoId);
        body.addProperty("memberKey", me.id());
        Acceptance a = Tokens.acceptanceFromJson(
                AvpJson.object(post(me, HostWire.Op.PREPARE_JOIN, null, body, "the join"), "the acceptance"));
        boolean ok = AvpBytes.same(a.hostKey(), key)
                && Tokens.verifyAcceptance(a, key)
                && AvpBytes.same(a.repoId(), repoId)
                && me.is(a.memberKey());
        if (!ok) {
            throw VaultFailures.protocol("the host's acceptance does not verify for this host, repository and member");
        }
        return a;
    }

    /**
     * Names the host by its key and locator.
     *
     * @return a description
     */
    @Override
    public String toString() {
        return "HostClient[" + locator + ", " + wire.describe() + ", " + AvpBytes.base64(key) + "]";
    }

    static List<byte[]> copyIds(List<byte[]> ids) {
        List<byte[]> out = new ArrayList<>(ids.size());
        for (byte[] id : ids) {
            out.add(Arrays.copyOf(id, id.length));
        }
        return out;
    }
}

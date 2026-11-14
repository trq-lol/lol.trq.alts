package lol.trq.alts.internal.vault;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
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
import lol.trq.alts.net.HttpTransport;
import lol.trq.alts.net.NetworkScope;

/**
 * A connection to one AVP host over the HTTP/JSON profile (SPEC 10.2), matched by its host key (SPEC 3.3,
 * 11.7).
 *
 * <p>Every request goes through the runtime's {@link HttpTransport} under {@link NetworkScope.Purpose#VAULT},
 * so the host's proxy, the timeouts and the header rules apply on every hop, and every answer is read up to
 * {@link #MAX_BODY_BYTES}. The host key comes from discovery and, when the caller knows the key it expects
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

    private static final NetworkScope SCOPE = NetworkScope.of(NetworkScope.Purpose.VAULT);

    private final HttpTransport transport;
    private final String base;
    private final String locator;
    private final byte[] key;
    private final TokenCache tokens;
    private final LongSupplier clock;
    private final ReentrantLock tokenLock = new ReentrantLock();

    private HostClient(
            HttpTransport transport, String base, String locator, byte[] key, TokenCache tokens, LongSupplier clock) {
        this.transport = transport;
        this.base = base;
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
        Objects.requireNonNull(transport, "transport");
        Objects.requireNonNull(tokens, "tokens");
        Objects.requireNonNull(clock, "clock");
        String scheme = base.getScheme();
        if (base.getHost() == null || !("https".equalsIgnoreCase(scheme) || "http".equalsIgnoreCase(scheme))) {
            throw VaultFailures.invalid("a vault host address is an http or https URL with a host");
        }
        String root = base.toString();
        while (root.endsWith("/")) {
            root = root.substring(0, root.length() - 1);
        }
        String locator = base.getHost() + (base.getPort() == -1 ? "" : ":" + base.getPort());
        HttpTransport.RawResponse answer = exchange(transport, "GET", root + "/.well-known/avp", null, null);
        if (answer.status() != 200) {
            throw refusal(answer, "discovery");
        }
        JsonObject discovery = AvpJson.object(AvpJson.parse(answer.body()), "the discovery answer");
        byte[] key = AvpJson.bytes(discovery, "hostKey", 32);
        if (expectedKey != null && !AvpBytes.same(key, expectedKey)) {
            throw VaultFailures.protocol("the host's discovery key is not the key it was expected to have");
        }
        return new HostClient(transport, root, locator, key, tokens, clock);
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

    // --- Transport -------------------------------------------------------------------------------

    private static HttpTransport.RawResponse exchange(
            HttpTransport transport, String method, String url, byte[] body, Map<String, String> headers) {
        try {
            return transport.exchange(
                    method, url, body == null ? null : "application/json", headers, body, MAX_BODY_BYTES, SCOPE);
        } catch (IllegalArgumentException badHeader) {
            // The transport refuses a header holding a control character without quoting it: the only header
            // here a host chose is the bearer token it minted.
            throw VaultFailures.protocol("the host minted a token that is not a header value");
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw VaultFailures.cancelled("interrupted", interrupted);
        } catch (Exception failure) {
            if (transport.isClosed()) {
                throw VaultFailures.cancelled("the runtime is closed", failure);
            }
            throw VaultFailures.network("the host could not be reached, or its answer could not be read", failure);
        }
    }

    private static AltsException refusal(HttpTransport.RawResponse answer, String what) {
        String code = null;
        try {
            JsonElement parsed = AvpJson.parse(answer.body());
            if (parsed.isJsonObject()) {
                JsonElement c = parsed.getAsJsonObject().get("code");
                if (c != null && c.isJsonPrimitive() && c.getAsJsonPrimitive().isString()) {
                    code = c.getAsString();
                }
            }
        } catch (AltsException notJson) {
            // A bare error (SPEC 10.4 allows a 400 with no error object): the status alone.
        }
        return VaultFailures.refused(answer.status(), code, answer.retryAfter(), what);
    }

    private JsonObject postOpen(String path, JsonObject body, String what) {
        HttpTransport.RawResponse answer = exchange(transport, "POST", base + path, AvpJson.write(body), null);
        if (answer.status() != 200) {
            throw refusal(answer, what);
        }
        return AvpJson.object(AvpJson.parse(answer.body()), "the " + what + " answer");
    }

    /** A bearer token for {@code me}: the cached one for this host, or a fresh one from the challenge. */
    private String token(MemberKeys me) {
        tokenLock.lock();
        try {
            byte[] subject = me.ed25519Public();
            Optional<String> cached = tokens.get(key, subject, clock.getAsLong());
            if (cached.isPresent()) {
                return cached.get();
            }
            JsonObject ask = new JsonObject();
            ask.addProperty("ed25519PublicKey", AvpBytes.base64(subject));
            JsonObject challenge = postOpen("/api/auth/keypair/challenge", ask, "the sign-in challenge");
            String nonceText = AvpJson.string(challenge, "nonce");
            byte[] nonce = AvpBytes.fromBase64(nonceText, "the field nonce");
            // The transcript CE(avp/challenge/v1, hostKey, key, nonce) for the key this host was matched by,
            // never the host's bytes on their own (SPEC 3.3).
            byte[] signature = Challenge.sign(key, me.seedRef(), nonce);
            JsonObject redeem = new JsonObject();
            redeem.addProperty("ed25519PublicKey", AvpBytes.base64(subject));
            redeem.addProperty("nonce", nonceText);
            redeem.addProperty("signature", AvpBytes.base64(signature));
            JsonObject minted = postOpen("/api/auth/keypair/token", redeem, "the sign-in");
            String value = AvpJson.string(minted, "token");
            long expiresAt = AvpJson.int64(minted, "expiresAt");
            tokens.put(key, subject, value, expiresAt);
            return value;
        } finally {
            tokenLock.unlock();
        }
    }

    /**
     * An authenticated JSON POST as {@code me}. A {@code 401} drops the cached token and tries once more with
     * a fresh one.
     *
     * @param me the caller
     * @param path the route
     * @param body the request body
     * @param what what is asked, a fixed phrase for failure messages
     * @return the parsed 2xx answer
     */
    JsonElement post(MemberKeys me, String path, JsonObject body, String what) {
        byte[] bytes = AvpJson.write(body);
        boolean fresh = false;
        while (true) {
            String token = token(me);
            HttpTransport.RawResponse answer =
                    exchange(transport, "POST", base + path, bytes, Map.of("Authorization", "Bearer " + token));
            if (answer.status() >= 200 && answer.status() < 300) {
                return AvpJson.parse(answer.body());
            }
            if (answer.status() == 401 && !fresh) {
                tokens.drop(key, me.ed25519Public());
                fresh = true;
                continue;
            }
            throw refusal(answer, what);
        }
    }

    /** A request that the host may answer {@code 422 missing_parents} while it fetches from its peers. */
    @FunctionalInterface
    interface Call<T> {
        T run();
    }

    /**
     * Runs {@code call} again while the host answers {@code 422 missing_parents} (SPEC 10.4, the only
     * retryable error), up to {@link #MISSING_PARENTS_RETRIES} times.
     *
     * @param call the request
     * @param <T> its result
     * @return the result
     */
    static <T> T retryMissingParents(Call<T> call) {
        int tries = 0;
        while (true) {
            try {
                return call.run();
            } catch (AltsException e) {
                if (!VaultFailures.hasCode(e, "missing_parents") || tries >= MISSING_PARENTS_RETRIES) {
                    throw e;
                }
                tries++;
                try {
                    Thread.sleep(RETRY_PAUSE_MILLIS);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw VaultFailures.cancelled("interrupted", interrupted);
                }
            }
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
        post(me, "/v1/repos", body, "the new repository");
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
        JsonObject answer = AvpJson.object(post(me, repoPath(repoId, "pull"), body, "the pull"), "the pull answer");
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
        retryMissingParents(() -> post(me, repoPath(repoId, "push"), body, "the write"));
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
        retryMissingParents(() -> post(me, repoPath(repoId, "manifest"), body, "the manifest change"));
    }

    /**
     * {@code leave}: a signed leave request.
     *
     * @param me the leaving member
     * @param request the request
     */
    void leave(MemberKeys me, LeaveRequest request) {
        post(me, repoPath(request.repoId(), "leave"), Tokens.toJson(request), "the leave request");
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
                AvpJson.object(post(me, "/v1/prepare-join", body, "the join"), "the acceptance"));
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
        return "HostClient[" + locator + ", " + AvpBytes.base64(key) + "]";
    }

    static List<byte[]> copyIds(List<byte[]> ids) {
        List<byte[]> out = new ArrayList<>(ids.size());
        for (byte[] id : ids) {
            out.add(Arrays.copyOf(id, id.length));
        }
        return out;
    }
}

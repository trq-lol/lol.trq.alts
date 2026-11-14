package lol.trq.alts.internal.vault;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.function.Function;
import lol.trq.alts.AltsException;
import lol.trq.alts.internal.avp.AvpBytes;
import lol.trq.alts.internal.avp.AvpCrypto;
import lol.trq.alts.internal.avp.AvpJson;
import lol.trq.alts.internal.avp.Challenge;
import lol.trq.alts.internal.avp.Commits;
import lol.trq.alts.internal.avp.Commits.Commit;
import lol.trq.alts.internal.avp.Ed25519Strict;
import lol.trq.alts.internal.avp.Manifest;
import lol.trq.alts.internal.avp.Manifest.ManifestState;
import lol.trq.alts.internal.avp.Manifest.Removal;
import lol.trq.alts.internal.avp.Manifest.SignedManifest;
import lol.trq.alts.internal.avp.ManifestRules;
import lol.trq.alts.internal.avp.Tokens;
import lol.trq.alts.internal.avp.Tokens.LeaveRequest;

/**
 * An honest, in-process AVP 0.5 host for the client tests: the client routes of SPEC 10 over loopback HTTP,
 * every rule decided by the {@code internal.avp} constructions (SPEC 3.3, 6, 7, 8). It does not replicate;
 * {@link #offer(SignedManifest, Commit)} stands in for a peer's offer, so a test can make the host switch to
 * a diverged owner chain (SPEC 6.5).
 *
 * <p>Simplifications, none of which a client can tell apart on the routes it uses: a commit that would be
 * held (SPEC 6.5) is refused with {@code 403}, which is what a push of a held commit gets anyway; a frontier
 * commit the host lacks makes a removed member's commit {@code 403}.
 *
 * <p>The hostile layer is {@link #interceptor}: it sees every request and decides the answer, usually by
 * asking the honest host and rewriting what it says. Every request is recorded, headers and body, for the
 * zero-knowledge checks.
 */
public final class TestAvpHost implements AutoCloseable {

    /** One recorded request. */
    public record Request(String method, String path, Map<String, List<String>> headers, byte[] body) {
        public String header(String name) {
            for (Map.Entry<String, List<String>> e : headers.entrySet()) {
                if (e.getKey() != null
                        && e.getKey().equalsIgnoreCase(name)
                        && !e.getValue().isEmpty()) {
                    return e.getValue().get(0);
                }
            }
            return null;
        }

        public JsonObject json() {
            return AvpJson.object(AvpJson.parse(body), "request");
        }
    }

    /** One answer. */
    public record Response(int status, byte[] body, Map<String, String> headers) {
        public static Response json(int status, JsonElement body) {
            return new Response(status, AvpJson.write(body), Map.of("Content-Type", "application/json"));
        }

        public static Response error(int status, String code, String text) {
            JsonObject o = new JsonObject();
            o.addProperty("error", text);
            o.addProperty("code", code);
            return json(status, o);
        }

        public JsonObject json() {
            return AvpJson.object(AvpJson.parse(body), "response");
        }
    }

    /** The hostile layer: decides the answer to a request, usually by asking the honest host first. */
    @FunctionalInterface
    public interface Interceptor {
        Response handle(Request request, Function<Request, Response> honest);
    }

    private static final Interceptor HONEST = (r, honest) -> honest.apply(r);

    private final HttpServer server;
    private final List<Request> log = new ArrayList<>();
    public volatile Interceptor interceptor = HONEST;

    private byte[] seed = AvpCrypto.randomBytes(32);
    private byte[] key = Ed25519Strict.publicKey(seed);
    private final Map<String, Repo> repos = new HashMap<>();
    private final Map<String, String> challenges = new HashMap<>();
    private final Map<String, Minted> tokens = new HashMap<>();
    /** Every token this host minted, by the host key it was minted under. */
    private final Map<String, Set<String>> mintedUnder = new HashMap<>();

    private record Minted(String subject, String hostKey, long expiresAt) {}

    public TestAvpHost() throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", this::serve);
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        server.start();
    }

    public URI base() {
        return URI.create("http://127.0.0.1:" + server.getAddress().getPort());
    }

    public synchronized byte[] key() {
        return key.clone();
    }

    synchronized byte[] seed() {
        return seed.clone();
    }

    /** Becomes another host at the same address: a new host key, tokens of the old one no longer valid. */
    public synchronized void rekey() {
        seed = AvpCrypto.randomBytes(32);
        key = Ed25519Strict.publicKey(seed);
    }

    public List<Request> requests() {
        synchronized (log) {
            return List.copyOf(log);
        }
    }

    public long count(String pathSuffix) {
        return requests().stream().filter(r -> r.path().endsWith(pathSuffix)).count();
    }

    public void clearLog() {
        synchronized (log) {
            log.clear();
        }
    }

    synchronized Set<String> tokensMintedUnder(byte[] hostKey) {
        return Set.copyOf(mintedUnder.getOrDefault(AvpBytes.base64(hostKey), Set.of()));
    }

    @Override
    public void close() {
        server.stop(0);
    }

    // --- HTTP ------------------------------------------------------------------------------------

    private void serve(HttpExchange ex) throws IOException {
        try (ex) {
            byte[] body;
            try (InputStream in = ex.getRequestBody()) {
                body = in.readAllBytes();
            }
            Request req = new Request(
                    ex.getRequestMethod(),
                    ex.getRequestURI().getRawPath(),
                    Map.copyOf(new HashMap<>(ex.getRequestHeaders())),
                    body);
            synchronized (log) {
                log.add(req);
            }
            Response resp;
            try {
                resp = interceptor.handle(req, this::honest);
            } catch (RuntimeException e) {
                resp = Response.error(500, "internal", "test host failure");
            }
            resp.headers().forEach((k, v) -> ex.getResponseHeaders().add(k, v));
            byte[] out = resp.body() == null ? new byte[0] : resp.body();
            ex.sendResponseHeaders(resp.status(), out.length == 0 ? -1 : out.length);
            if (out.length > 0) {
                try (OutputStream os = ex.getResponseBody()) {
                    os.write(out);
                }
            }
        }
    }

    /** What an honest host answers. */
    synchronized Response honest(Request req) {
        String path = req.path();
        try {
            if (req.method().equals("GET") && path.equals("/.well-known/avp")) {
                JsonObject o = new JsonObject();
                o.addProperty("version", "0.5");
                JsonArray profiles = new JsonArray();
                profiles.add("http-json");
                o.add("profiles", profiles);
                o.addProperty("hostKey", AvpBytes.base64(key));
                return Response.json(200, o);
            }
            if (!req.method().equals("POST")) {
                return Response.error(404, "not_found", "no such route");
            }
            switch (path) {
                case "/api/auth/keypair/challenge" -> {
                    return challenge(req.json());
                }
                case "/api/auth/keypair/token" -> {
                    return token(req.json());
                }
                default -> {
                    // falls through to the authenticated routes
                }
            }
            byte[] caller = caller(req);
            if (caller == null) {
                return Response.error(401, "unauthorized", "missing or invalid token");
            }
            if (path.equals("/v1/repos")) {
                return createRepo(caller, req.json());
            }
            if (path.equals("/v1/prepare-join")) {
                return prepareJoin(caller, req.json());
            }
            if (path.startsWith("/v1/repos/")) {
                String rest = path.substring("/v1/repos/".length());
                int slash = rest.indexOf('/');
                if (slash < 0) {
                    return Response.error(404, "not_found", "no such route");
                }
                String repoId;
                try {
                    repoId = URLDecoder.decode(rest.substring(0, slash), StandardCharsets.UTF_8);
                } catch (IllegalArgumentException badEscape) {
                    return new Response(400, new byte[0], Map.of());
                }
                Repo repo = repos.get(repoId);
                if (repo == null) {
                    return Response.error(404, "not_found", "no such repository");
                }
                return switch (rest.substring(slash + 1)) {
                    case "pull" -> pull(repo, caller, req.json());
                    case "push" -> push(repo, caller, req.json());
                    case "manifest" -> publish(repo, caller, req.json());
                    case "leave" -> leave(repo, caller, req.json());
                    default -> Response.error(404, "not_found", "no such route");
                };
            }
            return Response.error(404, "not_found", "no such route");
        } catch (AltsException malformed) {
            return Response.error(400, "bad_request", "malformed request");
        }
    }

    // --- Authentication (SPEC 3.3) -----------------------------------------------------------------

    private Response challenge(JsonObject body) {
        byte[] subject = AvpJson.bytes(body, "ed25519PublicKey", 32);
        byte[] nonce = AvpCrypto.randomBytes(32);
        challenges.put(AvpBytes.base64(nonce), AvpBytes.base64(subject));
        JsonObject o = new JsonObject();
        o.addProperty("nonce", AvpBytes.base64(nonce));
        return Response.json(200, o);
    }

    private Response token(JsonObject body) {
        byte[] subject = AvpJson.bytes(body, "ed25519PublicKey", 32);
        String nonceText = AvpJson.string(body, "nonce");
        byte[] signature = AvpJson.bytes(body, "signature", 64);
        String issuedFor = challenges.remove(nonceText);
        byte[] nonce = AvpBytes.fromBase64(nonceText, "nonce");
        if (issuedFor == null
                || !issuedFor.equals(AvpBytes.base64(subject))
                || !Challenge.verify(key, subject, nonce, signature)) {
            return Response.error(401, "unauthorized", "the challenge signature does not verify");
        }
        String token = AvpBytes.base64Url(AvpCrypto.randomBytes(24));
        long expiresAt = System.currentTimeMillis() + 600_000;
        tokens.put(token, new Minted(AvpBytes.base64(subject), AvpBytes.base64(key), expiresAt));
        mintedUnder.computeIfAbsent(AvpBytes.base64(key), k -> new HashSet<>()).add(token);
        JsonObject o = new JsonObject();
        o.addProperty("token", token);
        o.addProperty("expiresAt", expiresAt);
        return Response.json(200, o);
    }

    private byte[] caller(Request req) {
        String auth = req.header("Authorization");
        if (auth == null || !auth.startsWith("Bearer ")) {
            return null;
        }
        Minted m = tokens.get(auth.substring("Bearer ".length()));
        if (m == null || !m.hostKey().equals(AvpBytes.base64(key)) || m.expiresAt() < System.currentTimeMillis()) {
            return null;
        }
        return AvpBytes.fromBase64(m.subject(), "subject");
    }

    // --- Repository state ----------------------------------------------------------------------------

    /** One repository as this host holds it. */
    static final class Repo {
        final List<SignedManifest> chain = new ArrayList<>();
        final Map<String, SignedManifest> losing = new HashMap<>();
        final Map<String, Commit> accepted = new LinkedHashMap<>();
        final Set<String> rejected = new HashSet<>();
        final Map<String, List<byte[]>> ancestry = new HashMap<>();
        final LinkedHashSet<String> heads = new LinkedHashSet<>();
        final Map<String, LeaveRequest> leaves = new LinkedHashMap<>();

        SignedManifest tip() {
            return chain.get(chain.size() - 1);
        }

        byte[] hashAt(long seq) {
            return Manifest.hash(chain.get((int) seq - 1));
        }

        void learn(Commit c) {
            ancestry.put(AvpBytes.base64(c.commitId()), c.parents());
        }

        boolean isAncestor(byte[] id, List<byte[]> from) {
            String target = AvpBytes.base64(id);
            Set<String> seen = new HashSet<>();
            ArrayDeque<String> stack = new ArrayDeque<>();
            from.forEach(f -> stack.push(AvpBytes.base64(f)));
            while (!stack.isEmpty()) {
                for (byte[] p : ancestry.getOrDefault(stack.pop(), List.of())) {
                    String pid = AvpBytes.base64(p);
                    if (pid.equals(target)) {
                        return true;
                    }
                    if (seen.add(pid)) {
                        stack.push(pid);
                    }
                }
            }
            return false;
        }
    }

    /** A test's direct view of a repository's heads. */
    public synchronized List<byte[]> heads(String repoId) {
        List<byte[]> out = new ArrayList<>();
        repos.get(repoId).heads.forEach(h -> out.add(AvpBytes.fromBase64(h, "id")));
        return out;
    }

    public synchronized SignedManifest tip(String repoId) {
        return repos.get(repoId).tip();
    }

    public synchronized Commit commit(String repoId, byte[] id) {
        return repos.get(repoId).accepted.get(AvpBytes.base64(id));
    }

    // --- Routes ----------------------------------------------------------------------------------------

    private Response createRepo(byte[] caller, JsonObject body) {
        SignedManifest m = Manifest.signedFromJson(AvpJson.required(body, "manifest"));
        Commit c = Commits.fromJson(AvpJson.required(body, "commit"));
        if (ManifestRules.check(m, null) != ManifestRules.Verdict.OK) {
            return Response.error(400, "bad_request", "invalid genesis");
        }
        if (!AvpBytes.same(caller, m.state().ownerKey())) {
            return Response.error(403, "forbidden", "the caller is not the owner");
        }
        if (!m.state().hasHost(key)) {
            return Response.error(403, "not_hosted", "this host is not listed");
        }
        boolean first = c.parents().isEmpty()
                && c.manifestSeq() == 1
                && AvpBytes.same(c.manifestHash(), Manifest.hash(m))
                && AvpBytes.same(c.author(), m.state().ownerKey())
                && c.keyEpoch() == 0
                && AvpBytes.same(c.repoId(), m.state().repoId())
                && Commits.verify(c);
        if (!first) {
            return Response.error(400, "bad_request", "invalid first commit");
        }
        if (repos.containsKey(m.state().repoId())) {
            return Response.error(409, "duplicate_repo", "the repository exists");
        }
        Repo r = new Repo();
        r.chain.add(m);
        r.learn(c);
        r.accepted.put(AvpBytes.base64(c.commitId()), c);
        r.heads.add(AvpBytes.base64(c.commitId()));
        repos.put(m.state().repoId(), r);
        return Response.json(200, Manifest.toJson(m));
    }

    private Response pull(Repo r, byte[] caller, JsonObject body) {
        if (!r.tip().state().hasMember(caller)) {
            return Response.error(403, "forbidden", "not a member");
        }
        long since = AvpJson.int64(body, "sinceManifestSeq");
        Set<String> known = new HashSet<>();
        AvpJson.array(AvpJson.required(body, "knownHeads"), "knownHeads").forEach(k -> known.add(k.getAsString()));
        JsonArray manifests = new JsonArray();
        for (SignedManifest m : r.chain) {
            if (m.state().manifestSeq() > since) {
                manifests.add(Manifest.toJson(m));
            }
        }
        JsonArray heads = new JsonArray();
        for (String h : r.heads) {
            if (!known.contains(h)) {
                heads.add(Commits.toJson(r.accepted.get(h)));
            }
        }
        JsonArray leaves = new JsonArray();
        r.leaves.values().forEach(l -> leaves.add(Tokens.toJson(l)));
        JsonObject o = new JsonObject();
        o.add("manifests", manifests);
        o.add("heads", heads);
        o.add("leaves", leaves);
        return Response.json(200, o);
    }

    private Response push(Repo r, byte[] caller, JsonObject body) {
        Commit c = Commits.fromJson(AvpJson.required(body, "commit"));
        Optional<Response> refused = accept(r, c, caller);
        if (refused.isPresent()) {
            return refused.get();
        }
        JsonObject o = new JsonObject();
        o.addProperty("accepted", true);
        JsonArray heads = new JsonArray();
        r.heads.forEach(heads::add);
        o.add("heads", heads);
        return Response.json(200, o);
    }

    /** SPEC 7.1 to 7.4 for one commit; {@code caller} is null for a commit that arrives by replication. */
    private Optional<Response> accept(Repo r, Commit c, byte[] caller) {
        if (!AvpBytes.same(c.repoId(), r.chain.get(0).state().repoId()) || !Commits.verify(c)) {
            return Optional.of(Response.error(400, "bad_request", "the commit does not verify"));
        }
        r.learn(c);
        String id = AvpBytes.base64(c.commitId());
        ManifestState tip = r.tip().state();
        if (caller != null && (!tip.hasMember(caller) || !AvpBytes.same(caller, c.author()))) {
            return Optional.of(Response.error(403, "forbidden", "the caller is not the author or not a member"));
        }
        if (r.accepted.containsKey(id)) {
            return Optional.empty();
        }
        Optional<Response> binding = binding(r, c);
        if (binding.isPresent()) {
            return binding;
        }
        Optional<Removal> removal = tip.removalOf(c.author());
        if (removal.isPresent()) {
            List<byte[]> f = removal.get().frontier();
            boolean in = f.stream().anyMatch(x -> AvpBytes.same(x, c.commitId()));
            if (!in && !r.isAncestor(c.commitId(), f)) {
                r.rejected.add(id);
                return Optional.of(Response.error(403, "forbidden", "after the removal cutoff"));
            }
        }
        List<String> missing = new ArrayList<>();
        for (byte[] p : c.parents()) {
            String pid = AvpBytes.base64(p);
            if (r.rejected.contains(pid)) {
                r.rejected.add(id);
                return Optional.of(Response.error(403, "forbidden", "a parent was rejected"));
            }
            if (!r.accepted.containsKey(pid)) {
                missing.add(pid);
            }
        }
        if (!missing.isEmpty()) {
            JsonObject o = new JsonObject();
            o.addProperty("error", "unknown parents");
            o.addProperty("code", "missing_parents");
            o.addProperty("detail", String.join(",", missing));
            return Optional.of(Response.json(422, o));
        }
        Set<String> after = new LinkedHashSet<>(r.heads);
        c.parents().forEach(p -> after.remove(AvpBytes.base64(p)));
        after.add(id);
        if (caller != null && after.size() > 16) {
            return Optional.of(Response.error(409, "too_many_heads", "merge first"));
        }
        r.accepted.put(id, c);
        r.heads.clear();
        r.heads.addAll(after);
        return Optional.empty();
    }

    /** SPEC 7.2 with the losing-state re-check of SPEC 6.5 (a commit that would be held is refused). */
    private static Optional<Response> binding(Repo r, Commit c) {
        long seq = c.manifestSeq();
        boolean onChain = seq >= 1 && seq <= r.chain.size() && AvpBytes.same(r.hashAt(seq), c.manifestHash());
        if (onChain) {
            ManifestState s = r.chain.get((int) seq - 1).state();
            if (!s.hasMember(c.author()) || s.keyEpoch() != c.keyEpoch()) {
                return Optional.of(Response.error(403, "forbidden", "not a member at the commit's epoch"));
            }
            return Optional.empty();
        }
        SignedManifest losing = r.losing.get(AvpBytes.base64(c.manifestHash()));
        if (losing == null || losing.state().manifestSeq() != seq) {
            JsonObject o = new JsonObject();
            o.addProperty("error", "unknown manifest state");
            o.addProperty("code", "missing_parents");
            o.addProperty("detail", AvpBytes.base64(c.manifestHash()));
            return Optional.of(Response.json(422, o));
        }
        if (seq <= r.chain.size()) {
            ManifestState w = r.chain.get((int) seq - 1).state();
            if (w.hasMember(c.author()) && w.keyEpoch() == c.keyEpoch()) {
                return Optional.empty();
            }
        }
        return Optional.of(Response.error(403, "forbidden", "a commit citing a losing state"));
    }

    private Response publish(Repo r, byte[] caller, JsonObject body) {
        SignedManifest m = Manifest.signedFromJson(AvpJson.required(body, "manifest"));
        Optional<Commit> commit = AvpJson.optional(body, "commit").map(Commits::fromJson);
        if (!AvpBytes.same(caller, r.tip().state().ownerKey())) {
            return Response.error(403, "forbidden", "the caller is not the owner");
        }
        ManifestRules.Verdict v = ManifestRules.check(m, r.tip());
        if (v == ManifestRules.Verdict.NOT_LINKED) {
            retainIfLosing(r, m);
            return Response.error(409, "manifest_conflict", "not the next state");
        }
        if (v != ManifestRules.Verdict.OK) {
            return Response.error(400, "bad_request", "the state does not verify");
        }
        if (!m.state().hasHost(key)) {
            return Response.error(403, "not_hosted", "this host is not listed");
        }
        Optional<Response> refused = adopt(r, m, commit, true);
        return refused.orElseGet(() -> Response.json(200, Manifest.toJson(m)));
    }

    private static void retainIfLosing(Repo r, SignedManifest m) {
        long seq = m.state().manifestSeq();
        if (seq >= 2 && seq - 1 <= r.chain.size()) {
            SignedManifest prev = r.chain.get((int) seq - 2);
            if (ManifestRules.check(m, prev) == ManifestRules.Verdict.OK) {
                r.losing.put(AvpBytes.base64(Manifest.hash(m)), m);
            }
        }
    }

    /** Adopts a validated next state with its commit, atomically (SPEC 8.3). */
    private Optional<Response> adopt(Repo r, SignedManifest m, Optional<Commit> commit, boolean client) {
        ManifestState prev = r.tip().state();
        boolean raising = m.state().keyEpoch() == prev.keyEpoch() + 1;
        if (raising) {
            boolean rotation = commit.isPresent()
                    && commit.get().manifestSeq() == m.state().manifestSeq()
                    && AvpBytes.same(commit.get().manifestHash(), Manifest.hash(m))
                    && commit.get().keyEpoch() == m.state().keyEpoch()
                    && AvpBytes.same(commit.get().author(), m.state().ownerKey());
            if (!rotation) {
                return Optional.of(Response.error(400, "bad_request", "an epoch-raising state needs its rotation"));
            }
        }
        r.chain.add(m);
        if (commit.isPresent()) {
            Optional<Response> refused =
                    accept(r, commit.get(), client ? m.state().ownerKey() : null);
            if (refused.isPresent()) {
                r.chain.remove(r.chain.size() - 1);
                return refused;
            }
        }
        afterNewState(r);
        return Optional.empty();
    }

    /** Drops heads that fail the cutoff of a new removal, and leaves of members no longer listed. */
    private static void afterNewState(Repo r) {
        ManifestState tip = r.tip().state();
        for (Removal rem : tip.removals()) {
            r.heads.removeIf(h -> {
                Commit c = r.accepted.get(h);
                if (!AvpBytes.same(c.author(), rem.memberKey())) {
                    return false;
                }
                boolean in = rem.frontier().stream().anyMatch(x -> AvpBytes.same(x, c.commitId()));
                boolean keep = in || r.isAncestor(c.commitId(), rem.frontier());
                if (!keep) {
                    r.rejected.add(h);
                }
                return !keep;
            });
        }
        r.leaves.keySet().removeIf(k -> !tip.hasMember(AvpBytes.fromBase64(k, "k")));
    }

    private Response leave(Repo r, byte[] caller, JsonObject body) {
        LeaveRequest l = Tokens.leaveFromJson(body);
        Tokens.LeaveVerdict v = Tokens.leaveVerdict(l, r.tip().state());
        if (v != Tokens.LeaveVerdict.OK) {
            return Response.error(
                    v.code().map(c -> c.equals("forbidden") ? 403 : 400).orElse(400),
                    v.code().orElse("bad_request"),
                    "refused");
        }
        if (!AvpBytes.same(caller, l.memberKey())) {
            return Response.error(403, "forbidden", "the caller is not the leaving member");
        }
        r.leaves.put(AvpBytes.base64(l.memberKey()), l);
        return Response.json(200, new JsonObject());
    }

    private Response prepareJoin(byte[] caller, JsonObject body) {
        String repoId = AvpJson.string(body, "repoId");
        byte[] member = AvpJson.bytes(body, "memberKey", 32);
        if (!AvpBytes.same(caller, member)) {
            return Response.error(403, "forbidden", "the caller is not the member");
        }
        return Response.json(
                200, Tokens.toJson(Tokens.signAcceptance(repoId, member, System.currentTimeMillis() + 900_000, seed)));
    }

    // --- Replication, as a peer would offer it (SPEC 6.5, 9) -------------------------------------------

    /**
     * Receives a state (and its commit) as a peer's offer would carry it: the next state is adopted; a state
     * that forks the chain at a seq the host holds wins when its hash is lower (the host switches to it and
     * keeps the states it replaces as losing states), and is kept as a losing state otherwise.
     *
     * @return whether the host's chain changed
     */
    synchronized boolean offer(SignedManifest m, Commit commit) {
        Repo r = repos.get(m.state().repoId());
        long seq = m.state().manifestSeq();
        if (seq == r.chain.size() + 1) {
            if (ManifestRules.check(m, r.tip()) != ManifestRules.Verdict.OK) {
                return false;
            }
            return adopt(r, m, Optional.ofNullable(commit), false).isEmpty();
        }
        if (seq < 2 || seq > r.chain.size()) {
            return false;
        }
        SignedManifest prev = r.chain.get((int) seq - 2);
        if (ManifestRules.check(m, prev) != ManifestRules.Verdict.OK) {
            return false;
        }
        byte[] mine = r.hashAt(seq);
        byte[] theirs = Manifest.hash(m);
        if (AvpBytes.compare(theirs, mine) >= 0) {
            r.losing.put(AvpBytes.base64(theirs), m);
            return false;
        }
        List<SignedManifest> dropped = new ArrayList<>(r.chain.subList((int) seq - 1, r.chain.size()));
        r.chain.subList((int) seq - 1, r.chain.size()).clear();
        dropped.forEach(d -> r.losing.put(AvpBytes.base64(Manifest.hash(d)), d));
        Optional<Response> refused = adopt(r, m, Optional.ofNullable(commit), false);
        if (refused.isPresent()) {
            throw new IllegalStateException(
                    "the winning state's commit was refused: " + refused.get().status());
        }
        // Heads citing a dropped state are re-checked against the winning chain (SPEC 6.5).
        r.heads.removeIf(h -> {
            Commit c = r.accepted.get(h);
            boolean ok = binding(r, c).isEmpty();
            if (!ok) {
                r.rejected.add(h);
            }
            return !ok;
        });
        return true;
    }

    /** Adds a pending leave request directly, as replication from another host would. */
    synchronized void addLeave(LeaveRequest l) {
        repos.get(l.repoId()).leaves.put(AvpBytes.base64(l.memberKey()), l);
    }
}

package lol.trq.alts.internal.avp;

import static lol.trq.alts.internal.avp.Vectors.b64;
import static lol.trq.alts.internal.avp.Vectors.obj;
import static lol.trq.alts.internal.avp.Vectors.str;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import lol.trq.alts.AltsException;
import lol.trq.alts.internal.avp.Commits.Commit;
import lol.trq.alts.internal.avp.Manifest.SignedManifest;
import lol.trq.alts.internal.avp.ManifestRules.Verdict;
import lol.trq.alts.internal.vault.VerifiedChain;
import lol.trq.alts.internal.vault.VerifiedChain.CommitVerdict;
import org.junit.jupiter.api.Test;

/**
 * {@code acceptance.json} replayed from a client's side, with the vault client's own checks.
 *
 * <p>The file holds a host's rules (SPEC 6, 7, 8.3, 8.4): each step is the verdict one host gives an item.
 * The client keeps the chain the host's verdicts build and decides each step on its own terms, and this
 * test asserts it reaches the host's verdict:
 *
 * <ul>
 *   <li><b>Manifest states</b>, by SPEC 6.1 rules 1 to 5 and 6.2 ({@link ManifestRules}), against the
 *       client's verified tip. A diverged owner state (SPEC 6.5) is decided by the client's tie rule ({@link
 *       VerifiedChain#accepts(List, List)}): a state the host adopts in place of one the client holds must
 *       win it, and the client adopts the winning chain too; a diverged state the host answers {@code
 *       manifest_conflict} must lose it. At the end the client's tip is the host's {@code finalTip} in every
 *       scenario.
 *   <li><b>Commits</b>, by SPEC 7.5 rules 1 to 3 ({@link VerifiedChain#verifyCommit}): the recomputed id
 *       and the strict author signature, the removal cutoff with ancestry over every commit header the
 *       scenario has shown, and membership at the commit's epoch, of the cited state when it is on the
 *       client's chain and of a state at or after the cited seq otherwise. A commit the host accepts must
 *       pass; a commit the host refuses as {@code bad_request} must fail rule 1; a commit the host refuses as
 *       {@code forbidden} must fail rule 2 or 3 unless its refusal is the host's storage alone, which is
 *       checked too: a parent the host refused or dropped (SPEC 7.4). A commit the host answers {@code
 *       too_many_heads} must pass, since the client has no head bound; one it answers {@code missing_parents}
 *       must pass too, or be one the client refuses for the same lack: a citation of a state the client does
 *       not hold, which rule 3 then refuses, or a removed member's commit whose frontier names a commit the
 *       client has not seen, which rule 2 refuses until it has. Every head of {@code finalHeads} passes
 *       against the final chain.
 *   <li><b>Leave requests</b>, by {@link Tokens#leaveVerdict}: the SPEC 8.4 checks the owner's client makes
 *       before it acts on one. At the end, the latest request per member that still passes against the final
 *       tip is exactly {@code finalLeaves}.
 * </ul>
 *
 * <p>Only two classes are host-only, and they are counted, not replayed: {@code not_hosted} (SPEC 6.1 rule
 * 6, asserted to be a state that passes rules 1 to 5 and does not list the host) and publication
 * atomicity (SPEC 8.2, 8.3: the genesis or rotation commit carried with a state, asserted to be a state
 * that passes rules 1 to 5). The held commits are host storage. Of the 360 steps the client decides 352
 * (up from 326 with the constructions alone, which left the tie rule and rules 2 and 3 of SPEC 7.5 to the
 * client); the 8 host-only steps are skipped.
 */
class AcceptanceReplayTest {

    private static final JsonObject ROOT = Vectors.load("acceptance.json");

    /** Why a step is not replayed. */
    enum Skipped {
        NOT_HOSTED,
        PUBLISH_ATOMICITY
    }

    /** What happened to each step. */
    private record Tally(Map<String, Integer> decided, Map<Skipped, Integer> skipped, List<String> unexplained) {}

    /** The client's view of one scenario. */
    private static final class Client {
        final List<SignedManifest> chain = new ArrayList<>();
        final VerifiedChain.Ancestry ancestry = new VerifiedChain.Ancestry();
        final Map<String, Commit> accepted = new LinkedHashMap<>();
        final Map<String, Commit> seen = new LinkedHashMap<>();
        final Set<String> refused = new HashSet<>();
        final Map<String, Tokens.LeaveRequest> leaves = new LinkedHashMap<>();

        List<byte[]> hashes() {
            return hashes(chain);
        }

        static List<byte[]> hashes(List<SignedManifest> states) {
            List<byte[]> out = new ArrayList<>();
            states.forEach(m -> out.add(Manifest.hash(m)));
            return out;
        }

        VerifiedChain verified() {
            return VerifiedChain.of(chain);
        }

        CommitVerdict check(Commit c) {
            return chain.isEmpty()
                    ? CommitVerdict.BAD_ID_OR_SIGNATURE
                    : verified().verifyCommit(c, ancestry);
        }

        /** After a new tip, a commit the host accepted that now fails the client rules is dropped (SPEC 7.3). */
        void recheck() {
            VerifiedChain v = verified();
            accepted.entrySet().removeIf(e -> {
                boolean drop = v.verifyCommit(e.getValue(), ancestry) != CommitVerdict.OK;
                if (drop) {
                    refused.add(e.getKey());
                }
                return drop;
            });
        }

        void accept(Commit c) {
            ancestry.learn(c);
            seen.put(AvpBytes.base64(c.commitId()), c);
            accepted.put(AvpBytes.base64(c.commitId()), c);
        }
    }

    @Test
    void theClientReachesTheHostsVerdictOnEveryStepItDecides() {
        List<JsonObject> scenarios = Vectors.cases(ROOT, "scenarios", 78);
        Tally tally = new Tally(new TreeMap<>(), new TreeMap<>(), new ArrayList<>());
        int steps = 0;
        int tips = 0;
        for (JsonObject s : scenarios) {
            steps += replay(s, tally);
            tips++;
        }
        assertEquals(360, steps, "every step of every scenario");
        assertTrue(tally.unexplained().isEmpty(), String.join("\n", tally.unexplained()));

        int decided =
                tally.decided().values().stream().mapToInt(Integer::intValue).sum();
        int skipped =
                tally.skipped().values().stream().mapToInt(Integer::intValue).sum();
        assertEquals(steps, decided + skipped, "every step is decided or skipped for a stated reason");
        assertEquals(352, decided, "every step but the host-only classes is decided by the client");
        // Pinned, so a step that stops being decided (or a skip class that grows) is a visible change.
        assertEquals(
                new TreeMap<>(Map.ofEntries(
                        Map.entry("commit bad_request", 7),
                        Map.entry("commit forbidden", 16),
                        Map.entry("commit forbidden (a parent the host refused, SPEC 7.4)", 4),
                        Map.entry(
                                "commit missing_parents (a frontier commit the client has not seen: rule 2 refuses it"
                                        + " until then)",
                                2),
                        Map.entry("commit missing_parents (cites a state the client lacks: rule 3 refuses it too)", 2),
                        Map.entry("commit missing_parents (the client rules pass)", 4),
                        Map.entry("commit ok", 99),
                        Map.entry("commit too_many_heads (the client rules pass)", 2),
                        Map.entry("leave bad_request", 1),
                        Map.entry("leave forbidden", 2),
                        Map.entry("leave ok", 5),
                        Map.entry("manifest bad_request", 26),
                        Map.entry("manifest manifest_conflict", 10),
                        Map.entry("manifest ok", 172))),
                tally.decided());
        assertEquals(Map.of(Skipped.NOT_HOSTED, 2, Skipped.PUBLISH_ATOMICITY, 6), tally.skipped());
        assertEquals(78, tips, "every scenario's final tip, heads and leaves reproduced");
    }

    private static int replay(JsonObject scenario, Tally t) {
        String name = str(scenario, "name");
        byte[] hostKey = b64(scenario, "hostKey");
        Client client = new Client();
        int count = 0;
        for (JsonElement e : scenario.getAsJsonArray("steps")) {
            count++;
            JsonObject step = e.getAsJsonObject();
            String where = name + " step " + count + " (" + str(step, "label") + ")";
            String op = str(step, "op");
            String expect = str(step, "expect");
            switch (op) {
                case "manifest" -> manifestStep(step, expect, hostKey, client, where, t);
                case "commit" -> commitStep(step, expect, client, where, t);
                case "leave" -> leaveStep(step, expect, client, where, t);
                default -> t.unexplained().add(where + ": unknown op " + op);
            }
        }
        finalState(scenario, client, name, t);
        return count;
    }

    private static void finalState(JsonObject scenario, Client client, String name, Tally t) {
        JsonElement finalTip = scenario.get("finalTip");
        String want = finalTip.isJsonNull() ? null : finalTip.getAsString();
        String got = client.chain.isEmpty()
                ? null
                : AvpBytes.base64(Manifest.hash(client.chain.get(client.chain.size() - 1)));
        if (want == null ? got != null : !want.equals(got)) {
            t.unexplained().add(name + ": client tip " + got + " but host tip " + want);
            return;
        }
        for (JsonElement h : scenario.getAsJsonArray("finalHeads")) {
            Commit c = client.seen.get(h.getAsString());
            if (c == null || client.check(c) != CommitVerdict.OK) {
                t.unexplained().add(name + ": final head " + h.getAsString() + " does not pass the client rules");
            }
        }
        if (scenario.has("finalLeaves")) {
            Set<String> want2 = new TreeSet<>();
            for (JsonElement l : scenario.getAsJsonArray("finalLeaves")) {
                JsonObject o = l.getAsJsonObject();
                want2.add(str(o, "memberKey") + "@" + o.get("at").getAsLong());
            }
            Set<String> got2 = new TreeSet<>();
            Manifest.ManifestState tip =
                    client.chain.get(client.chain.size() - 1).state();
            for (Tokens.LeaveRequest l : client.leaves.values()) {
                if (Tokens.leaveVerdict(l, tip) == Tokens.LeaveVerdict.OK) {
                    got2.add(AvpBytes.base64(l.memberKey()) + "@" + l.at());
                }
            }
            if (!want2.equals(got2)) {
                t.unexplained().add(name + ": client pending leaves " + got2 + " but host " + want2);
            }
        }
    }

    private static void manifestStep(
            JsonObject step, String expect, byte[] hostKey, Client client, String where, Tally t) {
        JsonObject item = obj(step, "item");
        SignedManifest m;
        try {
            m = Manifest.signedFromJson(item.get("manifest"));
        } catch (AltsException malformed) {
            decide(t, "manifest", "bad_request", expect, where);
            return;
        }
        learnCarried(item, client);
        List<SignedManifest> chain = client.chain;
        SignedManifest tip = chain.isEmpty() ? null : chain.get(chain.size() - 1);
        Verdict v = ManifestRules.check(m, tip);
        String verdict = v.code().orElse("ok");
        Optional<List<SignedManifest>> fork = fork(m, chain);
        if (v == Verdict.NOT_LINKED && fork.isPresent() && str(step, "via").equals("offer")) {
            // A diverged owner state by replication (SPEC 6.5): the client's tie rule decides it. A client publish
            // is never adopted unless it extends the tip (SPEC 6.3), which the chain-link rule decides below.
            boolean wins = VerifiedChain.accepts(client.hashes(), Client.hashes(fork.get()));
            if (wins && expect.equals("ok")) {
                decide(t, "manifest", "ok", expect, where);
                chain.clear();
                chain.addAll(fork.get());
                carried(item, client);
                client.recheck();
                return;
            }
            if (!wins && expect.equals("manifest_conflict")) {
                decide(t, "manifest", "manifest_conflict", expect, where);
                return;
            }
            t.unexplained().add(where + ": tie rule " + (wins ? "wins" : "loses") + " but host " + expect);
            return;
        }
        if (verdict.equals(expect)) {
            decide(t, "manifest", verdict, expect, where);
            if (v == Verdict.OK) {
                chain.add(m);
                carried(item, client);
                client.recheck();
            }
            return;
        }
        if (v == Verdict.OK && expect.equals("not_hosted")) {
            // SPEC 6.1 rule 6 is the host's: the state passes every client rule and does not list it.
            if (m.state().hasHost(hostKey)) {
                t.unexplained().add(where + ": not_hosted for a state that lists the host");
            }
            t.skipped().merge(Skipped.NOT_HOSTED, 1, Integer::sum);
            return;
        }
        if (v == Verdict.OK
                && (expect.equals("bad_request") || expect.equals("missing_parents"))
                && publishRuleFails(m, tip, item, str(step, "via"), expect)) {
            t.skipped().merge(Skipped.PUBLISH_ATOMICITY, 1, Integer::sum);
            return;
        }
        t.unexplained().add(where + ": client " + v + " but host " + expect);
    }

    /**
     * A carried commit's header counts for ancestry whatever happens to its state (SPEC 7.3: every header
     * whose id recomputes and whose signature verifies), so a losing rotation commit can still cover a
     * frontier.
     */
    private static void learnCarried(JsonObject item, Client client) {
        try {
            if (item.has("commit")) {
                Commit c = Commits.fromJson(item.get("commit"));
                client.ancestry.learn(c);
                client.seen.put(AvpBytes.base64(c.commitId()), c);
            }
        } catch (AltsException malformed) {
            // A carried commit that does not decode teaches nothing.
        }
    }

    /** The commit carried with an adopted state is accepted with it. */
    private static void carried(JsonObject item, Client client) {
        if (item.has("commit")) {
            client.accept(Commits.fromJson(item.get("commit")));
        }
    }

    /**
     * The chain a valid state would make if it replaced the client's states from its seq on: present when the
     * state links to the client's state at the seq before and the client already holds another state there.
     */
    private static Optional<List<SignedManifest>> fork(SignedManifest m, List<SignedManifest> chain) {
        long seq = m.state().manifestSeq();
        if (seq < 2 || seq > chain.size()) {
            return Optional.empty();
        }
        SignedManifest prev = chain.get((int) seq - 2);
        if (ManifestRules.check(m, prev) != Verdict.OK
                || Arrays.equals(Manifest.hash(chain.get((int) seq - 1)), Manifest.hash(m))) {
            return Optional.empty();
        }
        List<SignedManifest> out = new ArrayList<>(chain.subList(0, (int) seq - 1));
        out.add(m);
        return Optional.of(out);
    }

    /**
     * SPEC 8.2 and 8.3: a genesis published without its first commit, an epoch-raising state without its
     * rotation commit, a carried commit of the wrong shape (citing another state, another epoch, an author
     * other than the owner, a genesis commit with parents) or that fails rule 1, or a carried commit whose
     * parents the host lacks.
     */
    private static boolean publishRuleFails(
            SignedManifest m, SignedManifest tip, JsonObject item, String via, String expect) {
        long seq = m.state().manifestSeq();
        boolean genesis = seq == 1;
        boolean raising = tip != null
                && ManifestRules.isNext(tip.state().keyEpoch(), m.state().keyEpoch());
        Optional<Commit> commit;
        try {
            commit = item.has("commit") ? Optional.of(Commits.fromJson(item.get("commit"))) : Optional.empty();
        } catch (AltsException malformed) {
            return expect.equals("bad_request");
        }
        if (commit.isEmpty()) {
            return expect.equals("bad_request") && ((genesis && via.equals("push")) || raising);
        }
        if (expect.equals("missing_parents")) {
            return !commit.get().parents().isEmpty();
        }
        Commit c = commit.get();
        boolean cites = c.manifestSeq() == seq && Arrays.equals(c.manifestHash(), Manifest.hash(m));
        boolean shaped = cites
                && (!(genesis || raising)
                        || (c.keyEpoch() == m.state().keyEpoch()
                                && Arrays.equals(c.author(), m.state().ownerKey())
                                && (!genesis || c.parents().isEmpty())));
        return !shaped || !Commits.verify(c);
    }

    private static void commitStep(JsonObject step, String expect, Client client, String where, Tally t) {
        Commit c;
        try {
            c = Commits.fromJson(step.get("item"));
        } catch (AltsException malformed) {
            decide(t, "commit", "bad_request", expect, where);
            return;
        }
        client.ancestry.learn(c);
        client.seen.put(AvpBytes.base64(c.commitId()), c);
        CommitVerdict v = client.check(c);
        String id = AvpBytes.base64(c.commitId());
        String result;
        switch (expect) {
            case "bad_request" -> result = v == CommitVerdict.BAD_ID_OR_SIGNATURE ? expect : v.name();
            case "ok" -> {
                result = v == CommitVerdict.OK ? expect : v.name();
                if (v == CommitVerdict.OK) {
                    client.accept(c);
                }
            }
            case "forbidden" -> {
                client.refused.add(id);
                if (v == CommitVerdict.AFTER_REMOVAL_CUTOFF || v == CommitVerdict.NOT_A_MEMBER_AT_EPOCH) {
                    result = expect;
                } else if (v == CommitVerdict.OK && parentRefused(c, client)) {
                    result = "forbidden (a parent the host refused, SPEC 7.4)";
                } else {
                    result = v.name();
                }
            }
            case "missing_parents", "too_many_heads" -> {
                if (v == CommitVerdict.OK) {
                    result = expect + " (the client rules pass)";
                } else if (expect.equals("missing_parents")
                        && v == CommitVerdict.NOT_A_MEMBER_AT_EPOCH
                        && !onChain(c, client)) {
                    result = expect + " (cites a state the client lacks: rule 3 refuses it too)";
                } else if (expect.equals("missing_parents")
                        && v == CommitVerdict.AFTER_REMOVAL_CUTOFF
                        && frontierUnseen(c, client)) {
                    result = expect + " (a frontier commit the client has not seen: rule 2 refuses it until then)";
                } else {
                    result = v.name();
                }
            }
            default -> result = "unknown " + expect;
        }
        if (result.startsWith(expect)) {
            t.decided().merge("commit " + result, 1, Integer::sum);
        } else {
            t.unexplained().add(where + ": client " + result + " but host " + expect);
        }
    }

    private static boolean parentRefused(Commit c, Client client) {
        return c.parents().stream().anyMatch(p -> client.refused.contains(AvpBytes.base64(p)));
    }

    private static boolean frontierUnseen(Commit c, Client client) {
        return client.chain.get(client.chain.size() - 1).state().removalOf(c.author()).stream()
                .flatMap(r -> r.frontier().stream())
                .anyMatch(id -> !client.ancestry.knows(id));
    }

    private static boolean onChain(Commit c, Client client) {
        long seq = c.manifestSeq();
        return seq >= 1
                && seq <= client.chain.size()
                && Arrays.equals(Manifest.hash(client.chain.get((int) seq - 1)), c.manifestHash());
    }

    private static void leaveStep(JsonObject step, String expect, Client client, String where, Tally t) {
        String verdict;
        Tokens.LeaveRequest l = null;
        try {
            l = Tokens.leaveFromJson(obj(step, "item"));
            verdict = Tokens.leaveVerdict(
                            l, client.chain.get(client.chain.size() - 1).state())
                    .code()
                    .orElse("ok");
        } catch (AltsException malformed) {
            verdict = "bad_request";
        }
        decide(t, "leave", verdict, expect, where);
        if (verdict.equals("ok") && expect.equals("ok")) {
            client.leaves.put(AvpBytes.base64(l.memberKey()), l);
        }
    }

    private static void decide(Tally t, String op, String verdict, String expect, String where) {
        if (!verdict.equals(expect)) {
            t.unexplained().add(where + ": client " + verdict + " but host " + expect);
            return;
        }
        t.decided().merge(op + " " + expect, 1, Integer::sum);
    }
}

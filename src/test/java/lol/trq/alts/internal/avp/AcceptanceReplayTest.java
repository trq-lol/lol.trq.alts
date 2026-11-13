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
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import lol.trq.alts.AltsException;
import lol.trq.alts.internal.avp.Commits.Commit;
import lol.trq.alts.internal.avp.Manifest.SignedManifest;
import lol.trq.alts.internal.avp.ManifestRules.Verdict;
import org.junit.jupiter.api.Test;

/**
 * {@code acceptance.json} replayed from a client's side.
 *
 * <p>The file holds a host's rules (SPEC 6, 7, 8.3, 8.4): each step is the verdict one host gives an item.
 * A client decides part of the same question on its own terms, and this test replays exactly that part
 * and asserts the client reaches the host's verdict:
 *
 * <ul>
 *   <li><b>Manifest states</b>, by SPEC 6.1 rules 1 to 5 and 6.2 ({@link ManifestRules}): structure, owner
 *       signature, genesis and the recomputed repository id, the chain link to the client's verified tip,
 *       and the content rules. A state the client accepts extends its chain, and at the end the client's
 *       tip is the host's {@code finalTip}.
 *   <li><b>Commits</b>, by SPEC 7.5 rule 1: structure, repository id, the recomputed commit id and the
 *       strict author signature. Every commit step is checked; a step the host refuses as {@code
 *       bad_request} must fail it, and every other step must pass it.
 *   <li><b>Leave requests</b>, by the SPEC 8.4 checks the owner's client makes before it acts on one:
 *       signature, repository id, a member of the tip who is not the owner.
 * </ul>
 *
 * <p>The rest is host-only, or a client rule that lands with the vault client (T6), and is counted, not
 * replayed: {@code not_hosted} (SPEC 6.1 rule 6, asserted to be a state that passes rules 1 to 5 and does
 * not list the host); publication atomicity (SPEC 8.2, 8.3: the genesis or rotation commit carried with a
 * state, asserted to be a state that passes rules 1 to 5); the host's commit decisions beyond rule 1
 * (membership, epoch and removal cutoff, held commits, unknown parents or manifests, the head bound);
 * diverged owner states, which a host resolves by the tie rule (SPEC 6.5) and after which the host's view
 * is not the client's; and the final heads, held commits and pending leaves, which are host storage.
 */
class AcceptanceReplayTest {

    private static final JsonObject ROOT = Vectors.load("acceptance.json");

    /** Why a step is not, or not fully, replayed. */
    enum Skipped {
        NOT_HOSTED,
        PUBLISH_ATOMICITY,
        COMMIT_ACCEPTED_BY_HOST,
        COMMIT_FORBIDDEN_BY_HOST,
        COMMIT_MISSING_PARENTS,
        COMMIT_TOO_MANY_HEADS,
        DIVERGED_OWNER_STATE,
        AFTER_DIVERGED_STATE
    }

    /** What happened to each step: decided by the client, skipped, or (for commits) left past rule 1. */
    private record Tally(
            Map<String, Integer> decided,
            Map<Skipped, Integer> skipped,
            Map<Skipped, Integer> commitRest,
            List<String> unexplained,
            int[] tips) {}

    @Test
    void theClientReachesTheHostsVerdictOnEveryStepItDecides() {
        List<JsonObject> scenarios = Vectors.cases(ROOT, "scenarios", 78);
        Tally tally = new Tally(new TreeMap<>(), new TreeMap<>(), new TreeMap<>(), new ArrayList<>(), new int[2]);
        int steps = 0;
        for (JsonObject s : scenarios) {
            steps += replay(s, tally);
        }
        assertEquals(360, steps, "every step of every scenario");
        assertTrue(tally.unexplained().isEmpty(), String.join("\n", tally.unexplained()));

        int decided =
                tally.decided().values().stream().mapToInt(Integer::intValue).sum();
        int skipped =
                tally.skipped().values().stream().mapToInt(Integer::intValue).sum();
        assertEquals(steps, decided + skipped, "every step is decided or skipped for a stated reason");
        // Pinned, so a step that stops being decided (or a skip class that grows) is a visible change.
        assertEquals(
                Map.of(
                        "commit bad_request", 7,
                        "commit rule 1 passes", 119,
                        "leave bad_request", 1,
                        "leave forbidden", 2,
                        "leave ok", 5,
                        "manifest bad_request", 26,
                        "manifest manifest_conflict", 9,
                        "manifest ok", 157),
                tally.decided());
        assertEquals(
                Map.of(
                        Skipped.NOT_HOSTED, 2,
                        Skipped.PUBLISH_ATOMICITY, 6,
                        Skipped.DIVERGED_OWNER_STATE, 11,
                        Skipped.AFTER_DIVERGED_STATE, 15),
                tally.skipped());
        assertEquals(
                Map.of(
                        Skipped.COMMIT_ACCEPTED_BY_HOST, 97,
                        Skipped.COMMIT_FORBIDDEN_BY_HOST, 12,
                        Skipped.COMMIT_MISSING_PARENTS, 8,
                        Skipped.COMMIT_TOO_MANY_HEADS, 2),
                tally.commitRest());
        assertEquals(67, tally.tips()[0], "scenarios whose final tip the client reproduces");
        assertEquals(11, tally.tips()[1], "scenarios whose host view left the client's at a diverged state");
    }

    private static int replay(JsonObject scenario, Tally t) {
        String name = str(scenario, "name");
        byte[] hostKey = b64(scenario, "hostKey");
        List<SignedManifest> chain = new ArrayList<>();
        boolean diverged = false;
        int count = 0;
        for (JsonElement e : scenario.getAsJsonArray("steps")) {
            count++;
            JsonObject step = e.getAsJsonObject();
            String where = name + " step " + count + " (" + str(step, "label") + ")";
            String op = str(step, "op");
            String expect = str(step, "expect");
            if (diverged) {
                t.skipped().merge(Skipped.AFTER_DIVERGED_STATE, 1, Integer::sum);
                continue;
            }
            switch (op) {
                case "manifest" -> diverged = manifestStep(step, expect, hostKey, chain, where, t);
                case "commit" -> commitStep(step, expect, chain, where, t);
                case "leave" -> leaveStep(step, expect, chain, where, t);
                default -> t.unexplained().add(where + ": unknown op " + op);
            }
        }
        if (diverged) {
            t.tips()[1]++;
        } else {
            JsonElement finalTip = scenario.get("finalTip");
            String want = finalTip.isJsonNull() ? null : finalTip.getAsString();
            String got = chain.isEmpty() ? null : AvpBytes.base64(Manifest.hash(chain.get(chain.size() - 1)));
            if (want == null ? got != null : !want.equals(got)) {
                t.unexplained().add(name + ": client tip " + got + " but host tip " + want);
            }
            t.tips()[0]++;
        }
        return count;
    }

    /** Returns true when the host's view has left the client's (a diverged owner state was adopted). */
    private static boolean manifestStep(
            JsonObject step, String expect, byte[] hostKey, List<SignedManifest> chain, String where, Tally t) {
        JsonObject item = obj(step, "item");
        SignedManifest m;
        try {
            m = Manifest.signedFromJson(item.get("manifest"));
        } catch (AltsException malformed) {
            decide(t, "manifest", "bad_request", expect, where);
            return false;
        }
        SignedManifest tip = chain.isEmpty() ? null : chain.get(chain.size() - 1);
        Verdict v = ManifestRules.check(m, tip);
        String client = v.code().orElse("ok");
        if (client.equals(expect)) {
            decide(t, "manifest", client, expect, where);
            if (v == Verdict.OK) {
                chain.add(m);
            }
            return false;
        }
        if (v == Verdict.OK && expect.equals("not_hosted")) {
            // SPEC 6.1 rule 6 is the host's: the state passes every client rule and does not list it.
            if (m.state().hasHost(hostKey)) {
                t.unexplained().add(where + ": not_hosted for a state that lists the host");
            }
            t.skipped().merge(Skipped.NOT_HOSTED, 1, Integer::sum);
            return false;
        }
        if (v == Verdict.OK
                && (expect.equals("bad_request") || expect.equals("missing_parents"))
                && publishRuleFails(m, tip, item, str(step, "via"), expect)) {
            t.skipped().merge(Skipped.PUBLISH_ATOMICITY, 1, Integer::sum);
            return false;
        }
        if (v == Verdict.NOT_LINKED && expect.equals("ok") && forks(m, chain)) {
            // The host adopted a state the client's chain does not extend to: a diverged owner state that
            // won the tie rule (SPEC 6.5). It is still a valid state on its own branch, and where it
            // replaces a state the client holds, it has the bytewise-lower manifest hash.
            long seq = m.state().manifestSeq();
            SignedManifest prev = seq == 1 ? null : chain.get((int) seq - 2);
            if (ManifestRules.check(m, prev) != Verdict.OK) {
                t.unexplained().add(where + ": an adopted diverged state that fails the client rules");
            }
            if (seq <= chain.size()
                    && AvpBytes.compare(Manifest.hash(m), Manifest.hash(chain.get((int) seq - 1))) >= 0) {
                t.unexplained().add(where + ": an adopted diverged state that does not win the tie rule");
            }
            t.skipped().merge(Skipped.DIVERGED_OWNER_STATE, 1, Integer::sum);
            return true;
        }
        t.unexplained().add(where + ": client " + v + " but host " + expect);
        return false;
    }

    /** A valid state whose seq the client already holds another state at, or that extends an older one. */
    private static boolean forks(SignedManifest m, List<SignedManifest> chain) {
        long seq = m.state().manifestSeq();
        if (seq < 1 || seq > chain.size() + 1) {
            return false;
        }
        if (seq <= chain.size() && Arrays.equals(Manifest.hash(chain.get((int) seq - 1)), Manifest.hash(m))) {
            return false;
        }
        return seq == 1 || Manifest.linksTo(m, chain.get((int) seq - 2)) || seq <= chain.size();
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

    private static void commitStep(JsonObject step, String expect, List<SignedManifest> chain, String where, Tally t) {
        boolean ruleOne;
        try {
            Commit c = Commits.fromJson(step.get("item"));
            boolean repoOk =
                    chain.isEmpty() || c.repoId().equals(chain.get(0).state().repoId());
            ruleOne = repoOk && Commits.verify(c);
        } catch (AltsException malformed) {
            ruleOne = false;
        }
        if (expect.equals("bad_request")) {
            if (ruleOne) {
                t.unexplained().add(where + ": host bad_request but the commit passes rule 1");
            }
            decide(t, "commit", "bad_request", expect, where);
            return;
        }
        if (!ruleOne) {
            t.unexplained().add(where + ": host " + expect + " but the commit fails rule 1");
            return;
        }
        t.decided().merge("commit rule 1 passes", 1, Integer::sum);
        Skipped rest =
                switch (expect) {
                    case "ok" -> Skipped.COMMIT_ACCEPTED_BY_HOST;
                    case "forbidden" -> Skipped.COMMIT_FORBIDDEN_BY_HOST;
                    case "missing_parents" -> Skipped.COMMIT_MISSING_PARENTS;
                    case "too_many_heads" -> Skipped.COMMIT_TOO_MANY_HEADS;
                    default -> null;
                };
        if (rest == null) {
            t.unexplained().add(where + ": unexpected commit verdict " + expect);
        } else {
            t.commitRest().merge(rest, 1, Integer::sum);
        }
    }

    private static void leaveStep(JsonObject step, String expect, List<SignedManifest> chain, String where, Tally t) {
        String client;
        try {
            Tokens.LeaveRequest l = Tokens.leaveFromJson(obj(step, "item"));
            Manifest.ManifestState tip = chain.get(chain.size() - 1).state();
            if (!Tokens.verifyLeave(l) || !l.repoId().equals(tip.repoId())) {
                client = "bad_request";
            } else if (!tip.hasMember(l.memberKey()) || Arrays.equals(l.memberKey(), tip.ownerKey())) {
                client = "forbidden";
            } else {
                client = "ok";
            }
        } catch (AltsException malformed) {
            client = "bad_request";
        }
        decide(t, "leave", client, expect, where);
    }

    private static void decide(Tally t, String op, String client, String expect, String where) {
        if (!client.equals(expect)) {
            t.unexplained().add(where + ": client " + client + " but host " + expect);
            return;
        }
        t.decided().merge(op + " " + expect, 1, Integer::sum);
    }
}

package lol.trq.alts.internal.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.function.Function;
import lol.trq.alts.internal.avp.AvpCrypto;
import lol.trq.alts.internal.avp.Commits;
import lol.trq.alts.internal.avp.Commits.Commit;
import org.junit.jupiter.api.Test;

/** The pin and the tie rule over chains of hashes (AVP SPEC 6.4, 6.5). */
class VerifiedChainTest {

    private static byte[] h(int first) {
        byte[] b = new byte[32];
        b[0] = (byte) first;
        return b;
    }

    @Test
    void aChainThatContainsThePinIsAdopted() {
        List<byte[]> pinned = List.of(h(1), h(2), h(3));
        assertTrue(VerifiedChain.accepts(pinned, List.of(h(1), h(2), h(3))));
        assertTrue(VerifiedChain.accepts(pinned, List.of(h(1), h(2), h(3), h(4))));
    }

    @Test
    void aPrefixOfThePinnedChainIsARollback() {
        assertFalse(VerifiedChain.accepts(List.of(h(1), h(2), h(3)), List.of(h(1), h(2))));
    }

    @Test
    void aDivergedChainWinsOnlyWithTheLowerHashAtTheForkAndMayEndBelowThePin() {
        List<byte[]> pinned = List.of(h(1), h(5), h(6), h(7));
        assertTrue(VerifiedChain.accepts(pinned, List.of(h(1), h(4))), "lower at the fork, shorter");
        assertFalse(VerifiedChain.accepts(pinned, List.of(h(1), h(9), h(1), h(1), h(1))), "higher at the fork");
        assertEquals(1, VerifiedChain.fork(pinned, List.of(h(1), h(4))));
        assertEquals(-1, VerifiedChain.fork(pinned, List.of(h(1), h(5))));
    }

    @Test
    void theLearnedGraphStopsAtItsBound() {
        byte[] key = AvpCrypto.randomBytes(32);
        byte[] seed = AvpCrypto.randomBytes(32);
        Function<List<byte[]>, Commit> commit = parents ->
                Commits.seal(key, new Commits.Header("r", parents, 1, new byte[32], 0), new byte[] {'{', '}'}, seed);
        var a = commit.apply(List.of());
        var b = commit.apply(List.of(a.commitId()));
        var c = commit.apply(List.of(b.commitId()));
        VerifiedChain.Ancestry graph = new VerifiedChain.Ancestry(2);
        graph.learn(a);
        graph.learn(b);
        graph.learn(c);
        assertTrue(graph.knows(a.commitId()) && graph.knows(b.commitId()));
        assertFalse(graph.knows(c.commitId()), "past the bound nothing more is learned");
        assertTrue(graph.isAncestor(a.commitId(), List.of(b.commitId())));
        assertFalse(graph.isAncestor(a.commitId(), List.of(c.commitId())), "fails closed: no edge, no ancestor");
        assertEquals(65_536, VerifiedChain.Ancestry.MAX_HEADERS);
    }

    @Test
    void aChainThatForksAtGenesisIsNeverAdopted() {
        assertFalse(VerifiedChain.accepts(List.of(h(5), h(6)), List.of(h(1), h(6))));
    }
}

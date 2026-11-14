package lol.trq.alts.internal.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
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
    void aChainThatForksAtGenesisIsNeverAdopted() {
        assertFalse(VerifiedChain.accepts(List.of(h(5), h(6)), List.of(h(1), h(6))));
    }
}

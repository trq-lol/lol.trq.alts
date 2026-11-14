package lol.trq.alts.internal.vault;

import java.util.List;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;
import lol.trq.alts.internal.avp.Payload;

/**
 * What a vault keeps between runs, for a host to persist (the content of a snapshot): the verified chain as
 * its {@code manifestHash}es, whose last entry is the pin of SPEC 6.4; every data key this device has held,
 * by epoch; the clock; the local payload; and whether this member left.
 *
 * <p>It holds secrets (the data keys and the payload's credentials), so {@link #toString()} shows neither.
 *
 * @param repoId the repository
 * @param chainHashes the {@code manifestHash} of every verified state, genesis first; the last is the pin
 * @param retainedKeys the data key of every epoch this device has held, by {@code keyEpoch}
 * @param hlcAt the clock's milliseconds
 * @param hlcN the clock's counter
 * @param local the local payload, the merge of every head read, under the policy
 * @param left whether this member sent a leave request and stopped syncing
 * @author trq
 * @since 1.0.0
 */
public record EngineState(
        String repoId,
        List<byte[]> chainHashes,
        SortedMap<Long, byte[]> retainedKeys,
        long hlcAt,
        long hlcN,
        Payload local,
        boolean left) {

    /**
     * Copies the arrays.
     *
     * @throws IllegalArgumentException if the chain is empty
     */
    public EngineState {
        chainHashes = HostClient.copyIds(chainHashes);
        if (chainHashes.isEmpty()) {
            throw new IllegalArgumentException("a vault state holds at least the genesis hash");
        }
        SortedMap<Long, byte[]> keys = new TreeMap<>();
        for (Map.Entry<Long, byte[]> e : retainedKeys.entrySet()) {
            keys.put(e.getKey(), e.getValue().clone());
        }
        retainedKeys = keys;
    }

    /**
     * The retained keys.
     *
     * @return copies, which the caller zeroes
     */
    @Override
    public SortedMap<Long, byte[]> retainedKeys() {
        SortedMap<Long, byte[]> out = new TreeMap<>();
        retainedKeys.forEach((k, v) -> out.put(k, v.clone()));
        return out;
    }

    /**
     * How many epoch keys are retained, without copying any.
     *
     * @return the count
     */
    public int epochKeyCount() {
        return retainedKeys.size();
    }

    /**
     * The chain hashes.
     *
     * @return copies
     */
    @Override
    public List<byte[]> chainHashes() {
        return HostClient.copyIds(chainHashes);
    }

    /**
     * The repository and the pin's seq only; never a key or the payload.
     *
     * @return a description
     */
    @Override
    public String toString() {
        return "EngineState[" + repoId + ", seq " + chainHashes.size() + ", " + retainedKeys.size()
                + " epoch keys, left=" + left + "]";
    }
}

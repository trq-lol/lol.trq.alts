package lol.trq.alts.internal.vault;

import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;
import lol.trq.alts.internal.avp.Tokens.LeaveRequest;

/**
 * What one pull found and did (AVP SPEC 5, 6.4, 6.5, 7.5, 8.4).
 *
 * @param newStates the verified states the pull added to the chain
 * @param divergedAt the seq at which the pull adopted a diverged chain that won the tie rule (SPEC 6.5): two
 *     owner devices published there while apart, and states of the losing side were dropped; empty when the
 *     chain only grew
 * @param policyTurnedOn whether the refresh-token policy went from withhold to share with this pull (SPEC 5.1)
 * @param readableHeads the verified heads this device read and merged
 * @param unreadableHeads the verified heads this device cannot read (no key for their epoch, or a payload that
 *     does not open or is not version 2), left alone for another member
 * @param discardedCommits the heads that failed a client check of SPEC 7.5: never merged, never a parent
 * @param malformedItems the head and leave items of the answer that did not decode at all
 * @param leaves the pending leave requests that pass the SPEC 8.4 checks against the tip
 * @param mergeCommit the merge commit pushed after the pull, when it read more than one head
 * @author trq
 * @since 1.0.0
 */
public record PullReport(
        int newStates,
        OptionalLong divergedAt,
        boolean policyTurnedOn,
        List<byte[]> readableHeads,
        List<byte[]> unreadableHeads,
        List<byte[]> discardedCommits,
        int malformedItems,
        List<LeaveRequest> leaves,
        Optional<byte[]> mergeCommit) {

    /** Copies the lists. */
    public PullReport {
        readableHeads = HostClient.copyIds(readableHeads);
        unreadableHeads = HostClient.copyIds(unreadableHeads);
        discardedCommits = HostClient.copyIds(discardedCommits);
        leaves = List.copyOf(leaves);
        mergeCommit = mergeCommit.map(byte[]::clone);
    }

    PullReport withMerge(Optional<byte[]> merge) {
        return new PullReport(
                newStates,
                divergedAt,
                policyTurnedOn,
                readableHeads,
                unreadableHeads,
                discardedCommits,
                malformedItems,
                leaves,
                merge);
    }
}

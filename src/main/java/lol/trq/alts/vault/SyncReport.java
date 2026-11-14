package lol.trq.alts.vault;

import java.util.List;
import java.util.OptionalLong;

/**
 * What one sync with the home host found and did (AVP SPEC 5, 6.4, 6.5, 7.5, 8.4), and what the owner may
 * have to act on: pending leave requests, a diverged owner chain, and a policy that started sharing refresh
 * tokens.
 *
 * @author trq
 * @since 1.0.0
 */
public final class SyncReport {

    private final int newStates;
    private final OptionalLong divergedAt;
    private final boolean policyTurnedOn;
    private final int readableHeads;
    private final int unreadableHeads;
    private final int discardedCommits;
    private final int malformedItems;
    private final List<VaultMember> pendingLeaves;
    private final boolean merged;

    SyncReport(
            int newStates,
            OptionalLong divergedAt,
            boolean policyTurnedOn,
            int readableHeads,
            int unreadableHeads,
            int discardedCommits,
            int malformedItems,
            List<VaultMember> pendingLeaves,
            boolean merged) {
        this.newStates = newStates;
        this.divergedAt = divergedAt;
        this.policyTurnedOn = policyTurnedOn;
        this.readableHeads = readableHeads;
        this.unreadableHeads = unreadableHeads;
        this.discardedCommits = discardedCommits;
        this.malformedItems = malformedItems;
        this.pendingLeaves = List.copyOf(pendingLeaves);
        this.merged = merged;
    }

    /**
     * How many verified manifest states the sync added to this device's chain: every state for the open or
     * join that first read the repository, the states past the pin for a resume.
     *
     * @return the count
     * @since 1.0.0
     */
    public int newStates() {
        return newStates;
    }

    /**
     * The seq at which this device adopted a diverged owner chain that won the tie rule (SPEC 6.5): two owner
     * devices published there while apart, and the states of the losing side were dropped. Show it to the
     * owner; empty when the chain only grew.
     *
     * @return the fork seq, or empty
     * @since 1.0.0
     */
    public OptionalLong divergedAt() {
        return divergedAt;
    }

    /**
     * Whether the repository's refresh-token policy went from withhold to share with this sync (SPEC 5.1), or,
     * for the open or join that first read it, whether it shares. Show it to the member the first time: from
     * now on, refresh tokens the members put are shared.
     *
     * @return whether sharing turned on
     * @since 1.0.0
     */
    public boolean policyTurnedOn() {
        return policyTurnedOn;
    }

    /**
     * How many verified heads this device read and merged.
     *
     * @return the count
     * @since 1.0.0
     */
    public int readableHeads() {
        return readableHeads;
    }

    /**
     * How many verified heads this device cannot read (no key for their epoch, or a payload that does not
     * open or is not version 2). They are left alone, not merged, and are not a failure.
     *
     * @return the count
     * @since 1.0.0
     */
    public int unreadableHeads() {
        return unreadableHeads;
    }

    /**
     * How many heads failed a client check of SPEC 7.5 (a forged commit, a removed member's commit past its
     * cutoff, a citation that does not hold): never merged, never a parent.
     *
     * @return the count
     * @since 1.0.0
     */
    public int discardedCommits() {
        return discardedCommits;
    }

    /**
     * How many head or leave items of the host's answer did not decode at all.
     *
     * @return the count
     * @since 1.0.0
     */
    public int malformedItems() {
        return malformedItems;
    }

    /**
     * The members whose signed leave request is pending and passes the SPEC 8.4 checks. The owner removes
     * them with {@link SharedVault#processLeaves()}.
     *
     * @return the leaving members
     * @since 1.0.0
     */
    public List<VaultMember> pendingLeaves() {
        return pendingLeaves;
    }

    /**
     * Whether the sync pushed a merge commit, because it read more than one head.
     *
     * @return whether it merged
     * @since 1.0.0
     */
    public boolean merged() {
        return merged;
    }

    /**
     * The counts.
     *
     * @return a description
     * @since 1.0.0
     */
    @Override
    public String toString() {
        return "SyncReport[newStates=" + newStates + ", divergedAt=" + divergedAt + ", policyTurnedOn="
                + policyTurnedOn + ", readable=" + readableHeads + ", unreadable=" + unreadableHeads
                + ", discarded=" + discardedCommits + ", malformed=" + malformedItems + ", leaves="
                + pendingLeaves.size() + ", merged=" + merged + "]";
    }
}

package lol.trq.alts.account;

import com.google.gson.annotations.SerializedName;
import java.util.List;

/**
 * The players an account has blocked, from {@code GET /privacy/blocklist}.
 *
 * @param blockedProfiles the blocked players' UUIDs, dashed
 * @author trq
 * @since 0.12.0
 */
public record Blocklist(@SerializedName("blockedProfiles") List<String> blockedProfiles) {

    /** Normalises a missing list to empty and every id to dashed form. */
    public Blocklist {
        blockedProfiles = blockedProfiles == null
                ? List.of()
                : blockedProfiles.stream().map(Uuids::dashed).toList();
    }

    /**
     * Returns whether a player is blocked.
     *
     * @param uuid the player's UUID, dashed or undashed
     * @return true if the player is on the list
     * @since 0.12.0
     */
    public boolean blocks(String uuid) {
        return uuid != null && blockedProfiles.contains(Uuids.dashed(uuid));
    }

    /**
     * Returns whether nobody is blocked.
     *
     * @return true if the list is empty
     * @since 0.12.0
     */
    public boolean isEmpty() {
        return blockedProfiles.isEmpty();
    }
}

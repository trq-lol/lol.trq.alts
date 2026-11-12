package lol.trq.alts.account;

import com.google.gson.annotations.SerializedName;

/**
 * A player's public identity — the name and UUID anyone can look up, with nothing an account owner alone
 * can see.
 *
 * @param uuid the player's UUID, dashed
 * @param name the player's current username, in the capitalisation the player chose
 * @author trq
 * @since 0.12.0
 */
public record PublicProfile(
        @SerializedName("id") String uuid,
        @SerializedName("name") String name) {

    /** Normalises the id to dashed form, whichever way it arrived. */
    public PublicProfile {
        uuid = Uuids.dashed(uuid);
    }
}

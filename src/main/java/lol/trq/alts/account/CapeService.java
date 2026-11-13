package lol.trq.alts.account;

import java.util.List;

/**
 * Shows or hides the account's capes. The account's owned capes come from the profile read
 * ({@link ProfileService#fetch()} → {@link PlayerProfile#capes()}), so there is no separate list call.
 *
 * @author trq
 * @since 1.0.0
 */
public interface CapeService {

    /**
     * Returns the capes the account owns, as a convenience over reading them off the profile.
     *
     * @return the owned capes
     * @throws lol.trq.alts.AltsException if the token was refused or the service failed
     * @since 1.0.0
     */
    List<Cape> owned();

    /**
     * Shows the cape with the given id.
     *
     * @param capeId the cape id (from {@link Cape#id()})
     * @return the updated profile
     * @throws lol.trq.alts.AltsException if the token was refused or the cape is not owned
     * @since 1.0.0
     */
    PlayerProfile setActive(String capeId);

    /**
     * Hides whatever cape is shown.
     *
     * @throws lol.trq.alts.AltsException if the token was refused or the service failed
     * @since 1.0.0
     */
    void hide();

    /**
     * Hides whatever cape is shown and returns the profile as it stands afterwards, the way
     * {@link #setActive(String)} does.
     *
     * @return the updated profile, or {@code null} when the service confirmed the change without sending
     *     one back
     * @throws lol.trq.alts.AltsException if the token was refused or the service failed
     * @since 0.12.0
     */
    default PlayerProfile hideActive() {
        hide();
        return null;
    }
}

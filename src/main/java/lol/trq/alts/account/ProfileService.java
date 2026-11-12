package lol.trq.alts.account;

import java.util.Optional;

/**
 * Reads an account's full Minecraft profile — name, UUID, skins, capes, and any pending moderation
 * actions — and creates one for an entitled account that has none. The slim name-and-UUID read the auth
 * chain performs is separate and internal; this is the whole picture a host shows.
 *
 * @author trq
 * @since 1.0.0
 */
public interface ProfileService {

    /**
     * Fetches the full profile.
     *
     * <p>An account with no profile fails this with a 404, which {@link AccountException#notFound()}
     * reports; {@link #fetchIfPresent()} is the form that treats it as an answer.
     *
     * @return the profile
     * @throws AccountException if the token was refused, the account has no profile, or the service
     *     failed
     * @since 1.0.0
     */
    PlayerProfile fetch() throws AccountException;

    /**
     * Fetches the full profile, treating "this account has no profile" as an answer rather than a
     * failure.
     *
     * <p>An account can authenticate perfectly well and still have no profile: it owns nothing, or it
     * is entitled — through a subscription, say — and has never chosen a name. The profile read alone
     * cannot tell those two apart; pair an empty result with {@link EntitlementService#fetch()}, and
     * where the account is entitled, {@link #create(String)} is what gives it a profile.
     *
     * @return the profile, or empty when the account has none
     * @throws AccountException if the token was refused or the service failed
     * @since 0.12.0
     */
    default Optional<PlayerProfile> fetchIfPresent() throws AccountException {
        try {
            return Optional.ofNullable(fetch());
        } catch (AccountException failure) {
            if (failure.notFound()) {
                return Optional.empty();
            }
            throw failure;
        }
    }

    /**
     * Creates the profile of an entitled account that does not have one yet, under the given name.
     *
     * <p>The name is checked locally first — three to sixteen letters, digits, or underscores — and one
     * that could never be accepted is reported as {@link ProfileCreationResult.Outcome#INVALID_NAME}
     * without a request being sent.
     *
     * @param name the username to create the profile with
     * @return the classified outcome, carrying the new profile on success
     * @throws AccountException only on a transport failure the call could not classify; a refused or
     *     rejected creation is a {@link ProfileCreationResult}, not an exception
     * @throws UnsupportedOperationException if this implementation predates profile creation
     * @since 0.12.0
     */
    default ProfileCreationResult create(String name) throws AccountException {
        throw new UnsupportedOperationException("profile creation is not supported by this implementation");
    }
}

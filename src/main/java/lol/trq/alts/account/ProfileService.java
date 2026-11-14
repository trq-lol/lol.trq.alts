package lol.trq.alts.account;

import java.util.Optional;

/**
 * Reads an account's full Minecraft profile — name, UUID, skins, capes, and any pending moderation
 * actions — and creates one for an entitled account that has none. The slim name-and-UUID read the auth
 * chain performs is separate and internal; this is the whole picture a host shows.
 *
 * <p>Not designed for host implementation; methods may be added in minor releases.
 *
 * @author trq
 * @since 0.11.0
 */
public interface ProfileService {

    /**
     * Fetches the full profile.
     *
     * <p>An account with no profile (the service answers 404) fails this with kind
     * {@link lol.trq.alts.AltsFailure.Kind#NOT_ENTITLED}, as sign-in and check report it;
     * {@link #fetchIfPresent()} is the form that treats it as an answer.
     *
     * @return the profile
     * @throws lol.trq.alts.AltsException if the token was refused, the account has no profile, or the service
     *     failed
     * @since 0.11.0
     */
    PlayerProfile fetch();

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
     * @throws lol.trq.alts.AltsException if the token was refused or the service failed
     * @since 0.12.0
     */
    default Optional<PlayerProfile> fetchIfPresent() {
        try {
            return Optional.ofNullable(fetch());
        } catch (lol.trq.alts.AltsException failure) {
            if (failure.kind() == lol.trq.alts.AltsFailure.Kind.NOT_ENTITLED) {
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
     * <p>Never throws for a refusal or an unreachable service: each is a {@link ProfileCreationResult},
     * a failure being {@link ProfileCreationResult.Outcome#FAILED} with its kind.
     *
     * @param name the username to create the profile with
     * @return the classified outcome, carrying the new profile on success
     * @throws UnsupportedOperationException if this implementation predates profile creation
     * @since 0.12.0
     */
    default ProfileCreationResult create(String name) {
        throw new UnsupportedOperationException("profile creation is not supported by this implementation");
    }
}

package lol.trq.alts.account;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

/**
 * Looks up a player's public identity by name or by UUID. These are the public endpoints: no token is
 * sent and no account is involved, so this is reachable without one — for resolving a name a user typed,
 * or checking what a stored account is called now.
 *
 * <p>Reached through {@code AltsRuntime#profileLookup}; there is no public factory.
 *
 * <p>"No such player" is an answer here, not a failure: a lookup that finds nobody returns empty, and an
 * {@link AccountException} is kept for a service that could not be reached or refused to answer.
 *
 * @author trq
 * @since 0.12.0
 */
public interface ProfileLookupService {

    /**
     * Looks a player up by username. Names match without regard to case, and the result carries the
     * name as the player capitalised it.
     *
     * @param name the username
     * @return the player, or empty when nobody has that name — including a name that no player could
     *     hold at all (empty, longer than 16 characters, or using a character outside letters, digits,
     *     and underscore), which is answered without a request. A name of one or two characters is
     *     looked up: none can be taken today, but accounts that predate the minimum still hold them
     * @throws AccountException if the service was rate limiting, refused, or could not be reached
     * @since 0.12.0
     */
    Optional<PublicProfile> byName(String name) throws AccountException;

    /**
     * Looks a player up by UUID.
     *
     * @param uuid the UUID, dashed or undashed
     * @return the player, or empty when no player has that UUID — including a value that is not a UUID
     *     at all, which is answered without a request
     * @throws AccountException if the service was rate limiting, refused, or could not be reached
     * @since 0.12.0
     */
    Optional<PublicProfile> byUuid(String uuid) throws AccountException;

    /**
     * Looks up several players by username. A name nobody has is simply absent from the result, as is
     * one that is not a valid username; a name given more than once, in any capitalisation, is resolved
     * once.
     *
     * <p>Any number of names is accepted. They are sent to the batch endpoint ten at a time, so the
     * distinct valid names cost one request per ten. A very long list is still the caller's to pace: a
     * rate limit part-way through fails the call with an exception for which
     * {@link AccountException#rateLimited()} is true and {@link AccountException#retryAfter()} carries
     * any stated wait, rather than returning a partial answer that reads as "those players do not exist".
     *
     * @param names the usernames to resolve
     * @return the players found, in the order their names were first given
     * @throws AccountException if the service was rate limiting, refused, or could not be reached
     * @since 0.12.0
     */
    List<PublicProfile> byNames(Collection<String> names) throws AccountException;
}

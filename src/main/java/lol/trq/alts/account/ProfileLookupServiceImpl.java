package lol.trq.alts.account;

import com.google.gson.JsonObject;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import lol.trq.alts.net.HttpUtil;
import lol.trq.alts.net.NetworkScope;

/**
 * Concrete {@link ProfileLookupService}: unauthenticated GETs against the public lookup endpoints, with a
 * 404 read as "nobody" rather than as a failure.
 *
 * <p>The list lookup resolves one name per request. The services also offer a batch endpoint, but it
 * answers with a top-level JSON array, and the library's one transport reads object bodies only; rather
 * than open a second way out of the library for one call, the list is resolved over the single-name
 * endpoint, which returns the same identities.
 *
 * @author trq
 * @since 0.12.0
 */
final class ProfileLookupServiceImpl implements ProfileLookupService {

    private final AccountHttp http = AccountHttp.anonymous();
    private final AccountEndpoints endpoints;

    ProfileLookupServiceImpl(AccountEndpoints endpoints) {
        this.endpoints = endpoints;
    }

    @Override
    public Optional<PublicProfile> byName(String name) throws AccountException {
        if (!NameRules.valid(name)) {
            return Optional.empty();
        }
        return lookup(endpoints.lookupByName(name));
    }

    @Override
    public Optional<PublicProfile> byUuid(String uuid) throws AccountException {
        String undashed = Uuids.undashed(uuid);
        if (undashed == null) {
            return Optional.empty();
        }
        return lookup(endpoints.lookupByUuid(undashed));
    }

    @Override
    public List<PublicProfile> byNames(Collection<String> names) throws AccountException {
        List<PublicProfile> found = new ArrayList<>();
        if (names == null) {
            return found;
        }
        Set<String> seen = new LinkedHashSet<>();
        for (String name : names) {
            if (!NameRules.valid(name) || !seen.add(name.toLowerCase(Locale.ROOT))) {
                continue;
            }
            byName(name).ifPresent(found::add);
        }
        return List.copyOf(found);
    }

    /**
     * Runs one lookup.
     *
     * @param url the lookup URL
     * @return the player, or empty on a 404 or an empty answer
     * @throws AccountException on any other refusal, or when the service could not be reached
     */
    private Optional<PublicProfile> lookup(String url) throws AccountException {
        HttpUtil.HttpResponse response = http.exchange("GET", url, null, null, NetworkScope.Purpose.PROFILE);
        if (response.status() == 404 || response.status() == 204) {
            return Optional.empty();
        }
        if (!response.successful()) {
            throw AccountHttp.failure("GET", url, response);
        }
        JsonObject body = response.body();
        String id = AccountHttp.string(body, "id");
        String name = AccountHttp.string(body, "name");
        if (id == null || name == null) {
            throw new AccountException("lookup response carried no identity", 0);
        }
        return Optional.of(new PublicProfile(id, name));
    }
}

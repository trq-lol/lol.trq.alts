package lol.trq.alts.account;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import lol.trq.alts.net.HttpUtil;
import lol.trq.alts.net.NetworkScope;

/**
 * Concrete {@link ProfileLookupService}: unauthenticated requests against the public lookup endpoints,
 * with a 404 read as "nobody" rather than as a failure.
 *
 * <p>The list lookup goes to the batch endpoint, {@value #BATCH_SIZE} names per request — the most it
 * accepts — so a list costs a tenth of the requests one name at a time would, against a service that
 * limits by request count.
 *
 * @author trq
 * @since 0.12.0
 */
final class ProfileLookupServiceImpl implements ProfileLookupService {

    /** The most names the batch endpoint accepts in one request. */
    static final int BATCH_SIZE = 10;

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
        if (names == null) {
            return List.of();
        }
        // Keyed case-insensitively and in the order given: a repeated name is asked about once, and the
        // answer is put back in the caller's order, which the service does not promise to keep.
        Map<String, String> wanted = new LinkedHashMap<>();
        for (String name : names) {
            if (NameRules.valid(name)) {
                wanted.putIfAbsent(name.toLowerCase(Locale.ROOT), name);
            }
        }
        List<String> asked = new ArrayList<>(wanted.values());
        Map<String, PublicProfile> resolved = new HashMap<>();
        for (int from = 0; from < asked.size(); from += BATCH_SIZE) {
            for (PublicProfile profile : batch(asked.subList(from, Math.min(from + BATCH_SIZE, asked.size())))) {
                resolved.putIfAbsent(profile.name().toLowerCase(Locale.ROOT), profile);
            }
        }
        List<PublicProfile> found = new ArrayList<>(resolved.size());
        for (String key : wanted.keySet()) {
            PublicProfile profile = resolved.get(key);
            if (profile != null) {
                found.add(profile);
            }
        }
        return List.copyOf(found);
    }

    /**
     * Resolves up to {@value #BATCH_SIZE} names in one request.
     *
     * @param names the names to resolve, already validated and de-duplicated
     * @return the players that exist; a name nobody holds is simply absent
     * @throws AccountException on a refusal — a rate limit included, carrying any stated wait — or when
     *     the service could not be reached or answered with something other than a list
     */
    private List<PublicProfile> batch(List<String> names) throws AccountException {
        JsonArray request = new JsonArray();
        names.forEach(request::add);
        String url = endpoints.lookupByNames();
        HttpUtil.JsonResponse response = http.exchangeElement(url, request.toString(), NetworkScope.Purpose.PROFILE);
        if (response.status() == 404 || response.status() == 204) {
            return List.of();
        }
        JsonElement body = response.body();
        if (!response.successful()) {
            throw AccountHttp.failure(
                    "POST",
                    url,
                    new HttpUtil.HttpResponse(
                            response.status(),
                            body != null && body.isJsonObject() ? body.getAsJsonObject() : null,
                            response.retryAfter()));
        }
        if (body == null || !body.isJsonArray()) {
            throw new AccountException("lookup response was not a list", 0);
        }
        List<PublicProfile> found = new ArrayList<>();
        for (JsonElement entry : body.getAsJsonArray()) {
            if (!entry.isJsonObject()) {
                continue;
            }
            String id = AccountHttp.string(entry.getAsJsonObject(), "id");
            String name = AccountHttp.string(entry.getAsJsonObject(), "name");
            if (id != null && name != null) {
                found.add(new PublicProfile(id, name));
            }
        }
        return found;
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

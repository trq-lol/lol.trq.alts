package lol.trq.alts.internal.account;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.util.ArrayList;
import java.util.List;
import lol.trq.alts.account.Blocklist;
import lol.trq.alts.account.BlocklistService;
import lol.trq.alts.net.NetworkScope;

/**
 * Concrete {@link BlocklistService}: one bearer GET, its {@code blockedProfiles} read into dashed ids.
 *
 * @author trq
 * @since 0.12.0
 */
public final class BlocklistServiceImpl implements BlocklistService {

    private final AccountHttp http;
    private final AccountUrls endpoints;

    public BlocklistServiceImpl(AccountHttp http, AccountUrls endpoints) {
        this.http = http;
        this.endpoints = endpoints;
    }

    @Override
    public Blocklist fetch() {
        JsonObject body = http.get(endpoints.blocklist(), NetworkScope.Purpose.PROFILE);
        List<String> blocked = new ArrayList<>();
        JsonElement profiles = body.get("blockedProfiles");
        if (profiles != null && profiles.isJsonArray()) {
            for (JsonElement profile : profiles.getAsJsonArray()) {
                if (profile.isJsonPrimitive()) {
                    blocked.add(profile.getAsString());
                }
            }
        }
        return new Blocklist(blocked);
    }
}

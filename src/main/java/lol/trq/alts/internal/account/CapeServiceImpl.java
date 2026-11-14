package lol.trq.alts.internal.account;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import java.util.List;
import lol.trq.alts.account.Cape;
import lol.trq.alts.account.CapeService;
import lol.trq.alts.account.PlayerProfile;
import lol.trq.alts.account.ProfileService;
import lol.trq.alts.net.NetworkScope;

/**
 * Concrete {@link CapeService}: a PUT to show a cape, a DELETE to hide, and the owned list read off the
 * profile.
 *
 * @author trq
 * @since 1.0.0
 */
public final class CapeServiceImpl implements CapeService {

    private final AccountHttp http;
    private final AccountUrls endpoints;
    private final Gson gson;
    private final ProfileService profile;

    public CapeServiceImpl(AccountHttp http, AccountUrls endpoints, Gson gson, ProfileService profile) {
        this.http = http;
        this.endpoints = endpoints;
        this.gson = gson;
        this.profile = profile;
    }

    @Override
    public List<Cape> owned() {
        return profile.fetch().capes();
    }

    @Override
    public PlayerProfile setActive(String capeId) {
        JsonObject request = new JsonObject();
        request.addProperty("capeId", capeId);
        JsonObject response =
                http.sendJson("PUT", endpoints.activeCape(), request.toString(), NetworkScope.Purpose.PROFILE);
        return AccountHttp.decode(gson, response, PlayerProfile.class);
    }

    @Override
    public void hide() {
        hideActive();
    }

    @Override
    public PlayerProfile hideActive() {
        JsonObject response = http.sendJson("DELETE", endpoints.activeCape(), null, NetworkScope.Purpose.PROFILE);
        return AccountHttp.decode(gson, response, PlayerProfile.class);
    }
}

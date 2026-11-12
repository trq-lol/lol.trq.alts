package lol.trq.alts.account;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import java.security.SecureRandom;
import java.util.HexFormat;
import lol.trq.alts.net.Multipart;
import lol.trq.alts.net.NetworkScope;

/**
 * Concrete {@link SkinService}: a JSON POST for a URL skin, a multipart POST for an uploaded one, a
 * DELETE to reset.
 *
 * @author trq
 * @since 1.0.0
 */
final class SkinServiceImpl implements SkinService {

    private static final SecureRandom BOUNDARIES = new SecureRandom();

    private final AccountHttp http;
    private final AccountEndpoints endpoints;
    private final Gson gson;

    SkinServiceImpl(AccountHttp http, AccountEndpoints endpoints, Gson gson) {
        this.http = http;
        this.endpoints = endpoints;
        this.gson = gson;
    }

    @Override
    public PlayerProfile setFromUrl(String url, SkinModel model) throws AccountException {
        JsonObject request = new JsonObject();
        request.addProperty("variant", (model == null ? SkinModel.CLASSIC : model).apiVariant());
        request.addProperty("url", url);
        JsonObject response =
                http.sendJson("POST", endpoints.skins(), request.toString(), NetworkScope.Purpose.PROFILE);
        return gson.fromJson(response, PlayerProfile.class);
    }

    @Override
    public PlayerProfile upload(byte[] pngBytes, SkinModel model) throws AccountException {
        Multipart form = new Multipart(boundary())
                .field("variant", (model == null ? SkinModel.CLASSIC : model).apiVariant())
                .file("file", "skin.png", "image/png", pngBytes);
        JsonObject response =
                http.sendRaw("POST", endpoints.skins(), form.contentType(), form.body(), NetworkScope.Purpose.PROFILE);
        return gson.fromJson(response, PlayerProfile.class);
    }

    @Override
    public void reset() throws AccountException {
        http.sendJson("DELETE", endpoints.activeSkin(), null, NetworkScope.Purpose.PROFILE);
    }

    /**
     * Returns a fresh multipart boundary. Random per request, so no fixed string exists for file content
     * to collide with — a constant boundary is one a crafted file can contain, ending its own part early
     * and appending fields of its choosing.
     *
     * @return a boundary unique to one request
     */
    private static String boundary() {
        byte[] random = new byte[16];
        BOUNDARIES.nextBytes(random);
        return "alts-skin-" + HexFormat.of().formatHex(random);
    }
}

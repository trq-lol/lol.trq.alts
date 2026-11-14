package lol.trq.alts.internal.account;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.util.LinkedHashSet;
import java.util.Set;
import lol.trq.alts.account.EntitlementService;
import lol.trq.alts.account.Entitlements;
import lol.trq.alts.net.NetworkScope;

/**
 * Concrete {@link EntitlementService}: reads the {@code items[]} of {@code /entitlements/mcstore} into
 * the product-id set.
 *
 * <p>Only the product names are read. The endpoint also returns per-item signatures and source data,
 * but the set of names is the whole answer to "what does this account own", and the extra fields are
 * noise a host does not act on.
 *
 * @author trq
 * @since 1.0.0
 */
public final class EntitlementServiceImpl implements EntitlementService {

    private final AccountHttp http;
    private final AccountUrls endpoints;

    public EntitlementServiceImpl(AccountHttp http, AccountUrls endpoints) {
        this.http = http;
        this.endpoints = endpoints;
    }

    @Override
    public Entitlements fetch() {
        JsonObject body = http.get(endpoints.entitlements(), NetworkScope.Purpose.PROFILE);
        Set<String> products = new LinkedHashSet<>();
        if (body.has("items") && body.get("items").isJsonArray()) {
            for (JsonElement item : body.getAsJsonArray("items")) {
                String name = item.isJsonObject() ? AccountHttp.string(item.getAsJsonObject(), "name") : null;
                if (name != null) {
                    products.add(name);
                }
            }
        }
        return new Entitlements(products);
    }
}

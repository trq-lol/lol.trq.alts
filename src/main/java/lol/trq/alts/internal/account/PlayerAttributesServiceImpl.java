package lol.trq.alts.internal.account;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.LinkedHashMap;
import java.util.Map;
import lol.trq.alts.account.PlayerAttributes;
import lol.trq.alts.account.PlayerAttributesService;
import lol.trq.alts.net.NetworkScope;

/**
 * Concrete {@link PlayerAttributesService}: a bearer GET to read, a bearer POST to set the profanity
 * filter, both answered with the same attributes document.
 *
 * <p>The document is read field by field rather than bound reflectively, because the leniency is the
 * point: a block that is missing, a member of the wrong shape, or a field added upstream must each cost
 * that one value and nothing else.
 *
 * @author trq
 * @since 0.12.0
 */
public final class PlayerAttributesServiceImpl implements PlayerAttributesService {

    private final AccountHttp http;
    private final AccountUrls endpoints;

    public PlayerAttributesServiceImpl(AccountHttp http, AccountUrls endpoints) {
        this.http = http;
        this.endpoints = endpoints;
    }

    @Override
    public PlayerAttributes fetch() {
        return parse(http.get(endpoints.playerAttributes(), NetworkScope.Purpose.PROFILE));
    }

    @Override
    public PlayerAttributes setProfanityFilter(boolean enabled) {
        JsonObject preferences = new JsonObject();
        preferences.addProperty("profanityFilterOn", enabled);
        JsonObject request = new JsonObject();
        request.add("profanityFilterPreferences", preferences);
        return parse(http.exchangeJson(
                "POST", endpoints.playerAttributes(), request.toString(), NetworkScope.Purpose.PROFILE));
    }

    /**
     * Reads an attributes document, taking each block only if it is present and shaped as expected.
     *
     * @param body the response body
     * @return the attributes
     */
    static PlayerAttributes parse(JsonObject body) {
        JsonObject privileges = object(body, "privileges");
        PlayerAttributes.Privileges parsedPrivileges = new PlayerAttributes.Privileges(
                enabled(privileges, "onlineChat"),
                enabled(privileges, "multiplayerServer"),
                enabled(privileges, "multiplayerRealms"),
                enabled(privileges, "telemetry"),
                enabled(privileges, "optionalTelemetry"));

        Boolean profanityFilter = bool(object(body, "profanityFilterPreferences"), "profanityFilterOn");

        Map<String, PlayerAttributes.Ban> bans = new LinkedHashMap<>();
        JsonObject scopes = object(object(body, "banStatus"), "bannedScopes");
        if (scopes != null) {
            for (Map.Entry<String, JsonElement> scope : scopes.entrySet()) {
                if (scope.getValue().isJsonObject()) {
                    bans.put(scope.getKey(), ban(scope.getValue().getAsJsonObject()));
                }
            }
        }

        return new PlayerAttributes(
                parsedPrivileges,
                profanityFilter,
                primitives(object(body, "friendsPreferences")),
                primitives(object(body, "chatPreferences")),
                bans);
    }

    private static PlayerAttributes.Ban ban(JsonObject ban) {
        return new PlayerAttributes.Ban(
                AccountHttp.string(ban, "banId"),
                instant(ban.get("expires")),
                AccountHttp.string(ban, "reason"),
                AccountHttp.string(ban, "reasonMessage"));
    }

    /** Reads a privilege's {@code {"enabled": bool}} wrapper. */
    private static Boolean enabled(JsonObject privileges, String name) {
        return bool(object(privileges, name), "enabled");
    }

    private static JsonObject object(JsonObject parent, String field) {
        JsonElement element = parent == null ? null : parent.get(field);
        return element != null && element.isJsonObject() ? element.getAsJsonObject() : null;
    }

    private static Boolean bool(JsonObject parent, String field) {
        JsonElement element = parent == null ? null : parent.get(field);
        if (element == null || !element.isJsonPrimitive()) {
            return null;
        }
        JsonPrimitive primitive = element.getAsJsonPrimitive();
        return primitive.isBoolean() ? primitive.getAsBoolean() : null;
    }

    /** Flattens a preferences block to its primitive members, so an unknown preference survives as text. */
    private static Map<String, String> primitives(JsonObject block) {
        Map<String, String> values = new LinkedHashMap<>();
        if (block != null) {
            for (Map.Entry<String, JsonElement> member : block.entrySet()) {
                if (member.getValue().isJsonPrimitive()) {
                    values.put(member.getKey(), member.getValue().getAsString());
                }
            }
        }
        return values;
    }

    /**
     * Reads an expiry given either as an ISO-8601 instant or as epoch milliseconds.
     *
     * @param element the {@code expires} member, or null
     * @return the instant, or {@code null} when absent, JSON null, or unreadable
     */
    private static Instant instant(JsonElement element) {
        if (element == null || !element.isJsonPrimitive()) {
            return null;
        }
        JsonPrimitive primitive = element.getAsJsonPrimitive();
        try {
            if (primitive.isNumber()) {
                return Instant.ofEpochMilli(primitive.getAsLong());
            }
            return Instant.parse(primitive.getAsString());
        } catch (DateTimeParseException | NumberFormatException unreadable) {
            return null;
        }
    }
}

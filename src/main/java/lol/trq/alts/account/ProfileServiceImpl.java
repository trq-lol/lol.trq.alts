package lol.trq.alts.account;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import lol.trq.alts.net.HttpTransport;
import lol.trq.alts.net.NetworkScope;

/**
 * Concrete {@link ProfileService}: one bearer GET, deserialised into a {@link PlayerProfile}, and one
 * bearer POST to create a profile, whose refusals are read out of the error body.
 *
 * @author trq
 * @since 1.0.0
 */
final class ProfileServiceImpl implements ProfileService {

    private final AccountHttp http;
    private final AccountEndpoints endpoints;
    private final Gson gson;

    ProfileServiceImpl(AccountHttp http, AccountEndpoints endpoints, Gson gson) {
        this.http = http;
        this.endpoints = endpoints;
        this.gson = gson;
    }

    @Override
    public PlayerProfile fetch() throws AccountException {
        return gson.fromJson(http.get(endpoints.profile(), NetworkScope.Purpose.PROFILE), PlayerProfile.class);
    }

    @Override
    public ProfileCreationResult create(String name) throws AccountException {
        if (!NameRules.valid(name)) {
            return new ProfileCreationResult(
                    ProfileCreationResult.Outcome.INVALID_NAME,
                    null,
                    "A name is 3 to 16 letters, digits, or underscores",
                    null);
        }
        JsonObject request = new JsonObject();
        request.addProperty("profileName", name);
        HttpTransport.HttpResponse response = http.exchange(
                "POST",
                endpoints.profile(),
                "application/json",
                request.toString().getBytes(StandardCharsets.UTF_8),
                NetworkScope.Purpose.PROFILE);
        return classify(response);
    }

    /**
     * Maps a creation response onto a result. A 400 is told apart by the {@code details.status} the
     * service sends with it; one that names no cause the library knows is a malformed name.
     *
     * @param response the creation response
     * @return the classified result
     */
    private ProfileCreationResult classify(HttpTransport.HttpResponse response) {
        int status = response.status();
        if (response.successful()) {
            PlayerProfile profile =
                    response.body() == null ? null : gson.fromJson(response.body(), PlayerProfile.class);
            return new ProfileCreationResult(ProfileCreationResult.Outcome.CREATED, profile, "Profile created", null);
        }
        ProfileCreationResult.Outcome outcome = fromErrorCode(AccountHttp.errorCode(response));
        if (outcome == null) {
            outcome = switch (status) {
                case 400 -> ProfileCreationResult.Outcome.INVALID_NAME;
                case 401 -> ProfileCreationResult.Outcome.UNAUTHORIZED;
                case 429 -> ProfileCreationResult.Outcome.RATE_LIMITED;
                default -> ProfileCreationResult.Outcome.FAILED;
            };
        }
        return new ProfileCreationResult(outcome, null, AccountHttp.reason(response), response.retryAfter());
    }

    /**
     * Maps the service's machine-readable cause onto an outcome.
     *
     * @param code the cause from the error body, or null
     * @return the matching outcome, or {@code null} when the code is absent or not one this knows
     */
    private static ProfileCreationResult.Outcome fromErrorCode(String code) {
        if (code == null) {
            return null;
        }
        return switch (code.toUpperCase(Locale.ROOT)) {
            case "DUPLICATE" -> ProfileCreationResult.Outcome.DUPLICATE;
            case "NOT_ALLOWED" -> ProfileCreationResult.Outcome.NOT_ALLOWED;
            case "NOT_ENTITLED" -> ProfileCreationResult.Outcome.NOT_ENTITLED;
            default -> null;
        };
    }
}

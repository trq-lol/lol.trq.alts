package lol.trq.alts.internal.account;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Optional;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure;
import lol.trq.alts.AltsFailure.Kind;
import lol.trq.alts.account.PlayerProfile;
import lol.trq.alts.account.ProfileCreationResult;
import lol.trq.alts.account.ProfileService;
import lol.trq.alts.internal.net.HttpTransport;
import lol.trq.alts.net.NetworkScope;

/**
 * Concrete {@link ProfileService}: one bearer GET, deserialised into a {@link PlayerProfile}, and one
 * bearer POST to create a profile, whose refusals are read out of the error body.
 *
 * @author trq
 * @since 1.0.0
 */
public final class ProfileServiceImpl implements ProfileService {

    private final AccountHttp http;
    private final AccountUrls endpoints;
    private final Gson gson;

    public ProfileServiceImpl(AccountHttp http, AccountUrls endpoints, Gson gson) {
        this.http = http;
        this.endpoints = endpoints;
        this.gson = gson;
    }

    @Override
    public PlayerProfile fetch() {
        JsonObject body;
        try {
            body = http.get(endpoints.profile(), NetworkScope.Purpose.PROFILE);
        } catch (AltsException failure) {
            if (failure.kind() == Kind.NOT_FOUND) {
                // The token is fine; there is no Minecraft profile behind it. Sign-in and check report
                // the same answer as NOT_ENTITLED, and so does this.
                throw new AltsException(Kind.NOT_ENTITLED, "Profile: this account has no Minecraft profile");
            }
            throw failure;
        }
        return AccountHttp.decode(gson, body, PlayerProfile.class);
    }

    @Override
    public ProfileCreationResult create(String name) {
        if (!NameRules.valid(name)) {
            return new ProfileCreationResult(
                    ProfileCreationResult.Outcome.INVALID_NAME,
                    null,
                    "A name is 3 to 16 letters, digits, or underscores",
                    Optional.empty());
        }
        JsonObject request = new JsonObject();
        request.addProperty("profileName", name);
        HttpTransport.HttpResponse response;
        try {
            response = http.exchange(
                    "POST",
                    endpoints.profile(),
                    "application/json",
                    request.toString().getBytes(StandardCharsets.UTF_8),
                    NetworkScope.Purpose.PROFILE);
        } catch (AltsException unreachable) {
            // Unreachable is a failed creation like any other: the result says what kind it was.
            return ProfileCreationResult.failed(unreachable.failure());
        }
        return classify(response);
    }

    /**
     * Maps a creation response onto a result. A 400 is told apart by the {@code details.status} the
     * service sends with it; one that names no cause the library knows is a malformed name. An account
     * that owns nothing, a refused token, a rate limit and anything else are a
     * {@link ProfileCreationResult.Outcome#FAILED} carrying the kind. The service's own error text is not
     * repeated.
     *
     * @param response the creation response
     * @return the classified result
     */
    private ProfileCreationResult classify(HttpTransport.HttpResponse response) {
        int status = response.status();
        if (response.successful()) {
            PlayerProfile profile = AccountHttp.decode(gson, response.body(), PlayerProfile.class);
            return new ProfileCreationResult(
                    ProfileCreationResult.Outcome.CREATED, profile, "Profile created", Optional.empty());
        }
        String code = AccountHttp.errorCode(response);
        String cause = code == null ? "" : code.toUpperCase(Locale.ROOT);
        switch (cause) {
            case "DUPLICATE" -> {
                return new ProfileCreationResult(
                        ProfileCreationResult.Outcome.DUPLICATE, null, "The name is already taken", Optional.empty());
            }
            case "NOT_ALLOWED" -> {
                return new ProfileCreationResult(
                        ProfileCreationResult.Outcome.NOT_ALLOWED,
                        null,
                        "The name is blocked or reserved",
                        Optional.empty());
            }
            case "NOT_ENTITLED" -> {
                return ProfileCreationResult.failed(
                        AltsFailure.of(Kind.NOT_ENTITLED, "Profile creation: the account owns no Java edition"));
            }
            default -> {
                // Fall through to the status.
            }
        }
        if (status == 400) {
            return new ProfileCreationResult(
                    ProfileCreationResult.Outcome.INVALID_NAME, null, "The name is not valid", Optional.empty());
        }
        return ProfileCreationResult.failed(
                AccountHttp.failure("POST", "/minecraft/profile", response).failure());
    }
}

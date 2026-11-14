package lol.trq.alts.internal.store;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.TypeAdapter;
import com.google.gson.TypeAdapterFactory;
import com.google.gson.annotations.SerializedName;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import java.io.IOException;
import java.util.Map;
import lol.trq.alts.model.AccountType;
import lol.trq.alts.model.AltAccount;
import lol.trq.alts.model.BanInfo;

/**
 * The JSON form of an {@link AltAccount}: the account file's entries and a 0.4 repository's payload
 * accounts. Gson reads and writes the record {@link Stored}, which it builds through its canonical
 * constructor, and the account is built from that through its builder. Nothing writes the account's final
 * fields by reflection, which a later JDK is set to refuse.
 *
 * <p>The record's components are the account's fields, under the same names and in the same order, so the
 * bytes are what Gson wrote for the account when it was a record: a missing field reads as {@code null} or
 * {@code 0}, an unknown one is ignored, and a {@code null} is left out on write.
 */
public final class AltAccountJson {

    private AltAccountJson() {}

    /**
     * Returns {@code builder} with the account's JSON form registered on it.
     *
     * @param builder the Gson builder to register on
     * @return {@code builder}, for chaining
     */
    public static GsonBuilder register(GsonBuilder builder) {
        return builder.registerTypeAdapterFactory(FACTORY);
    }

    /**
     * Returns a Gson keyed purely on {@link SerializedName}, the house convention, that reads and writes
     * accounts in their JSON form.
     *
     * @return a new Gson
     */
    public static Gson gson() {
        return register(new GsonBuilder()).create();
    }

    private static final TypeAdapterFactory FACTORY = new TypeAdapterFactory() {
        @Override
        @SuppressWarnings("unchecked")
        public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> type) {
            if (type.getRawType() != AltAccount.class) {
                return null;
            }
            return (TypeAdapter<T>) new Adapter(gson.getAdapter(Stored.class));
        }
    };

    /** Maps the account to its record and back; a JSON {@code null} is a {@code null} account. */
    private static final class Adapter extends TypeAdapter<AltAccount> {

        private final TypeAdapter<Stored> stored;

        Adapter(TypeAdapter<Stored> stored) {
            this.stored = stored;
        }

        @Override
        public void write(JsonWriter out, AltAccount account) throws IOException {
            stored.write(out, account == null ? null : Stored.of(account));
        }

        @Override
        public AltAccount read(JsonReader in) throws IOException {
            Stored read = stored.read(in);
            return read == null ? null : read.account();
        }
    }

    /**
     * The account as the file holds it. The component names and their order are the store file's format.
     *
     * @param uuid the player's UUID
     * @param username the player's username
     * @param accessToken the access token
     * @param type the account type
     * @param lastUsed the last-used time, epoch millis
     * @param lastUsedBy the member that last used it
     * @param bans the ban records by server id
     * @param sourceClient the client it was added from
     * @param sourceUser the user within that client
     * @param refreshToken the refresh token
     * @param expiresAt the access token's expiry, epoch millis
     */
    private record Stored(
            @SerializedName("uuid") String uuid,
            @SerializedName("username") String username,
            @SerializedName("accessToken") String accessToken,
            @SerializedName("type") AccountType type,
            @SerializedName("lastUsed") long lastUsed,
            @SerializedName("lastUsedBy") String lastUsedBy,
            @SerializedName("bans") Map<String, BanInfo> bans,
            @SerializedName("sourceClient") String sourceClient,
            @SerializedName("sourceUser") String sourceUser,
            @SerializedName("refreshToken") String refreshToken,
            @SerializedName("expiresAt") long expiresAt) {

        static Stored of(AltAccount a) {
            return new Stored(
                    a.uuid(),
                    a.username(),
                    a.accessToken(),
                    a.type(),
                    a.lastUsed(),
                    a.lastUsedBy(),
                    a.bans(),
                    a.sourceClient(),
                    a.sourceUser(),
                    a.refreshToken(),
                    a.expiresAt());
        }

        AltAccount account() {
            return AltAccount.builder(uuid, username, accessToken, type)
                    .lastUsed(lastUsed)
                    .lastUsedBy(lastUsedBy)
                    .bans(bans)
                    .sourceClient(sourceClient)
                    .sourceUser(sourceUser)
                    .refreshToken(refreshToken)
                    .expiresAt(expiresAt)
                    .build();
        }

        // The record carries both credentials; a log of it must not.
        @Override
        public String toString() {
            return "Stored[uuid=" + uuid + "]";
        }
    }
}

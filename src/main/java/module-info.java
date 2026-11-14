/**
 * A general account library for Minecraft: Java Edition: sign-in, account management over a token, bulk
 * operations, an encrypted local store and a shared vault. A host builds one {@link lol.trq.alts.AltsRuntime}
 * and reaches everything else through it.
 *
 * <p>The exported packages are the API. Everything under {@code lol.trq.alts.internal} is implementation: it
 * is not exported, is left out of the published Javadoc, and may change in any release.
 *
 * @since 1.0.0
 */
module lol.trq.alts {
    // Gson is part of the API: @SerializedName sits on the public records, so a consumer reads it too.
    requires transitive com.google.gson;
    // The browser sign-in opens the system browser and the default avatar source crops the skin with
    // ImageIO (java.desktop); the browser sign-in's loopback redirect listens on the JDK HTTP server.
    requires java.desktop;
    requires jdk.httpserver;

    exports lol.trq.alts;
    exports lol.trq.alts.account;
    exports lol.trq.alts.auth;
    exports lol.trq.alts.bulk;
    exports lol.trq.alts.cache;
    exports lol.trq.alts.model;
    exports lol.trq.alts.net;
    exports lol.trq.alts.skin;
    exports lol.trq.alts.spi;
    exports lol.trq.alts.store;
    exports lol.trq.alts.time;
    exports lol.trq.alts.vault;

    // Gson builds these private records by reflection: the store files (AccountStore.StorageData,
    // HostSecrets.SecretData) and the device-code authorization response. AltAccount is a final class whose
    // private fields Gson reads and sets, for the account file. Every other type Gson reads is a public
    // record in an exported package, which needs no opening.
    opens lol.trq.alts.store to
            com.google.gson;
    opens lol.trq.alts.internal.auth to
            com.google.gson;
    opens lol.trq.alts.model to
            com.google.gson;
}

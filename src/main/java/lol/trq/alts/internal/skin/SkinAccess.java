package lol.trq.alts.internal.skin;

import java.util.Objects;
import java.util.concurrent.Executor;
import lol.trq.alts.skin.SkinAvatarCache;
import lol.trq.alts.spi.AvatarSource;
import lol.trq.alts.spi.MainThreadExecutor;
import lol.trq.alts.spi.TextureUploader;

/**
 * How the runtime builds its {@link SkinAvatarCache} without the cache having a public constructor. The
 * skin package installs the one {@link Bridge} when {@link SkinAvatarCache} initializes, and
 * {@link #install} accepts no other: only the library's own bridge class, loaded by this class's own
 * loader, and only once. Not part of the library's API: a host gets the cache from
 * {@code AltsRuntime#skinCache()}.
 *
 * @author trq
 * @since 1.0.0
 */
public final class SkinAccess {

    /** The one class whose instance {@link #install} accepts. */
    private static final String BRIDGE_CLASS = "lol.trq.alts.skin.SkinBridge";

    private static volatile Bridge bridge;

    private SkinAccess() {}

    /**
     * Installs the bridge. Called once, by the skin package, as it initializes.
     *
     * @param value the bridge
     * @throws IllegalArgumentException if {@code value} is not the library's own skin bridge, loaded by
     *     this class's loader; nothing is installed
     * @throws IllegalStateException if a bridge is already installed
     * @since 1.0.0
     */
    public static synchronized void install(Bridge value) {
        Objects.requireNonNull(value, "bridge");
        Class<?> type = value.getClass();
        if (!type.getName().equals(BRIDGE_CLASS) || type.getClassLoader() != SkinAccess.class.getClassLoader()) {
            throw new IllegalArgumentException("not the library's skin bridge");
        }
        if (bridge != null) {
            throw new IllegalStateException("skin bridge already installed");
        }
        bridge = value;
    }

    /**
     * Returns the bridge, initializing the skin package first when nothing has yet.
     *
     * @return the installed bridge
     * @since 1.0.0
     */
    public static Bridge bridge() {
        try {
            Class.forName(SkinAvatarCache.class.getName(), true, SkinAccess.class.getClassLoader());
        } catch (ClassNotFoundException impossible) {
            throw new IllegalStateException("skin package unavailable", impossible);
        }
        return Objects.requireNonNull(bridge, "skin bridge not installed");
    }

    /**
     * The runtime's way into the skin package.
     *
     * @since 1.0.0
     */
    public interface Bridge {

        /**
         * Builds an avatar cache.
         *
         * @param source the avatar source
         * @param uploader the host texture uploader, or null for a cache that stays empty
         * @param mainThread the host main-thread executor
         * @param executor the executor downloads run on
         * @param <H> the host's texture-handle type
         * @return the cache
         */
        <H> SkinAvatarCache<H> cache(
                AvatarSource source, TextureUploader<H> uploader, MainThreadExecutor mainThread, Executor executor);
    }
}

package lol.trq.alts.skin;

import java.util.concurrent.Executor;
import lol.trq.alts.internal.skin.SkinAccess;
import lol.trq.alts.spi.AvatarSource;
import lol.trq.alts.spi.MainThreadExecutor;
import lol.trq.alts.spi.TextureUploader;

/**
 * The skin package's side of {@link SkinAccess}: the runtime builds its cache through it, so
 * {@link SkinAvatarCache} needs no public constructor. Installed exactly once, when the cache class
 * initializes.
 *
 * @author trq
 * @since 1.0.0
 */
final class SkinBridge implements SkinAccess.Bridge {

    static {
        SkinAccess.install(new SkinBridge());
    }

    private SkinBridge() {}

    /** Initializes this class, and with it the bridge; repeat calls do nothing. */
    static void install() {
        // The static initializer above does the work.
    }

    @Override
    public <H> SkinAvatarCache<H> cache(
            AvatarSource source, TextureUploader<H> uploader, MainThreadExecutor mainThread, Executor executor) {
        return new SkinAvatarCache<>(source, uploader, mainThread, executor);
    }
}

package lol.trq.alts.internal.skin;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;
import lol.trq.alts.internal.ChildFirstLoader;
import lol.trq.alts.skin.SkinAvatarCache;
import lol.trq.alts.spi.AvatarSource;
import lol.trq.alts.spi.MainThreadExecutor;
import lol.trq.alts.spi.TextureUploader;
import org.junit.jupiter.api.Test;

/**
 * The skin bridge is the only way to build the runtime's avatar cache, so only the skin package's own
 * bridge may be installed: a foreign one, one of the right name from another loader, and a second
 * install are all refused.
 */
class SkinAccessTest {

    @Test
    void aForeignBridgeIsRefused() {
        AtomicBoolean reached = new AtomicBoolean();
        SkinAccess.Bridge foreign = new SkinAccess.Bridge() {
            @Override
            public <H> SkinAvatarCache<H> cache(
                    AvatarSource source,
                    TextureUploader<H> uploader,
                    MainThreadExecutor mainThread,
                    Executor executor) {
                reached.set(true);
                return null;
            }
        };

        assertThrows(IllegalArgumentException.class, () -> SkinAccess.install(foreign));
        assertNotSame(foreign, SkinAccess.bridge());
        assertFalse(reached.get());
    }

    @Test
    void aBridgeOfTheRightNameFromAnotherClassLoaderIsRefused() {
        String bridgeName = "lol.trq.alts.skin.SkinBridge";
        ClassLoader foreign = new ChildFirstLoader(SkinAccessTest.class.getClassLoader(), bridgeName);

        if (SkinAccess.class.getModule().isNamed()) {
            // On the module path the copy sits in an unnamed module, to which the library does not export
            // its internal packages: it cannot even implement the bridge interface, let alone install it.
            assertThrows(IllegalAccessError.class, () -> Class.forName(bridgeName, true, foreign));
        } else {
            ExceptionInInitializerError refused =
                    assertThrows(ExceptionInInitializerError.class, () -> Class.forName(bridgeName, true, foreign));
            assertInstanceOf(IllegalArgumentException.class, refused.getCause());
        }
        assertNotSame(foreign, SkinAccess.bridge().getClass().getClassLoader());
    }

    @Test
    void theLibrarysOwnBridgeIsNotInstalledTwice() {
        SkinAccess.Bridge installed = SkinAccess.bridge();

        assertThrows(IllegalStateException.class, () -> SkinAccess.install(installed));
    }
}

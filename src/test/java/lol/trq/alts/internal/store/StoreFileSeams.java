package lol.trq.alts.internal.store;

import java.time.Duration;

/**
 * Reaches the package-private test seams of {@link StoreFile} from the store tests in another package. Test
 * sources only: the seams themselves stay package-private in the library.
 */
public final class StoreFileSeams {

    /** How many unreadable copies a store keeps. */
    public static final int MAX_UNREADABLE_KEPT = StoreFile.MAX_UNREADABLE_KEPT;

    /** The suffix an unreadable copy carries after the file name. */
    public static final String UNREADABLE_SUFFIX = StoreFile.UNREADABLE_SUFFIX;

    /** The suffix of the sidecar lock file. */
    public static final String LOCK_SUFFIX = StoreFile.LOCK_SUFFIX;

    private StoreFileSeams() {}

    /** Runs {@code hook} before each write. */
    public static void beforeWrite(StoreFile file, Runnable hook) {
        file.beforeWriteForTests(hook);
    }

    /** Whether the file still holds key material. */
    public static boolean holdsKeyMaterial(StoreFile file) {
        return file.holdsKeyMaterialForTests();
    }

    /** The coalescing window. */
    public static Duration writeDelay(StoreFile file) {
        return file.writeDelay();
    }

    /** The registered shutdown flush, or null. */
    public static Thread shutdownFlush(StoreFile file) {
        return file.shutdownFlushForTests();
    }
}

package lol.trq.alts.net;

/**
 * Reaches the transport's package-private test seams from tests in other packages. It lives in the test
 * sources, in the transport's own package, so the seams themselves never have to be public in the
 * library: removing a proxy provider is not something a host should be one call away from.
 */
public final class NetTestHooks {

    private NetTestHooks() {}

    /** Removes the installed proxy provider and any substituted TLS factory. */
    public static void resetHttp() {
        HttpUtil.resetForTests();
    }

    /** Restores the default executor. */
    public static void resetExecutor() {
        IoExecutor.resetForTests();
    }
}

package lol.trq.alts.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.concurrent.Executor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * The seams tests use to undo process-wide state each undo something a host depends on: the proxy that
 * hides its address, the trust that authenticates a server, the executor it chose. None of them may be
 * a public method, and none may work in a JVM that is not running the test suite.
 */
class TestSeamGateTest {

    private static final String PROPERTY = "lol.trq.alts.testSeams";

    @AfterEach
    void restore() {
        System.setProperty(PROPERTY, "true");
        HttpUtil.resetForTests();
        IoExecutor.resetForTests();
    }

    @Test
    void noTestSeamIsPublic() {
        for (Class<?> type : new Class<?>[] {HttpUtil.class, IoExecutor.class}) {
            for (Method method : type.getDeclaredMethods()) {
                if (method.getName().endsWith("ForTests")) {
                    assertEquals(
                            0,
                            method.getModifiers() & (Modifier.PUBLIC | Modifier.PROTECTED),
                            type.getSimpleName() + "." + method.getName() + " must not be callable by a host");
                }
            }
        }
    }

    @Test
    void outsideTheTestSuiteTheProxyProviderCannotBeRemoved() throws Exception {
        ProxyRoute route = ProxyRoute.http("proxy.example", 8080);
        HttpUtil.bind(scope -> route);
        System.clearProperty(PROPERTY);

        assertThrows(IllegalStateException.class, HttpUtil::resetForTests);

        assertSame(route, HttpUtil.routeFor(null), "the provider a host installed is still the one in use");
    }

    @Test
    void outsideTheTestSuiteTheTlsTrustCannotBeSubstituted() {
        System.clearProperty(PROPERTY);

        assertThrows(IllegalStateException.class, () -> HttpUtil.tlsSocketFactoryForTests(null));
    }

    @Test
    void outsideTheTestSuiteTheExecutorCannotBeReset() {
        Executor host = Runnable::run;
        IoExecutor.bind(host);
        System.clearProperty(PROPERTY);

        assertThrows(IllegalStateException.class, IoExecutor::resetForTests);

        assertSame(host, IoExecutor.executor());
    }
}

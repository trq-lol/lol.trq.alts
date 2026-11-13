package lol.trq.alts.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Optional;
import org.junit.jupiter.api.Test;

/** A route tag names a route; a blank one names none, so no scope may carry it to a provider. */
class NetworkScopeTest {

    @Test
    void aBlankTagIsRefusedHoweverTheScopeIsBuilt() {
        NetworkScope scope = NetworkScope.of(NetworkScope.Purpose.AUTH);

        assertThrows(IllegalArgumentException.class, () -> scope.withRouteTag(""));
        assertThrows(IllegalArgumentException.class, () -> scope.withRouteTag("  "));
        assertThrows(
                IllegalArgumentException.class,
                () -> new NetworkScope(NetworkScope.Purpose.AUTH, null, null, Optional.of("\t")));
    }

    @Test
    void anAbsentTagIsEmptyAndAPresentOneIsKept() {
        NetworkScope scope = new NetworkScope(NetworkScope.Purpose.PROFILE, "uuid", "Alex", null);

        assertEquals(Optional.empty(), scope.routeTag());
        assertEquals(Optional.empty(), scope.withRouteTag(null).routeTag());
        assertEquals(Optional.of("pool-7"), scope.withRouteTag("pool-7").routeTag());
        assertEquals(Optional.empty(), new NetworkScope(NetworkScope.Purpose.AUTH, null, null).routeTag());
    }
}

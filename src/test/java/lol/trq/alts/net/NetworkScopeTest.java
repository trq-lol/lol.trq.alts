package lol.trq.alts.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
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
                () -> NetworkScope.forAccount(NetworkScope.Purpose.AUTH, null, null)
                        .withRouteTag("\t"));
    }

    @Test
    void anAbsentTagIsEmptyAndAPresentOneIsKept() {
        NetworkScope scope = NetworkScope.forAccount(NetworkScope.Purpose.PROFILE, "uuid", "Alex");

        assertEquals(Optional.empty(), scope.routeTag());
        assertEquals(Optional.empty(), scope.withRouteTag(null).routeTag());
        assertEquals(Optional.of("pool-7"), scope.withRouteTag("pool-7").routeTag());
        assertEquals(
                Optional.empty(), NetworkScope.of(NetworkScope.Purpose.AUTH).routeTag());
    }

    @Test
    void aScopeIsAValueThatAlwaysStatesAPurpose() {
        NetworkScope scope = NetworkScope.forAccount(NetworkScope.Purpose.PROFILE, "uuid", "Alex");

        assertEquals(NetworkScope.Purpose.AUTH, NetworkScope.of(null).purpose());
        assertEquals(NetworkScope.forAccount(NetworkScope.Purpose.PROFILE, "uuid", "Alex"), scope);
        assertEquals(
                NetworkScope.forAccount(NetworkScope.Purpose.PROFILE, "uuid", "Alex")
                        .hashCode(),
                scope.hashCode());
        assertNotEquals(scope, scope.withRouteTag("pool-7"));
        assertEquals(
                "NetworkScope[purpose=PROFILE, accountUuid=uuid, accountUsername=Alex, routeTag=Optional[pool-7]]",
                scope.withRouteTag("pool-7").toString());
    }
}

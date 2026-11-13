package lol.trq.alts.internal.avp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import lol.trq.alts.AltsException;
import lol.trq.alts.AltsFailure.Kind;
import org.junit.jupiter.api.Test;

/**
 * The CE item table of SPEC 4.1, item by item, and the domain separation it rests on. The construction
 * vectors pin whole strings; this pins each item's bytes on its own.
 */
class CeTest {

    @Test
    void everyItemHasTheBytesOfTheSpecTable() {
        assertEquals("616200000000026162", Vectors.hex(Ce.tag("ab").str("ab").finish()));
        assertEquals("7400", Vectors.hex(Ce.tag("t").finish()));
        assertEquals(
                "740000000003010203",
                Vectors.hex(Ce.tag("t").bytes(new byte[] {1, 2, 3}).finish()));
        assertEquals("740000000000", Vectors.hex(Ce.tag("t").bytes(new byte[0]).finish()));
        assertEquals(
                "74000000000568c3a96c6c", Vectors.hex(Ce.tag("t").str("héll").finish()));
        assertEquals("74000000000000000102", Vectors.hex(Ce.tag("t").i64(258).finish()));
        assertEquals("7400ffffffffffffffff", Vectors.hex(Ce.tag("t").i64(-1).finish()));
        assertEquals(
                "74008000000000000000",
                Vectors.hex(Ce.tag("t").i64(Long.MIN_VALUE).finish()));
        assertEquals("74000100", Vectors.hex(Ce.tag("t").bool(true).bool(false).finish()));
        assertEquals("740001020304", Vectors.hex(Ce.tag("t").count(0x01020304).finish()));
    }

    @Test
    void aLabelWithNulOrANegativeCountIsRefused() {
        assertThrows(IllegalArgumentException.class, () -> Ce.tag("a\u0000b"));
        assertThrows(IllegalArgumentException.class, () -> Ce.tag("t").count(-1));
    }

    @Test
    void theLabelsAreDistinctAndPrefixFree() {
        List<String> labels = List.of(
                Ce.MANIFEST,
                Ce.REPO_ID,
                Ce.COMMIT,
                Ce.COMMIT_SIG,
                Ce.AAD,
                Ce.LEAVE,
                Ce.CHALLENGE,
                Ce.ACCEPT,
                Ce.LINK_CODE);
        Set<String> tags = new TreeSet<>();
        for (String label : labels) {
            tags.add(Vectors.hex(Ce.tag(label).finish()));
        }
        assertEquals(labels.size(), tags.size());
        for (String a : tags) {
            for (String b : tags) {
                assertEquals(a.equals(b), b.startsWith(a), a + " is a prefix of " + b);
            }
        }
    }

    @Test
    void sortedListsUseUnsignedBytesAndRefuseADuplicate() {
        byte[] low = {0x01};
        byte[] high = {(byte) 0x80};
        byte[] prefix = {};
        List<byte[]> sorted = AvpBytes.sortedUnique(List.of(high, low, prefix), "id");
        assertEquals(List.of("", "01", "80"), sorted.stream().map(Vectors::hex).toList());
        AltsException e =
                assertThrows(AltsException.class, () -> AvpBytes.sortedUnique(List.of(low, new byte[] {0x01}), "id"));
        assertEquals(Kind.PROTOCOL, e.kind());
    }

    @Test
    void base64AndBase64UrlDecodeOnlyCanonicalText() {
        assertEquals("01ff", Vectors.hex(AvpBytes.fromBase64("Af8=", "x")));
        assertEquals("01ff", Vectors.hex(AvpBytes.fromBase64Url("Af8", "x")));
        for (String bad : new String[] {"Af8", "Af9=", " Af8=", "Af8=\n", "A-8="}) {
            assertEquals(
                    Kind.PROTOCOL,
                    assertThrows(AltsException.class, () -> AvpBytes.fromBase64(bad, "x"))
                            .kind(),
                    bad);
        }
        for (String bad : new String[] {"Af8=", "Af9", "Af+", " Af8"}) {
            assertEquals(
                    Kind.PROTOCOL,
                    assertThrows(AltsException.class, () -> AvpBytes.fromBase64Url(bad, "x"))
                            .kind(),
                    bad);
        }
        assertEquals(
                Kind.PROTOCOL,
                assertThrows(AltsException.class, () -> AvpBytes.fromBase64("AAAA", 2, "x"))
                        .kind());
    }
}

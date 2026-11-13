package lol.trq.alts.internal.avp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.InputStream;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Map;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;

/**
 * Pins the vendored AVP 0.5 vector files to the bytes of {@code trqlmao/avp} at commit {@code 3dbdf79}
 * (see {@code avp-vectors/VENDORED.md}), so a local edit to a vector, or a partial update, fails here
 * instead of quietly changing what the conformance tests check.
 */
class AvpVectorFilesTest {

    /** SHA-256 of each vendored file, as {@code git show 3dbdf79:vectors/<file>} yields it. */
    static final Map<String, String> SHA256 = new TreeMap<>(Map.ofEntries(
            Map.entry("acceptance.json", "c517b14251ebfc9ae994146398a503bbe771b7086699b0e1c98235a74b1639f0"),
            Map.entry("bip39-english.txt", "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"),
            Map.entry("bip39-owner.json", "cb94bb9ec771d5861cecaabeecd6e8103f7fe6c8791a7674d5fbcfafa13d3a14"),
            Map.entry("commit.json", "05dfe65f5f7c6db5ef1cf86cdf0c4730d31096c1ccdc5c335c4f685813ff8503"),
            Map.entry("ed25519.json", "6845ffe793a6323235e1a062fae5ac3ba6867cfd2b9e90ea4f79e2c68e86372e"),
            Map.entry("federation.json", "0d319d4e56b51b29ca0a56e606040b49be19c497663d10895a973835ab642dd7"),
            Map.entry("hkdf.json", "52f1cc2ef6b9586156671a71384306322b3298624fa134eee9f5b8e5dd764d74"),
            Map.entry("index.json", "308d641590f93a5bb718eececb92e0cf5484b2b5e5b5814c73d7f23bb5948958"),
            Map.entry("key-wrap.json", "0b32246bb7067e93eca21283e0ebc8f1c3987ef4e6e8d5942cc55689f0d1bf4a"),
            Map.entry("manifest.json", "df9a531c4298441b8d88faa2917d917a01825a854d6f7281b1b49976f0b41ca8"),
            Map.entry("merge.json", "f33bf3782f1bf3c69e190140ebbf16c3c1f1bd28b8fff0c2a24609a856531bf5"),
            Map.entry("negative.json", "0b09642301587a5db6ce13138976a94423761cd75f40b846dd193537feeefe79"),
            Map.entry("README.md", "9b8fca1209dd8e24b8589b477ac0ac522c72faecc3d3139e603f762dad772f70"),
            Map.entry("x25519.json", "070ef12805fe4ac6d718ded40a210c1c829e1739d68b61e3ff529ca1e0257cbd")));

    @Test
    void everyVendoredFileIsTheUpstreamBytes() throws Exception {
        for (Map.Entry<String, String> e : SHA256.entrySet()) {
            try (InputStream in = AvpVectorFilesTest.class.getResourceAsStream("/avp-vectors/" + e.getKey())) {
                assertNotNull(in, e.getKey());
                byte[] digest = MessageDigest.getInstance("SHA-256").digest(in.readAllBytes());
                assertEquals(e.getValue(), HexFormat.of().formatHex(digest), e.getKey());
            }
        }
    }
}

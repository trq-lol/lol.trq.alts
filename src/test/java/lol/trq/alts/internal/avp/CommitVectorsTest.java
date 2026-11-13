package lol.trq.alts.internal.avp;

import static lol.trq.alts.internal.avp.Vectors.hex;
import static lol.trq.alts.internal.avp.Vectors.obj;
import static lol.trq.alts.internal.avp.Vectors.str;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import lol.trq.alts.internal.avp.Commits.Commit;
import lol.trq.alts.internal.avp.Commits.Header;
import org.junit.jupiter.api.Test;

/**
 * {@code commit.json} (SPEC 4.3): the root, single-parent and three-parent merge commits. The header
 * bytes, commit id, author signature, AAD v2 and ciphertext are reproduced from the seeds, the payload
 * opens back to its plaintext, every commit cites a {@code manifest.json} state by its real hash, and
 * neither the header nor the AAD depends on the order the parents arrive in.
 */
class CommitVectorsTest {

    private static final JsonObject ROOT = Vectors.load("commit.json");

    private static Map<String, byte[]> authorSeeds() {
        Map<String, byte[]> out = new HashMap<>();
        for (JsonElement e : ROOT.getAsJsonObject("seeds").getAsJsonArray("authors")) {
            out.put(str(e.getAsJsonObject(), "label"), hex(e.getAsJsonObject(), "ed25519SeedHex"));
        }
        return out;
    }

    @Test
    void everyCommitReproducesByteForByte() {
        JsonObject seeds = ROOT.getAsJsonObject("seeds");
        byte[] dataKey = hex(seeds, "dataKeyHex");
        byte[] iv = hex(seeds, "ivHex");
        Map<String, byte[]> authors = authorSeeds();
        for (JsonObject c : Vectors.cases(ROOT, "cases", 3)) {
            String name = str(c, "name");
            JsonObject expected = obj(c, "expected");
            Commit wire = Commits.fromJson(c.get("commit"));
            byte[] plaintext = str(c, "plaintextUtf8").getBytes(StandardCharsets.UTF_8);
            byte[] seed = authors.get(str(c, "authorLabel"));

            assertEquals(str(expected, "headerHex"), Vectors.hex(Commits.headerBytes(wire)), name);
            assertEquals(str(expected, "commitIdHex"), Vectors.hex(Commits.id(wire)), name);
            assertEquals(str(expected, "commitIdHex"), Vectors.hex(wire.commitId()), name);
            assertEquals(
                    str(expected, "aadHex"),
                    Vectors.hex(Commits.aadV2(wire.repoId(), wire.keyEpoch(), wire.author(), wire.parents())),
                    name);
            assertArrayEquals(
                    wire.authorSignature(), Ed25519Strict.sign(seed, Commits.sigMessage(wire.commitId())), name);
            assertTrue(Commits.verify(wire), name);

            Header header =
                    new Header(wire.repoId(), wire.parents(), wire.manifestSeq(), wire.manifestHash(), wire.keyEpoch());
            Commit sealed = Commits.sealWithIv(dataKey, header, plaintext, seed, iv);
            assertArrayEquals(wire.ciphertext(), sealed.ciphertext(), name + " ciphertext");
            assertArrayEquals(wire.commitId(), sealed.commitId(), name);
            assertArrayEquals(wire.authorSignature(), sealed.authorSignature(), name);
            assertArrayEquals(wire.author(), sealed.author(), name);

            assertArrayEquals(plaintext, Commits.open(wire, dataKey), name);
            assertEquals(Commits.toJson(wire), AvpJson.parse(AvpJson.write(c.get("commit"))), name + " wire form");
        }
    }

    @Test
    void theHeaderAndAadDoNotDependOnParentOrder() {
        for (JsonObject c : Vectors.cases(ROOT, "cases", 3)) {
            Commit wire = Commits.fromJson(c.get("commit"));
            List<byte[]> reversed = new ArrayList<>(wire.parents());
            Collections.reverse(reversed);
            Commit flipped = new Commit(
                    wire.repoId(),
                    wire.commitId(),
                    reversed,
                    wire.manifestSeq(),
                    wire.manifestHash(),
                    wire.keyEpoch(),
                    wire.author(),
                    wire.iv(),
                    wire.ciphertext(),
                    wire.authorSignature());
            assertEquals(str(obj(c, "expected"), "headerHex"), Vectors.hex(Commits.headerBytes(flipped)));
            assertEquals(
                    str(obj(c, "expected"), "aadHex"),
                    Vectors.hex(Commits.aadV2(wire.repoId(), wire.keyEpoch(), wire.author(), reversed)));
        }
    }

    @Test
    void everyCommitCitesAManifestStateByItsHash() {
        Map<Long, String> hashes = new HashMap<>();
        for (JsonObject m : Vectors.cases(Vectors.load("manifest.json"), "cases", 4)) {
            hashes.put(
                    m.getAsJsonObject("signedManifest")
                            .getAsJsonObject("state")
                            .get("manifestSeq")
                            .getAsLong(),
                    str(obj(m, "expected"), "manifestHashHex"));
        }
        for (JsonObject c : Vectors.cases(ROOT, "cases", 3)) {
            Commit wire = Commits.fromJson(c.get("commit"));
            assertEquals(hashes.get(wire.manifestSeq()), Vectors.hex(wire.manifestHash()), str(c, "name"));
        }
    }
}

package lol.trq.alts.internal.vault;

import static lol.trq.alts.internal.vault.VaultFixture.ACCOUNT;
import static lol.trq.alts.internal.vault.VaultFixture.await;
import static lol.trq.alts.internal.vault.VaultFixture.newOwner;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonPrimitive;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import lol.trq.alts.internal.avp.AvpBytes;
import lol.trq.alts.internal.avp.AvpCrypto;
import lol.trq.alts.internal.avp.Bip39;
import org.junit.jupiter.api.Test;

/**
 * No request the client sends a host carries the owner phrase, its entropy or seed, a private key, a data
 * key, or a plaintext account field, in any encoding (AVP SPEC 1, the freeze record's zero-knowledge rule).
 */
class VaultZeroKnowledgeTest {

    @Test
    void noRecordedRequestCarriesASecretOrAPlaintext() throws Exception {
        try (VaultFixture fx = new VaultFixture()) {
            VaultFixture.Owner o = newOwner();
            String marker = AvpBytes.hex(AvpCrypto.randomBytes(8));
            VaultEngine owner = fx.create(o);
            MemberKeys bobKeys = MemberKeys.generate();
            MemberKeys carolKeys = MemberKeys.generate();
            VaultEngine bob = fx.invite(owner, bobKeys);
            VaultEngine carol = fx.invite(owner, carolKeys);
            await(owner.write(e -> {
                e.setField(ACCOUNT, "username", new JsonPrimitive("user-" + marker));
                e.setField(ACCOUNT, "accessToken", new JsonPrimitive("access-" + marker));
                e.setField(ACCOUNT, "refreshToken", new JsonPrimitive("withheld-" + marker));
            }));
            await(owner.setShareRefreshTokens(true));
            await(bob.pull());
            await(bob.write(e -> e.setField(ACCOUNT, "refreshToken", new JsonPrimitive("shared-" + marker))));
            await(owner.pull());
            await(carol.pull());
            await(carol.leave());
            await(owner.processLeaves());
            await(owner.remove(bobKeys.ed25519Public()));
            await(owner.pull());

            Map<String, byte[]> secrets = new LinkedHashMap<>();
            String phrase = Bip39.entropyToMnemonic(o.entropy());
            secrets.put("entropy", o.entropy());
            secrets.put("phrase", phrase.getBytes(StandardCharsets.UTF_8));
            secrets.put("seed", Bip39.mnemonicToSeed(phrase, ""));
            secrets.put("owner ed25519 seed", o.keys().ed25519Seed());
            secrets.put("owner x25519 private", o.keys().x25519Private());
            secrets.put("bob ed25519 seed", bobKeys.ed25519Seed());
            secrets.put("bob x25519 private", bobKeys.x25519Private());
            secrets.put("carol ed25519 seed", carolKeys.ed25519Seed());
            secrets.put("carol x25519 private", carolKeys.x25519Private());
            owner.retainedEpochKeys().forEach((epoch, key) -> secrets.put("data key " + epoch, key));
            bob.retainedEpochKeys().forEach((epoch, key) -> secrets.put("bob's data key " + epoch, key));
            for (String plain : List.of("user-", "access-", "withheld-", "shared-")) {
                secrets.put("plaintext " + plain, (plain + marker).getBytes(StandardCharsets.UTF_8));
            }
            secrets.put("marker", marker.getBytes(StandardCharsets.UTF_8));
            assertTrue(owner.retainedEpochKeys().size() >= 3, "every epoch's key is checked");

            List<TestAvpHost.Request> requests = fx.host.requests();
            assertTrue(requests.size() > 30, "the whole flow was recorded");
            for (TestAvpHost.Request r : requests) {
                byte[] wire = wire(r);
                for (Map.Entry<String, byte[]> s : secrets.entrySet()) {
                    for (byte[] form : forms(s.getValue())) {
                        assertFalse(contains(wire, form), s.getKey() + " sent in " + r.method() + " " + r.path());
                    }
                }
            }
        }
    }

    private static byte[] wire(TestAvpHost.Request r) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write((r.method() + " " + r.path() + "\n").getBytes(StandardCharsets.UTF_8));
        for (Map.Entry<String, List<String>> h : r.headers().entrySet()) {
            out.write((h.getKey() + ": " + String.join(",", h.getValue()) + "\n").getBytes(StandardCharsets.UTF_8));
        }
        out.write(r.body());
        return out.toByteArray();
    }

    private static List<byte[]> forms(byte[] secret) {
        return List.of(
                secret,
                AvpBytes.base64(secret).replace("=", "").getBytes(StandardCharsets.UTF_8),
                AvpBytes.base64Url(secret).getBytes(StandardCharsets.UTF_8),
                AvpBytes.hex(secret).getBytes(StandardCharsets.UTF_8),
                AvpBytes.hex(secret).toUpperCase(java.util.Locale.ROOT).getBytes(StandardCharsets.UTF_8));
    }

    private static boolean contains(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }
}

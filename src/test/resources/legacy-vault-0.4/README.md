# AVP 0.4 repository fixtures (legacy importer)

Written once by the 0.4 half of `SharedVault`, as it shipped in 0.12.0, before that code was
removed: `createRepo`, `addMember`, `encryptPayload` and `removeMember` with the
`X25519-HKDF-SHA256-AESGCM-v1` wrap, serialized with Gson exactly as the 0.4 DTOs
(`VaultManifest`, `EncryptedEnvelope`, `WrappedIdentity`) went on the wire. Each `*-expected.json`
is what the 0.12 `openRepo` and `decryptPayload` returned for that repository, read by the member
named below. Never regenerate them: the importer is tested against what 0.12 wrote.

| File | What it is |
| --- | --- |
| `identity-alice.json` | Alice's stored identity, passphrase `alice-0.4-passphrase`, with a recovery sealing under the code in `alice-recovery-code.txt` |
| `identity-bob.json` | Bob's stored identity, passphrase `bob-0.4-passphrase` |
| `identity-carol.json` | Carol's stored identity, passphrase `carol-0.4-passphrase`; a member of no repository |
| `sharing-*` | Alice's repository that shares refresh tokens; Bob invited; payload version 2. Expected as Bob reads it |
| `withholding-*` | Alice's repository that withholds refresh tokens; Bob invited; payload version 1. Expected as Bob reads it |
| `smuggled-*` | A payload that carries refresh tokens under a manifest that withholds them (what a modified peer could push). Expected as Bob reads it: stripped |
| `rotated-*` | The sharing repository after Alice removed Bob: key epoch 1, Alice the only member. Expected as Alice reads it |

The passphrases and the recovery code are test values and protect nothing.

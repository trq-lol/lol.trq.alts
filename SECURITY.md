# Security Policy

## Supported versions

The latest released version on the `main` branch receives security updates.

## Reporting a vulnerability

Please report security vulnerabilities privately via [GitHub Security Advisories](https://github.com/trq-lol/lol.trq.alts/security/advisories/new) rather than opening a public issue.

We aim to acknowledge reports within 72 hours and to ship a fix or mitigation as quickly as the severity warrants.

Do not disclose the issue publicly until a fix has been released.

## Scope notes

This library handles Minecraft account credentials. The on-disk store is encrypted (AES-256-GCM + PBKDF2) and bound to the host machine; credentials are never transmitted by the library itself. API keys for optional integrations are supplied by the host through a seam and are never held or persisted by the library.

## Threat model

Worth being explicit about what the two encryption layers do and do not buy, so nobody over-trusts them.

**The local store (`AltStore`, `SecretStore`).** By default the PBKDF2 password is derived from machine properties, not from a user secret: the OS user name, the OS name, the home directory, and a constant that is public in this source. None of those is secret. The default key therefore keeps credentials off disk in plaintext and defeats casual copying — a file lifted from a backup or a synced folder does not open as-is on another machine — but it is obfuscation, not protection, against anyone who knows or can guess those values: they can derive the same key anywhere. It also does **not** protect against an attacker who can already run code as the same user on the same machine. A host that needs the store to resist a copied file should give it real key material through a host-supplied store key (for example one held in the OS credential store or derived from a user passphrase), and a user who wants more should use full-disk or per-user encryption underneath it.

**The shared vault (`SharedVault`).** Payloads are encrypted on the client and the data key is wrapped to each member's public key, so the server stores and relays only ciphertext, wrapped keys, public keys, and counters. What that guarantees depends on how the server behaves, so the two cases are stated separately.

*Guaranteed:* confidentiality of the accounts against a **passive (honest-but-curious) server** — one that stores and serves what members upload without altering it — and against anyone observing the network. Such a server, or someone who obtains a copy of its storage, cannot read a payload or recover a data key. Tampering with a payload, or splicing one across repositories, versions, or key epochs, fails authentication on the client.

*Not guaranteed:* confidentiality against an **actively malicious or compromised server**. In the current protocol nothing signs a member's wrapped data key, the manifest, or an envelope. A member's Ed25519 identity key signs authentication challenges only, and the key wrap is anonymous: anyone who knows a member's public key can produce a wrap that the member will accept. Concretely:

- **Key substitution on join.** A server can generate a data key of its own, wrap it to a joining member's public key, and serve that in the manifest. The member opens the repository normally, and everything they subsequently encrypt is readable by the server. The member cannot detect this from the manifest alone.
- **Key substitution on invite or rotation.** A server that serves member public keys can swap one for a key it controls, so that an existing member wraps the real data key to the server. This one has a defence today: `SharedVault` runs a `KeyBindingVerifier` before every wrap to another member's keys, and `IssuerSignedKeyBindingVerifier` rejects keys that do not carry a valid signature from an identity provider the host trusts. It protects only hosts that configure a real verifier; `KeyBindingVerifier.trustTransport()` accepts whatever is served.
- **The refresh-token sharing flag is unsigned.** The policy binds **members**, not the **manifest host**. `shareRefreshTokens` is plain manifest metadata with no signature over it and no binding into the payload AAD, so a server can serve `true` for a repository created withholding, and members will then upload refresh tokens.
- **Rollback.** A server can serve an older manifest or envelope. The client rejects this only where it has something to compare against: a host that persists a `RepoPin` per repository and passes it to `openRepo` gets a floor on the key epoch and payload version; a host that does not is trusting the server's counters.

Authenticated wraps — a signature by the wrapping member over the wrapped key, bound to the repository, the epoch, and the recipient, together with a signed manifest — are planned for a future protocol revision. They need a change to the wire format and so cannot be added compatibly. Until then, treat the shared vault as protecting against a server that is curious, breached, or subpoenaed for its storage, and not against one that is actively working against its members; share a repository only through a server whose operator you would trust not to do that.

One further boundary is inherent rather than pending: opting a repository into refresh-token sharing is effectively irreversible. `removeMember` and `rotateKey` re-key future payloads, but a refresh token already on a member's disk can only be revoked at the identity provider.

These are described in more detail in [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Reports that a guarantee above does not hold, or that a stated gap is wider than described, are in scope; reports that the stated gaps exist are not, since they are stated here.

**Out of scope.** How a consuming application acquires the accounts it feeds this library, and whether that use complies with any service's terms, is that application's responsibility — see [DISCLAIMER.md](DISCLAIMER.md).

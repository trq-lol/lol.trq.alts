# Security Policy

## Supported versions

The latest released version on the `main` branch receives security updates.

## Reporting a vulnerability

Please report security vulnerabilities privately via [GitHub Security Advisories](https://github.com/trq-lol/lol.trq.alts/security/advisories/new) rather than opening a public issue.

We aim to acknowledge reports within 72 hours and to ship a fix or mitigation as quickly as the severity warrants.

Do not disclose the issue publicly until a fix has been released.

## Scope notes

This library handles Minecraft account credentials. The on-disk stores are encrypted with AES-256-GCM under a PBKDF2-derived key. What that encryption is worth depends on where the key comes from: the default key is derived from machine properties and is obfuscation against casual copying, while a key the host supplies through `StoreKeyProvider` gives real protection for a copied file. The threat model below states both. The library sends credentials only to the identity and Minecraft services a sign-in or an account operation addresses, over the route the host configured. API keys for optional integrations are supplied by the host through a seam and are never held or persisted by the library.

## Threat model

This section states what each layer does and does not protect against, so that nobody trusts it for more than it gives.

### The local stores (`AltStore`, `SecretStore`)

**The default key.** With no `StoreKeyProvider`, the PBKDF2 password is derived from machine properties: the OS user name, the OS name, the home directory, and a constant that is public in this source. None of those is secret. The default key keeps credentials out of plaintext on disk and defeats casual copying: a file lifted from a backup or a synced folder does not open as it is on another machine. It is obfuscation, not protection, against anyone who knows or can guess those values, because they can derive the same key anywhere. It does not protect against an attacker who can already run code as the same user on the same machine.

**A host-supplied key.** A host that needs the stores to resist a copied file installs a `StoreKeyProvider` that returns real key material, for example an entry in the operating system's credential store or a key derived from a passphrase the user types. With a provider installed:

- A store file opens under the host's key or is reported unreadable. The machine-derived key is not accepted, so a file planted by someone who can write the store directory, sealed under that guessable key, does not load.
- The provider is never removed once installed. A `null` passed later, or a second runtime built without a provider, leaves it in place, so the stores cannot be silently rewritten under the weaker key.
- Resolution fails closed. When the provider throws, or returns `null` or fewer than 16 bytes, the store is unreadable and nothing is written. Writes stay refused, even once the provider answers again, until the store has been loaded successfully: the file on disk is intact, and writing what is in memory would replace it.

**Migration.** Files written before the provider was installed are sealed under the machine-derived key. They load under a provider only when the host sets `migrateFromMachineKey(true)`. That launch loads the old store, rewrites it under the host's key, and reseals or removes the rolling backup and every unreadable copy, so that no file left in the directory opens under the old key. The opt-in is meant for the one launch that adopts the provider. While it is on, the machine-derived key is still accepted, so anyone able to write the store directory can plant a store sealed under it, or put back a copy from before the migration, and have it load. Turn it off afterwards.

**What a host key does not cover.** The strength of the stores is the strength of the key material and of wherever the host keeps it. The key and the decrypted accounts are held in process memory while the library runs. An attacker running code as the same user can usually reach whatever the provider reaches. A user who wants more should use full-disk or per-user encryption underneath.

**Integrity of the files.** A write is staged, forced to disk, and moved into place in one step, and the file it replaces is kept as a rolling backup. A file that exists but cannot be read is never overwritten before it has been copied aside to `<name>.unreadable.<time>`; the newest five such copies are kept. On POSIX file systems the store file is created readable by its owner only.

### The transport and proxies

Every HTTP request the library makes goes through one class, which applies these rules:

- **Proxy resolution fails closed.** Once a `ProxyProvider` is installed, a provider that throws or names no route fails the request, and a proxy that refuses a tunnel fails it too. Nothing falls back to a direct connection. An installed provider cannot be removed by a later `null` or by a second runtime.
- **The proxy credential goes to the proxy only.** An HTTPS target behind an HTTP proxy is reached through a `CONNECT` tunnel the library opens itself. The credential is sent on the `CONNECT` and is never inside the TLS stream the origin reads. For a plain `http` target the credential is a request header, which the proxy is the peer for.
- **Connections are isolated per proxy identity.** A kept-alive connection is reused only by requests with the same proxy host, port and credential, so two usernames on one gateway never share a tunnel. A plain `http` request through an authenticated proxy is not kept alive.
- **TLS is the JVM's.** Default trust, hostname verification on, tunnelled or not. The library installs no system property, default authenticator, default `SSLContext` or proxy selector.
- **Redirects.** Requests do not follow redirects, except the binary fetch (avatars), which follows at most five, never when the request carries an `Authorization` header, drops credential headers when a hop leaves the origin, and refuses a step from `https` to `http`.
- **Bounded input.** Timeouts are finite, and a JSON or text response is read up to 1 MiB.

Limits a host relying on a proxy for privacy should know:

- **DNS on the tunnel path.** The `CONNECT` names the origin host, so the proxy resolves it. The JVM still looks the origin host name up through the local resolver before the tunnel is opened. The answer is unused, but the lookup happens: a host relying on the proxy to hide which services it contacts leaks those host names through local DNS.
- **The proxy leg is not encrypted by the library.** The connection to an HTTP proxy is plain TCP, so the `CONNECT` line and the Basic proxy credential cross that leg in the clear, as with any HTTP proxy using Basic authentication. The traffic inside the tunnel is TLS to the origin.
- **Authenticated SOCKS5 is not supported.** A SOCKS5 route with credentials is refused when it is built.
- **`NtpTimeSource` is not proxied.** It is opt-in, sends one UDP datagram to the NTP server directly, and does not consult the `ProxyProvider`.
- **A direct route uses the JVM's own proxy configuration**, if the host set one. "Direct" means the library adds no proxy of its own.

### Tokens in logs and messages

- Records that carry a credential redact it from `toString`: `AltAccount` (access and refresh token), `AuthToken`, `PlayerCertificate` (private key), `ProxyRoute` (username and password), and the HTTP response records, which print the status and never the body or a header value.
- Messages on a `LoginResult`, an `AccountStatus`, an `AccountException` or a bulk result are written by the library. A failure that came from the JDK or the transport is described by its kind ("timed out", "connection refused") and its own message is not repeated, because the JDK routinely quotes the offending input there.
- A request header holding a control character is refused before the JDK sees it, with a message that quotes nothing. Pasted tokens are stripped of whitespace and control characters.
- Store load and save errors name the file and a fixed phrase, never a file-system path.
- Bulk result labels are a username or a position (`entry 4`), never the input line.

The limit: the original exception stays reachable as the cause of a failure, for a host that wants to log it deliberately. A host that logs full cause chains takes on whatever the JDK put in them. The library also cannot redact what a host reads from an accessor (`account.accessToken()`) and logs itself.

### Interactive sign-in

- The browser login uses PKCE (S256), listens on the loopback addresses only, and lets only a request carrying the login's `state` decide the outcome.
- A device code signs in whoever started the flow, not whoever types the code. A host must start it only on the user's own action and show the verification address unmodified; a code shown to someone else is a phishing lure. The library never opens a browser or prints the code for this flow.
- Cookie login sends only `live.com` cookies, only to HTTPS hosts their domain covers, and accepts a token only from the service the sign-in starts at.

The device-code flow and the cookie chain were tested against loopback and scripted servers, not against the live services.

### The shared vault (`SharedVault`)

Payloads are encrypted on the client and the data key is wrapped to each member's public key, so the server stores and relays only ciphertext, wrapped keys, public keys, and counters. What that guarantees depends on how the server behaves, so the two cases are stated separately.

*Guaranteed:* confidentiality of the accounts against a **passive (honest-but-curious) server**, one that stores and serves what members upload without altering it, and against anyone observing the network. Such a server, or someone who obtains a copy of its storage, cannot read a payload or recover a data key. Tampering with a payload, or splicing one across repositories, versions, or key epochs, fails authentication on the client.

*Not guaranteed:* confidentiality against an **actively malicious or compromised server**. In the current protocol nothing signs a member's wrapped data key, the manifest, or an envelope. A member's Ed25519 identity key signs authentication challenges only, and the key wrap is anonymous: anyone who knows a member's public key can produce a wrap that the member will accept. Concretely:

- **Key substitution on join.** A server can generate a data key of its own, wrap it to a joining member's public key, and serve that in the manifest. The member opens the repository normally, and everything they subsequently encrypt is readable by the server. The member cannot detect this from the manifest alone.
- **Key substitution on invite or rotation.** A server that serves member public keys can swap one for a key it controls, so that an existing member wraps the real data key to the server. This one has a defence today: `SharedVault` runs a `KeyBindingVerifier` before every wrap to another member's keys and wraps only to the keys the verifier returned. `IssuerSignedKeyBindingVerifier` rejects keys that do not carry a valid signature from an identity provider the host trusts. There is no default verifier: the two-argument `SharedVault` constructor requires one, and `KeyBindingVerifier.trustTransport()`, which accepts whatever is served, has to be passed on purpose. It is the right choice only when the keys did not come from a server the host would not trust with the accounts themselves. The deprecated one-argument constructor installs `trustTransport()` without being asked, which is why it is deprecated.
- **The refresh-token sharing flag is unsigned.** The policy binds **members**, not the **manifest host**. `shareRefreshTokens` is plain manifest metadata with no signature over it and no binding into the payload AAD, so a server can serve `true` for a repository created withholding, and members will then upload refresh tokens.
- **Rollback.** A server can serve an older manifest or envelope. The client rejects this only where it has something to compare against: a host that persists a `RepoPin` per repository and passes it to `openRepo` gets a floor on the key epoch and payload version; a host that does not is trusting the server's counters.

Authenticated wraps (a signature by the wrapping member over the wrapped key, bound to the repository, the epoch, and the recipient, together with a signed manifest) are planned for a future protocol revision. They need a change to the wire format and so cannot be added compatibly. Until then, treat the shared vault as protecting against a server that is curious, breached, or subpoenaed for its storage, and not against one that is actively working against its members; share a repository only through a server whose operator you would trust not to do that.

One further boundary is inherent rather than pending: opting a repository into refresh-token sharing is effectively irreversible. `removeMember` and `rotateKey` re-key future payloads, but a refresh token already on a member's disk can only be revoked at the identity provider.

### Scope of reports

These are described in more detail in [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Reports that a guarantee above does not hold, or that a stated gap is wider than described, are in scope; reports that the stated gaps exist are not, since they are stated here.

**Out of scope.** How a consuming application acquires the accounts it feeds this library, and whether that use complies with any service's terms, is that application's responsibility; see [DISCLAIMER.md](DISCLAIMER.md).

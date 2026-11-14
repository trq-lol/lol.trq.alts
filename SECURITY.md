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

### The local stores (`AccountStore`, `HostSecrets`)

Each `AltsRuntime` owns one `AccountStore` and one `HostSecrets`, each an encrypted file in the directory the host named, with its own key binding, its own key and its own lock. Nothing about them is process-wide: two runtimes in one process, on two directories, never see each other's accounts, secrets or keys.

**The default key.** With no `StoreKeyProvider`, the PBKDF2 password is derived from machine properties: the OS user name, the OS name, the home directory, and a constant that is public in this source. None of those is secret. The default key keeps credentials out of plaintext on disk and defeats casual copying: a file lifted from a backup or a synced folder does not open as it is on another machine. It is obfuscation, not protection, against anyone who knows or can guess those values, because they can derive the same key anywhere. It does not protect against an attacker who can already run code as the same user on the same machine.

**A host-supplied key.** A host that needs the stores to resist a copied file installs a `StoreKeyProvider` that returns real key material, for example an entry in the operating system's credential store or a key derived from a passphrase the user types. With a provider installed:

- A store file opens under the host's key or is reported unreadable. The machine-derived key is not accepted, so a file planted by someone who can write the store directory, sealed under that guessable key, does not load.
- The provider belongs to the runtime it was given to, and is fixed for that runtime's life; no other runtime's stores ever see it. A runtime built without it, on the same directory, cannot open the host-keyed files, and does not write over them either: a file that exists and did not open is never overwritten (see below), so it cannot be silently rewritten under the weaker key.
- Resolution fails closed. When the provider throws, or returns `null` or fewer than 16 bytes, the store is unreadable and nothing is written, even once the provider answers again, until the store has been loaded successfully: the file on disk is intact, and writing what is in memory would replace it.

**Migration.** Files written before the provider was installed are sealed under the machine-derived key. They load under a provider only when the host sets `migrateFromMachineKey(true)`. That launch loads the old store, rewrites it under the host's key, and reseals or removes the rolling backup and every unreadable copy, so that no file left in the directory opens under the old key. The opt-in is meant for the one launch that adopts the provider. While it is on, the machine-derived key is still accepted, so anyone able to write the store directory can plant a store sealed under it, or put back a copy from before the migration, and have it load. Turn it off afterwards.

**What a host key does not cover.** The strength of the stores is the strength of the key material and of wherever the host keeps it. The key and the decrypted accounts are held in process memory while the library runs. An attacker running code as the same user can usually reach whatever the provider reaches. A user who wants more should use full-disk or per-user encryption underneath.

**Integrity of the files.**

- **Fail-closed after any failed load.** A file that exists but cannot be read, whatever the reason (the wrong key, an unavailable key, a damaged file, a read error), is never written over. The load is reported on `loadError()` as kind `STORAGE`, and every write is refused, reported on `saveError()`, until a later load succeeds, the file is gone, or the host calls `discardUnreadable()`. That call is the explicit route for a renamed OS user, a moved home directory or a rotated key, and only the host can decide it; nothing in the library gives up on a file by itself.
- **Copies aside.** Such a file is copied to `<name>.unreadable.<time>` when the load fails (or, when it failed only because the key was unavailable, when it is discarded); the newest five copies are kept. A discard whose copy fails leaves the refusal in place.
- **The lock.** Each store holds an exclusive lock on a sidecar `<name>.lock` for its runtime's lifetime, so two runtimes, in one process or two, never write the same file: the second one's `build()` fails with kind `CONFLICT`, and a build that fails holds no lock. `close()` releases it.
- **Atomic writes.** A write is staged, forced to disk, and moved into place in one step, and the file it replaces is kept as a rolling backup. On POSIX file systems the store file is created readable by its owner only.

### The transport and proxies

Every HTTP request the library makes goes through one transport, which the runtime builds for itself and hands to every service; two runtimes share no transport, tunnel or thread. It applies these rules:

- **Proxy resolution fails closed.** When a runtime has a `ProxyProvider`, a provider that throws or names no route fails the request, and a proxy that refuses a tunnel fails it too. Nothing falls back to a direct connection. The provider is fixed when the runtime is built; a runtime built without one connects directly, whatever another runtime in the process was given.
- **The proxy credential goes to the proxy only.** An HTTPS target behind an HTTP proxy is reached through a `CONNECT` tunnel the library opens itself. The credential is sent on the `CONNECT` and is never inside the TLS stream the origin reads. For a plain `http` target the credential is a request header, which the proxy is the peer for. A caller-supplied `Proxy-Authorization` header, in any capitalisation, is refused before anything is sent, so no code path inside the library can put the credential on a connection the JDK would send to the origin.
- **Connections are isolated per proxy identity.** A kept-alive connection is reused only by requests with the same proxy host, port and credential within one runtime, so two usernames on one gateway never share a tunnel. A plain `http` request through an authenticated proxy is not kept alive.
- **TLS is the JVM's.** Default trust, hostname verification on, tunnelled or not. The library installs no system property, default authenticator, default `SSLContext` or proxy selector.
- **Redirects.** Requests do not follow redirects, except the binary fetch (avatars), which follows at most five, never when the request carries an `Authorization` header, drops credential headers when a hop leaves the origin, and refuses a step from `https` to `http`.
- **Bounded input.** Timeouts are finite, a JSON or text response is read up to 1 MiB, and a vault exchange up to 16 MiB.
- **Closing.** After `AltsRuntime.close()` the transport refuses every request and its tunnels are closed.

Limits a host relying on a proxy for privacy should know:

- **DNS on the tunnel path.** The `CONNECT` names the origin host, so the proxy resolves it. The JVM still looks the origin host name up through the local resolver before the tunnel is opened. The answer is unused, but the lookup happens: a host relying on the proxy to hide which services it contacts leaks those host names through local DNS.
- **The proxy leg is not encrypted by the library.** The connection to an HTTP proxy is plain TCP, so the `CONNECT` line and the Basic proxy credential cross that leg in the clear, as with any HTTP proxy using Basic authentication. The traffic inside the tunnel is TLS to the origin.
- **Authenticated SOCKS5 is not supported.** A SOCKS5 route with credentials is refused when it is built.
- **`NtpTimeSource` is not proxied.** It is opt-in, sends one UDP datagram to the NTP server directly, and does not consult the `ProxyProvider`.
- **A direct route uses the JVM's own proxy configuration**, if the host set one. "Direct" means the library adds no proxy of its own.
- **A host-installed `CookieHandler` sees library requests.** `HttpURLConnection` consults the process-wide `java.net.CookieHandler.getDefault()` on every request, and the library cannot turn that off per connection. A handler the host (or another library in the process) installed is offered the URL and response headers of every library request, including the sign-in hops, and may add cookies to them. The library installs none. The JVM's response cache, by contrast, is off for every library connection (`setUseCaches(false)`), so no body carrying a token is handed to a host-installed `ResponseCache`.

### Tokens in logs and messages

- Records that carry a credential redact it from `toString`: `AltAccount` (access and refresh token), `PlayerCertificate` (private key), `ProxyRoute` (username and password), and the transport's response records, which print the status and never the body or a header value. The vault's secret-bearing types do the same: `OwnerIdentity` shows its fingerprint only, `VaultSnapshot` its repository, pin and counts, and `LinkGrant` nothing but its type.
- Every failure is an `AltsFailure` whose message the library builds. A failure that came from the JDK or the transport is described by its kind ("timed out", "connection refused") and its own message is not repeated, because the JDK routinely quotes the offending input there; nor is a service's own error text, or what the host's session injector threw. No message carries a token, a cookie, a code or a file-system path.
- A request header holding a control character is refused before the JDK sees it, with a message that quotes nothing. Pasted tokens are stripped of whitespace and control characters.
- Store load and save errors name the file and a fixed phrase, never a path.
- Bulk result labels are a username or a position (`entry 4`), never the input line.

The limit: the original exception stays reachable as the cause of a failure, for a host that wants to log it deliberately. A host that logs full cause chains takes on whatever the JDK put in them. The library also cannot redact what a host reads from an accessor (`account.accessToken()`) and logs itself.

### Interactive sign-in

- The browser login uses PKCE (S256), listens on the loopback addresses only, and lets only a request carrying the login's `state` decide the outcome.
- A device code signs in whoever started the flow, not whoever types the code. A host must start it only on the user's own action and show the verification address unmodified; a code shown to someone else is a phishing lure. The library never opens a browser or prints the code for this flow.
- Cookie login sends only `live.com` cookies, only to HTTPS hosts their domain covers, and accepts a token only from the service the sign-in starts at.

The device-code flow and the cookie chain were tested against loopback and scripted servers, not against the live services.

### The shared vault (AVP 0.5)

The vault implements the [Alt Vault Protocol](https://github.com/trqlmao/avp) 0.5, whose specification is still labelled draft, as a client; the protocol's own threat model (`THREATMODEL.md` in that repository) is the reference, and this section states what this client adds or chooses. Payloads are encrypted on the client and the data key is wrapped to each member's X25519 key, so a host stores and relays only ciphertext, wrapped keys, public keys, counters, ids and signatures. Every host is untrusted for confidentiality and integrity, the member's own home host included, and trusted only for availability.

**What it resists.**

- **An owner-signed chain.** The members, their wrapped data keys, the key epoch, the refresh-token policy and the hosts are fixed by a chain of manifest states, each signed by the owner key (derived from a 24-word BIP39 phrase) and hash-linked to the one before. The client verifies the chain from genesis itself, recomputes the repository id from the owner key and genesis nonce, and checks the owner key against the fingerprint in the repo locator a joiner was given. A host cannot add a member, a host or a key, and cannot forge a state.
- **Member-signed commits.** Every write is a commit whose id covers the repository, the parents, the state it was written under, the epoch, the author, the IV and the ciphertext, and whose author signs that id; the payload AAD binds the repository, epoch, author and parents. A commit by a non-member, a commit moved to another repository, epoch or parent set, or a removed member's commit outside the signed removal cutoff, is refused.
- **The policy flag.** `shareRefreshTokens` is inside the owner-signed state, so a host that flips it breaks the signature. And the client enforces it on both sides: unless the latest verified state says to share, `refreshToken` and `expiresAt` are stripped from every payload it writes, reads or merges, so a token a modified member wrote is discarded on read.
- **Wraps only to invite-token keys.** The owner's client wraps the data key only to keys taken from the invite token the joiner produced, never to keys a host serves, and verifies the acceptance the joiner's home host signed into that token before adding the member. An owner compares the token's fingerprint with the one the joiner's device shows.
- **Pins and the tie rule.** The client pins the sequence number and hash of the highest state it verified (held in `VaultSnapshot`) and refuses a chain without the pin, so a host cannot roll a device back. The one exception is a fork at or below the pin that wins the deterministic tie rule (the bytewise-lower state hash), which only two offline owner devices can produce; it is reported (`SyncReport.divergedAt()`), not silent.
- **Strict Ed25519.** Signatures are verified with the strict rules the specification fixes (small-order and non-canonical points and an out-of-range `S` rejected before a cofactorless check), so this client accepts exactly the signatures every conformant implementation accepts.
- **A domain-separated challenge.** Host authentication signs `CE(tag "avp/challenge/v1", bytes(hostKey), bytes(memberKey), bytes(nonce))`, never the raw nonce, and every signed construction starts with its own tag, so a host cannot use the challenge to obtain a commit, leave or manifest signature. The library signs nothing outside these constructions. The 0.4 export aid `VaultIdentity.signChallenge`, which does sign raw bytes for a 0.4 server, refuses any input that begins with `avp/` or is shorter than 16 or longer than 1024 bytes.
- **Zero knowledge.** The library never sends a host the owner phrase, its entropy or seed, a private key, a data key or a plaintext account field; a test checks every recorded request body for each.

**Design choice: a forged state fails the operation.** A host that serves a state failing a check of the specification's manifest rules, or a chain that does not contain the pin and does not win the tie rule (a rollback), fails the whole operation with `PROTOCOL`, and the device's copy stays as it was. This deviates from the reference client, which keeps the valid prefix of what a host served and goes on from there. Failing closed means a lying host cannot choose the point, within the chain it served, to which a device advances; the cost is availability, since one bad state stops that host's syncs until it stops serving it. A head the client cannot read is left alone and counted, not fatal.

**A relayed challenge on first contact.** Discovery is unauthenticated (SPEC 11.7). A client that reaches a host by its locator alone, with no key from a token, a manifest or a snapshot, takes whatever key the answer names. An impostor at that address can name host A's key, fetch a challenge nonce from A for the member, and relay it; the client signs A's transcript, and the impostor redeems it at A for a bearer token in the member's name. The domain separation keeps that signature from serving anything but A's sign-in, the token cache never hands A's token to another address, and the client never sends the impostor a cached token, a secret or a plaintext; but the impostor holds a token for A, with which it can pull ciphertext as the member there until it expires. This is inherent to SPEC 3.3 and 11.7 without an authenticated channel or a known key. The library narrows it by reaching a locator over HTTPS by default and by passing the known key on every connection that has one: use `connect(HostRef)`, `connect(locator, key)`, `connect(RepoLocator)` or `connect(VaultSnapshot)` once the key is known, and `connectFirstContact` only for a true first contact, comparing the key it reports out of band.

**Secrets the host stores.** `VaultSnapshot` holds the retained data keys of every epoch the member could read, and the owner's `entropy()` is the owner key. Both are secrets: persist them encrypted, in `HostSecrets` for example, which is what the examples do, and never in plain configuration. A member's `VaultIdentity` is stored as its passphrase-wrapped `WrappedIdentity`. A lost owner phrase cannot be recovered by the library.

**What it still does not cover.**

- **Denial of service.** A host can refuse to serve, or delete what it holds. Several hosts improve availability in practice and guarantee nothing.
- **Metadata.** Hosts see the roster (public keys), the host set, payload sizes, the shape of the commit graph, and when members read and write.
- **Forked views.** A host cannot invent a second history, but it can show different members different subsets of heads. Members detect it the moment they compare what they hold (the manifest hashes they pinned, the heads they see); nothing in the protocol makes them compare.
- **A member who is the attacker.** A current member holds the data key by design and can copy every account. Removal rotates the key for future commits only; there is no backward secrecy, and a refresh token already shared keeps working until it is revoked upstream.
- **A member who writes the largest stamp.** A current member can sign a commit holding a field or ban whose stamp has `at` and `n` both at the int64 maximum. The specification makes a client observe every stamp it merges before its next write, and no stamp is greater, so every member whose client merges that commit can stamp nothing more: each account write (`update`, `put`, `remove`, `markBanned`) fails with `PROTOCOL`, while syncs, merge pushes and owner operations still work. Merge keeps that field, since its stamp is the greatest; each member's merge commit carries it on in its full-state payload, and each device's clock in `VaultSnapshot` stays at the maximum. Removing the member, rotating the key or editing the account therefore does not undo it, and nothing within the protocol does: the only way out is a new repository. Only a member can cause it, because the commit is member-signed; a host cannot forge such a stamp, and can only relay a commit a member signed, as replication would. The library does not depart from the specification to resist it, because a bounded-skew rule would break its rule that every stamp is observed; it is an open item of the protocol.
- **A withholding host.** A host can withhold or delay new heads and states. A member whose only host withholds cannot tell "nothing new" from "hidden", and a first join with no pin depends on its host for freshness. A member on another listed host still gets the writes through replication. Freshness against a withholding host is an open item of the protocol.
- **A lost owner phrase.** The owner key is fixed for the repository's life and ownership transfer is not specified. With the phrase lost and no other owner device, the repository keeps working for its members, but its membership, policy and hosts are frozen. A stolen phrase is a full ownership compromise.
- **The losing owner branch.** When two offline owner devices diverge, the tie rule keeps one branch and discards the other's changes: members invited only there must be invited again, and removals made only there must be made again. Until they are redone, a member the owner meant to remove on the losing device is still a member.
- **A stolen bearer token.** A host's bearer token is a bearer credential: until it expires, whoever holds it can pull ciphertext as that member at that host. It cannot sign a commit, a state or a leave request. TLS is what keeps it from being captured, so reach hosts over HTTPS (the default); a `Builder#vaultHostAddress` mapping to plain `http` is for a loopback or test host only.
- **The draft label.** 1.0 freezes the vault API against AVP 0.5 as it stands; a wire change to 0.5 before it is final would need a new major version or a documented exception.

**Refresh-token sharing is effectively irreversible.** Removing a member re-keys future commits, but a refresh token already on a member's disk can only be revoked at the identity provider.

**The 0.4 importer.** `LegacyVaultReader` reads one 0.4 repository with a member's identity, for carrying its accounts into a new 0.5 repository. It is read-only: it never writes and never talks to a host. It proves nothing 0.4 did not: nothing in a 0.4 repository is signed, so a 0.4 host that lied could have substituted keys or served an older payload before the import, and the import has no rollback floor, being one read with no earlier state to compare. Review the accounts before writing them into the new repository.

### Jar sealing and the module

The implementation lives under `lol.trq.alts.internal`. On the module path that package is closed: the module does not export it, and code outside the library cannot read it. On the class path a module descriptor restricts nothing, so public classes under `internal` stay callable there; they are outside the API and outside every guarantee here, and the internal bridges the runtime uses to build its stores and services can be called by class-path code too. What the class path cannot do is join the library's packages: the jar is sealed, so a class from another jar cannot be loaded into one of them to reach package-private members, and the bridges accept only the library's own implementation, loaded by the library's own class loader, so no code can substitute one and see a key provider or a store the library did not open.

### Scope of reports

These are described in more detail in [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Reports that a guarantee above does not hold, or that a stated gap is wider than described, are in scope; reports that the stated gaps exist are not, since they are stated here.

**Out of scope.** How a consuming application acquires the accounts it feeds this library, and whether that use complies with any service's terms, is that application's responsibility; see [DISCLAIMER.md](DISCLAIMER.md).

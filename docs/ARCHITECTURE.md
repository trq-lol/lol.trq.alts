# Architecture

**lol.trq.alts** is an account library for Minecraft: Java Edition, usable from a launcher, a tool, the host application of a bot, or an account manager. It is consumer-agnostic and holds no Minecraft or renderer types; everything platform-specific crosses a seam the host implements.

## Layers

```
            ┌──────────────────────────────────────────────────────────────┐
  host      │  seam implementations (SessionInjector, ProxyProvider, ...)   │
            └───────────────▲──────────────────────────────────────────────┘
                            │ spi/ interfaces
            ┌───────────────┴──────────────────────────────────────────────┐
            │  AltsRuntime: wiring root + Builder, AutoCloseable            │
            │  AltsFailure / AltsException: the one error model             │
            ├───────────────────────────────────────────────────────────────┤
  API       │ spi/      the host seams: session, directory, main thread, toasts,
  (module   │           textures, avatars, stats, proxy, store key, device-code prompt
  exports)  │ auth/     login and account services, LoginResult, AccountStatus, config
            │ account/  services over a token: profile, entitlements, name, skin, cape,
            │           attributes, certificates, blocklist; public profile lookup
            │ bulk/     one operation over many accounts: options, progress, report
            │ store/    AccountStore + HostSecrets, one per runtime
            │ net/      NetworkScope, ProxyRoute: what a ProxyProvider sees
            │ time/     TimeSource, SystemTimeSource, NtpTimeSource
            │ cache/    AsyncCache<K,V>
            │ skin/     SkinAvatarCache<H>
            │ model/    AltAccount, SessionData, GameStats, BanInfo, enums
            │ vault/    VaultHosts, SharedVault, identities, tokens, snapshot,
            │           LegacyVaultReader
            ├───────────────────────────────────────────────────────────────┤
  internal  │ internal.net    HttpTransport (one per runtime), proxy tunnel, FailureText
  (not      │ internal.auth   the Microsoft, cookie and session chains; the login services
  exported) │ internal.account, internal.bulk, internal.skin   service implementations
            │ internal.store  StoreFile (the locked, atomic writer), EncryptionUtil
            │ internal.crypto Ed25519, X25519, PBKDF2, PayloadCipher
            │ internal.avp    AVP 0.5 constructions: canonical encoding, strict Ed25519,
            │                 BIP39, manifest, commit, payload, tokens
            │ internal.vault  the AVP 0.5 client engine; legacy/ the 0.4 importer
            └───────────────────────────────────────────────────────────────┘
```

## Key pieces

- **`AltsRuntime<H>`** is the single wiring root, and it owns everything it builds. Its builder takes the seam implementations and validates the required ones (`SessionInjector`, `VaultDirectoryProvider`, `MainThreadExecutor`, `ToastSink`) in `build()`, never in the setters. `build()` asks the directory provider once, opens and locks the two store files, creates the executor (unless the host gave one) and the transport, loads the stores, and constructs the services and caches over them. A build that fails part-way releases what it opened: no lock, no executor. `H` is the host's texture-handle type, threaded through `SkinAvatarCache<H>` so the cache is type-safe without the library knowing what a texture is. Nothing is process-wide: two runtimes in one process, on two directories, share no account, secret, proxy provider, connection or thread.

- **`spi/`** is the entire host boundary. The library calls these interfaces and never imports a host class. Required: `SessionInjector`, `VaultDirectoryProvider`, `MainThreadExecutor`, `ToastSink`. Optional: `TextureUploader<H>`, `AvatarSource`, `GameStatsSource`, `ProxyProvider`, `StoreKeyProvider`, and `DeviceCodePrompt`, which is passed per login rather than to the builder. A host implements these, so a method added to one needs a default.

- **`auth/`**. `AltLoginService` exposes eight `CompletableFuture`-based methods: seven sign-in routes (Microsoft browser, Microsoft device code, refresh token, cookie text, cookie file, session token, offline) plus `loginAccount`, which logs into a record the caller already holds. Each resolves on the runtime's executor and hands the identity to the host's `SessionInjector` as a transport-neutral `SessionData`. The browser route is the authorization-code flow with PKCE and a loopback callback server that only a request carrying the login's `state` can complete. The device-code route polls the token endpoint at the advertised interval until approval, refusal or expiry. `loginAccount` renews an expired session from the account's stored refresh token, proactively when the stored expiry says the access token is spent and once reactively when the services refuse it, persisting the rotated credential before installing the session. `routed(tag)` returns a view of the service whose every request carries a route tag.

  `AltAccountService` is the same machinery with the injection removed: `check` asks whether a stored token still works and changes nothing, `refresh` renews it and persists the rotation, and neither installs a session. The split exists because a sweep over every stored account cannot be a loop over `loginAccount`, which switches session once per account, and because rotation is not free: the token endpoint issues a new refresh token on every redemption.

  `MicrosoftAuthConfig` carries the dialect as well as the endpoints. An Azure OAuth application and a legacy MSA one differ in the redirect the grant must declare, the scope it asks for, and the RPS ticket prefix Xbox Live wants, so `legacyMsa(clientId)` exists alongside `of(clientId)`. The config also carries the device-code endpoints and the Minecraft services URLs the cookie route and the account services use. The chains themselves (`MicrosoftAuthUtil`, `CookieAuthUtil`, `AccountNetworkUtil`) are instance classes in `internal.auth` over the runtime's transport.

- **`account/`** is the surface over a live access token, built by `alts.accountServices(account)` (or `(token, uuid)`): `profile()` (read, read-if-present, create), `entitlements()`, `name()` (availability, eligibility, change, scheduled claim), `skin()` (with local `validate`), `cape()`, `attributes()` (privileges, preferences, platform ban status), `certificates()` (the chat-signing key pair) and `blocklist()`. None of them installs a session or touches the store. `ProfileLookupService`, reached as `alts.profileLookup()`, is the anonymous counterpart: name or UUID to public identity, with no token. Both reach `Builder#accountEndpoints`, or by default the origin of the configured Minecraft profile URL. The implementations live in `internal.account`.

- **`bulk/`** runs `checkAll`, `refreshAll`, `entitlementsAll` and `importCredentials` over a list. See [Bulk runs](#bulk-runs).

- **`store/`**, **`net/`**: see [Store persistence](#store-persistence) and [Transport](#transport). The public `net` package holds only the two values a `ProxyProvider` deals in, `NetworkScope` (purpose, account, route tag) and `ProxyRoute`.

- **`time/`**. `TimeSource` is the clock the scheduled name claim reads. `NtpTimeSource.now()` is arithmetic over the last measured offset and never touches the network; measurement runs in the background on the executor its constructor takes, and `sync()` is the blocking form. It is the library's only non-HTTP network use: one UDP datagram, sent directly, not through the `ProxyProvider`.

- **`cache/AsyncCache<K,V>`** is the async-lookup primitive. `get(key)` never blocks: it returns the cached value or `null` and starts a background fetch on the executor it was built with. A positive TTL makes it stale-while-revalidate. A failed first fetch is retried after a backoff that grows from five seconds to five minutes; a failed refresh keeps the stale value. The cache is bounded (4096 entries by default), dropping the entries read longest ago. The per-server game-stats caches are built on it.

- **`skin/SkinAvatarCache<H>`** is keyed by UUID and built only by the runtime. The default source (`internal.skin.MojangAvatarSource`) resolves the skin from Mojang's session server, requires the texture address to name the Mojang texture host, fetches it over HTTPS with redirects held to that host, checks the declared image dimensions before decoding, and crops the face locally. `Builder#avatarUrlTemplate` selects the template source instead. At most six downloads are in flight; the rest queue. A failed fetch retries on a growing backoff.

- **`vault/`**: see [Shared vault](#shared-vault).

## Module and internal packages

The jar is the named module `lol.trq.alts` (`src/main/java/module-info.java`). It exports the twelve API packages and nothing under `lol.trq.alts.internal`; it `requires transitive com.google.gson`, because `@SerializedName` sits on public records (the build declares Gson as an ordinary `api` dependency), and requires `java.desktop` (the system browser, ImageIO) and `jdk.httpserver` (the loopback redirect). It opens exactly three packages, to Gson only: `store` and `internal.auth`, whose private records Gson builds by reflection, and `model`, whose `AltAccount` is a final class Gson reads and fills field by field.

The fences around `internal`:

- **On the module path** a host cannot read an internal package at all; `ModulePathConsumerTest` compiles a consumer module against the jar and shows that an internal import does not compile.
- **On the class path** a descriptor restricts nothing, so the jar is sealed (`Sealed: true`): no other jar can add a class to one of the library's packages and reach its package-private members. Public classes under `internal` remain callable there, outside the API and outside every promise.
- **The published Javadoc** documents the exported packages only, and `javadocCheck` fails on any internal entry or reference in the javadoc jar.
- **The compatibility gate.** `api/lol.trq.alts.api` is the committed dump of every exported type, member and signature (constants with their values), generated from the jar by the JDK-only tool in `src/apiTool`. `apiCheck`, part of `check`, fails when a line is removed or changed unless the build's major version is greater than the dump's, when the jar has API the dump lacks, and outright when a signature names an internal type or an internal package is exported. `apiDump` writes the dump and refuses to erase lines within a major version unless given `-PapiAllowBreaking=<reason>`.

Runtime-built public types (the stores, `AccountServices`, `ProfileLookupService`, `SkinAvatarCache`, `VaultHosts`) have no public factory. Each package holds a package-private bridge (`StoreBridge`, `AccountBridge`, `SkinBridge`, `VaultBridge`) that installs itself into an `internal.*Access` class when the package initializes; the `Access` class accepts only that bridge, loaded by the library's own class loader, and only once, and the runtime builds through it.

`check` runs the whole suite twice: on the class path (`test`) and with the jar as a named module and the tests patched into it (`moduleTest`), so a missing `requires` or `opens` fails there.

## Threading

- **The runtime's executor.** Every blocking call, and everything that waits on one, runs on the runtime's executor: by default one the runtime creates, which starts a virtual thread per task named `alts-io-<n>`, or the executor the host passed to `Builder.executor(...)`. Nothing runs on `ForkJoinPool.commonPool()`. Continuations a host attaches to a returned future without naming an executor run there too while the future is still pending (one attached to a future that has already completed runs on the caller's thread, as the JDK does), and so do `AsyncCache` loaders, `GameStatsSource.fetch`, `AvatarSource`, and `DeviceCodePrompt.show`. Services reach the executor through the transport (`transport.executor()`); none reads a static.
- **Waits.** Every delay in the library (bulk pacing, device-code polling, a scheduled claim, retry backoff) goes through the transport's `schedule` / `delay`, which `close()` ends: a wait pending at close fails at once, as does a task the executor refuses. The JDK's own delayed executor would swallow that rejection and leave the waiter waiting.
- **The session injector is called off the main thread.** A `SessionInjector` that touches main-thread state marshals onto it itself. The library uses the `MainThreadExecutor` for texture uploads.
- **The store writers.** Each store writes on its own daemon thread, `alts-store-writer`, separate from the executor so that a slow disk does not hold a request thread and a busy executor does not delay a write. A shutdown hook per store (`alts-store-flush`) flushes whatever is still pending; `close()` removes it.
- **Avatar fetches** are bounded to six in flight. The bound is a queue, not blocked threads.
- **Bulk runs** create no executor. The concurrency bound is structural: that many worker chains each pull the next entry off a shared cursor.
- **Store state.** `AccountStore`'s account list is copy-on-write and `HostSecrets`' map is concurrent, because a login resolving on an executor thread mutates them while the host reads them from its own thread. `accounts()` is a live list, and iterating it during a login sees a snapshot. Mutators are atomic with respect to each other and to a save.
- **Closing.** `AltsRuntime.close()` is idempotent. It flushes and closes both stores (releasing their locks and stopping their writers), drops the vault's cached host tokens, closes the transport (pooled tunnels closed, every later request refused), and shuts down an executor the runtime created; a host's executor is left running. Whatever waited on the runtime fails on the thread that calls `close()`, with the callbacks chained onto it. A route started afterwards returns a `CANCELLED` result, or throws `AltsException` of kind `CANCELLED` where it has no result type.

## Store persistence

`AccountStore` (accounts) and `HostSecrets` (per-user secrets that must never enter a shared repository) are instance types, one of each per runtime, each over its own `internal.store.StoreFile` with its own file, key binding and lock. Neither has a public factory or `close()`: the runtime opens them through the store bridge and closes them when it closes.

- **Format and key.** AES-256-GCM under a PBKDF2-derived key. Without a `StoreKeyProvider` the PBKDF2 password is derived from machine properties and a host-configurable key-binding constant, which is obfuscation (see [SECURITY.md](../SECURITY.md)). With one, the password is the host's key material bound to the same constant. The key is derived once per store and reused with a fresh nonce per write.
- **The lock.** Each store takes an exclusive `FileChannel` lock on a sidecar `<name>.lock` when it opens and holds it until it closes. A second runtime on the same file, in this process or another, fails `build()` with an `AltsException` of kind `CONFLICT` (the message names the file, never the path), and a directory that cannot be created or locked fails it with `STORAGE`.
- **Atomic write.** A snapshot is encrypted, written to `<name>.tmp`, forced to disk, and moved over the store in one step, falling back to a plain replace where the file system has no atomic move. Writers are serialized, and each snapshot carries its order, so a late writer cannot put an older state over a newer one. On POSIX file systems the file is owner-only.
- **Rolling backup.** The file a write replaces is kept as `<name>.bak`, when that file was known to be good.
- **Unreadable files.** "Cannot read" and "nothing stored" are different states. A failed load of a file that exists, whatever the reason (the wrong key, an unavailable key, a damaged file, a read error), leaves the in-memory collection alone, records why on `loadError()` as an `AltsFailure` of kind `STORAGE` (the file name and a fixed phrase, no path), and copies the file to `<name>.unreadable.<time>`; a file whose exact bytes are already kept is not copied again, and the newest five copies are kept. A file unread only because the key was unavailable is copied when it is discarded instead.
- **Write refusal.** After such a load every write is refused and reported on `saveError()`: the file on disk is intact and merely unread, and writing what is in memory would replace it. The refusal lifts when a later `load()` succeeds, when the file is gone, or when the host calls `discardUnreadable()`, which copies the file aside, lifts the refusal and writes what memory holds at once. That is the explicit route for a renamed OS user, a moved home directory or a rotated key.
- **Key provider.** With a provider installed, a file opens under the host's key or is unreadable. A provider that throws, or returns too little, fails closed: nothing falls back to the machine-derived key. The provider belongs to the runtime it was given to.
- **Migration.** With `migrateFromMachineKey(true)`, a file that opens only under the machine-derived key is loaded and rewritten under the host's key, and the rolling backup and every unreadable copy are resealed or removed before the new file is moved into place. It is meant for the one launch that adopts a provider.
- **Write delay and flush.** A runtime's stores write 100 ms after a mutation: mutations within the window are covered by one write on the writer thread. `save()` and `flush()` write at once and return when the snapshot is on disk; a shutdown hook flushes on a normal exit, and `close()` flushes. A write that fails is reported on `saveError()` and retried by the next mutation, `save()` or `flush()`. After `close()` a mutator changes memory only and records "the store is closed".
- **Load warnings.** A stored entry with no UUID, or a duplicate, is skipped and noted on `AccountStore.loadWarning()`; the rest of the store loads.

## Transport

Every HTTP request goes through the runtime's `internal.net.HttpTransport`, which is what makes the rules enforceable in one place. The runtime builds one and hands it to every service through its constructor; two runtimes have two transports and share no route, tunnel or thread.

- **Timeouts** are ten seconds to connect and thirty to read.
- **Routing.** Each request resolves a `ProxyRoute` from its `NetworkScope` (the purpose, the account when there is one, and the route tag of a routed view) through the runtime's `ProxyProvider`, fixed at `build()`. Resolution fails closed: a provider that throws or returns `null` fails the request. Without a provider every request is direct. A direct route opens without naming a proxy, so the JVM's own proxy configuration still applies to it.
- **Route tags.** `AltLoginService.routed(tag)` and `BulkOptions.withRouteTag(tag)` give a view of the transport whose every request carries the tag in its scope, on every hop of every route, so a provider can pin a new account's first sign-in to its proxy before any UUID exists. The view shares the provider, the executor, the tunnels and being closed.
- **Proxy tunnel.** An HTTPS target behind an HTTP proxy is tunnelled by `ProxyTunnelSocketFactory`, not by the JDK, because the JDK cannot authenticate a `CONNECT` per request without process-global state. The factory connects to the proxy, sends `CONNECT` with the credential, requires a `2xx` within one deadline, and only then lets the JVM's own factory layer TLS with endpoint identification on. One factory serves one proxy identity (host, port, credential) within one transport, and the JDK pools kept-alive connections per factory, so identities never share a tunnel; the factory cache holds 64 identities. The JVM still resolves the origin host name locally before the tunnel is opened; the answer is unused. A plain `http` target through an authenticated proxy carries the credential as a header and is not kept alive. SOCKS5 routes go through the JDK and cannot carry credentials.
- **Redirects.** The JDK's redirect following is always off. Only the binary fetch follows redirects, by hand: never with an `Authorization` header, dropping credential headers when a hop leaves the origin, refusing `https` to `http`, at most five hops, with an optional per-hop predicate. The cookie route follows its own chain a step at a time.
- **Body cap.** A JSON or text body is read up to 1 MiB; a longer one fails the request. The binary fetch takes its cap from the caller, and the vault's exchanges use 16 MiB.
- **Headers.** A header name or value holding a control character is refused before the JDK sees it, and so is a caller-supplied `Proxy-Authorization` in any capitalisation: the proxy credential is placed only by the route. Both refusals quote nothing.
- **Rate-limit signalling.** The status-carrying calls return the status with the body; `429` is a rate limit, and `Retry-After` is read as seconds or as an HTTP-date measured against the response's own `Date`, absent when the service named no wait.
- **Closing.** `close()` closes the tunnels the transport opened and refuses every request made from then on; a request already past its route resolution may still complete or fail on its own. Every wait registered on the transport is ended (see [Threading](#threading)). Connections the JDK pools itself (direct, unauthenticated SOCKS, unauthenticated plain-HTTP proxy) are process-wide in the JDK and keyed by target and proxy, so nothing leaks between routes, but `close()` cannot close them.
- **No global state.** No system property, default authenticator, default `SSLContext` or proxy selector is installed.

## Error model

One value describes a failure everywhere: `AltsFailure(kind, message, retryAfter, xstsError, retryAt)`, with `AltsFailure.Kind` one enum for the whole library (`NETWORK`, `RATE_LIMITED`, `UNAUTHORIZED`, `REAUTH_REQUIRED`, `NOT_ENTITLED`, `NOT_FOUND`, `XBOX_DENIED`, `DECLINED`, `TIMED_OUT`, `CANCELLED`, `INVALID_INPUT`, `CONFLICT`, `NOT_CONFIGURED`, `STORAGE`, `CRYPTO`, `PROTOCOL`, `UNKNOWN`). It ends in `UNKNOWN` so a host's `default` branch covers a constant a later release adds. One unchecked exception carries it, `AltsException`, with `failure()` and `kind()`.

Three rules decide where a failure appears:

1. **An outcome the caller is expected to branch on is a result.** `LoginResult` (sign-in), `AccountStatus` (check and refresh; its `State` is the account's state, mapped from the kind by an exhaustive switch: `RATE_LIMITED` and `NETWORK` are `UNREACHABLE`, `XBOX_DENIED` is `NOT_ENTITLED`), `NameChangeResult` and `ProfileCreationResult` (their outcome constants stay, and every failure folds into `FAILED`), `ClaimResult` (a `TERMINAL_FAILURE` carries the failure), and `BulkEntryResult`. Each carries `Optional<AltsFailure> failure()`. These routes never throw at the caller and never complete exceptionally, even on a closed runtime.
2. **Everything else is an `AltsException`.** The account services, the profile lookup, `CookieFile.read`, the vault and `build()` throw it, and a library future completes exceptionally only with it (inside a `CompletionException`), never with a transport exception or a checked one.
3. The stores throw nothing for I/O; they report on `loadError()`, `loadWarning()` and `saveError()`, each an `Optional<AltsFailure>` of kind `STORAGE`.

`retryable()` is true for `NETWORK`, and for `NETWORK` or `RATE_LIMITED` once a stated wait (`retryAt`) has passed; a `RATE_LIMITED` with no stated wait is not retryable, because retrying into an unknown limit is how a short limit becomes a long one.

Messages are for people and are not a contract. A message never repeats a transport exception's own text (`internal.net.FailureText` maps a failure to a fixed phrase for its kind, and the original stays reachable as the cause), never carries a token, a cookie, a code or a path, and never repeats what a service or the host's session injector said. `ErrorKindMigrationTableTest` pins every 0.12 constant's kind against the CHANGELOG's table, and per-service loopback tests drive each failing response to its kind.

## Bulk runs

`bulk/` runs one operation per entry with a concurrency bound, a minimum spacing between starts, a retry budget and per-entry progress. `BulkOptions.defaults()` is four at a time, a quarter second apart, two retries growing from two seconds, stopping on a rate limit.

- Only `NETWORK` failures are retried, on an exponential, jittered backoff. A refused or spent credential is never retried.
- A rate limit is recognised by its kind, with or without a stated wait. With `stopOnRateLimit` (the default) it ends the run: nothing further starts, and the report says `stoppedEarly()`. Without it, the whole run is held back for the stated wait, or a growing one when none was stated, and the entry then tries again within its retry budget. It is never retried at once.
- Spacing is global, not per proxy route.
- Cancelling stops new entries from starting; entries in flight finish and appear in the report.
- The report holds every entry. A run cut short by `close()` or a refusing executor reports each entry it did not finish as `CANCELLED`. A `BulkProgress.started` that throws fails that entry with `UNKNOWN`, unattempted; a `completed` or `finished` that throws a `RuntimeException` is ignored; an `Error` from a callback cuts the run short, the remaining entries reported as `CANCELLED`. The report completes after `finished` has returned.
- `entitlementsAll` reads each account with the token it currently holds and does not renew it.
- Labels are a resolved username or a position, never the input line.

## Shared vault

The vault speaks [AVP 0.5](https://github.com/trqlmao/avp) (a draft specification) as a client only. The constructions are in `internal.avp`, the client engine in `internal.vault`, and the public types in `vault/` are thin handles over them.

- **Structures.** A repository is an owner-signed **manifest chain**: each state is the canonical encoding of the repository id, its sequence number, the previous state's hash, the owner key, the genesis nonce, the wrap scheme, the key epoch, the refresh-token policy, the hosts, the members (each with its keys, its wrapped data key and its home host) and the cumulative removals, signed by the owner. The payload travels as a **commit graph** of member-signed commits: a commit id is the hash of a header naming the repository, the parents, the state it was written under, the epoch, the author, the IV and the ciphertext, and the payload's AAD binds the repository, epoch, author and parents. The payload is per-account and per-field, each field stamped by a hybrid logical clock, so concurrent heads merge rather than overwrite.
- **Identities.** The owner is an `OwnerIdentity`, whose Ed25519 and X25519 keys come from a 24-word BIP39 phrase; the repository id derives from the owner key and a genesis nonce, so the owner key is fixed for the repository's life. A member is a `VaultIdentity` (an Ed25519 member key and an X25519 key), stored as a passphrase-wrapped `WrappedIdentity` with an optional `RecoveryCode`. A second owner device joins through `LinkSession`, after a confirmation code is compared on both devices.
- **Hosts.** `alts.vault()` is the runtime's `VaultHosts`: it reaches a host on the runtime's transport (purpose `VAULT`, a 16 MiB body cap), at `https://<locator>` unless `Builder#vaultHostAddress` maps it, and matches it by its key: `connect` passes the key a token, a `HostRef` or a snapshot names and refuses another with `PROTOCOL`; `connectFirstContact` takes the key discovery names. Bearer tokens are cached per runtime, keyed by host key and origin, so one host is never handed another's token; `close()` drops them. A host only ever receives what the protocol sends: public keys, signatures, ciphertext and counters.
- **Verification.** The engine verifies every state from genesis (owner signature, chain link, repository id, content rules) and every commit (id, author signature, membership at the cited state and epoch, the removal cutoff) itself, with strict Ed25519 (small-order and non-canonical points and an out-of-range `S` rejected before a cofactorless check). It never trusts a host's acceptance.
- **Pin and tie rule.** The client pins the sequence number and hash of the highest verified state and refuses a chain that does not contain the pin, except one that diverges at or below it and wins the tie rule (the bytewise-lower state hash at the fork), which only two offline owner devices can produce; `SyncReport.divergedAt()` surfaces it. Conflicts get one re-pull and one retry, never a loop.
- **Failing closed.** A state that fails a check, or a chain that drops the pin without winning the tie rule, fails the whole operation with `PROTOCOL`, and the device's copy stays as it was. The reference client instead keeps the valid prefix of what a host served; this library chose availability loss over letting a lying host pick the point a device advances to. A head the client cannot read is left alone and counted, not fatal.
- **Writes.** The owner wraps the data key only to keys taken from an invite token, never to keys a host serves, after verifying the acceptance the joiner's home host signed into it; members cannot invite. Removing a member rotates the key to a new epoch with a signed removal cutoff. `update(uuid, edit)` stamps only the fields the edit changed, so a remote edit of another field is never reverted. Every vault future fails only with an `AltsException`.
- **Refresh-token policy.** `shareRefreshTokens` is inside the owner-signed state, so a host cannot flip it. The policy counts as on only when the latest verified state says so; otherwise the engine strips `refreshToken` and `expiresAt`, with their stamps, from every payload it encrypts, decrypts or merges. `SyncReport.policyTurnedOn()` surfaces a change to sharing.
- **State the host keeps.** `VaultSnapshot` (the chain hashes and pin, the retained epoch keys, the clock, the merged payload, the member id and the home host) and the owner's entropy are secrets the host persists encrypted, recommended in `HostSecrets`. The snapshot names its member and does not hold the identity.
- **The 0.4 importer.** `LegacyVaultReader` (over `internal.vault.legacy`) reads one 0.4 manifest and envelope with a member's identity and returns the accounts. It makes the checks a 0.12 member made, has no rollback floor, never writes and never talks to a host.

The constructions are gated byte for byte by the AVP 0.5 vectors vendored under `src/test/resources/avp-vectors/`, the must-reject bank included; the 0.4 vectors the importer and the identity rest on are kept beside them. [SECURITY.md](../SECURITY.md) states what the protocol resists and what it does not.

## Design rules

- No Minecraft, renderer or consumer imports anywhere in the library; only the JDK and Gson.
- DTOs are records with `@SerializedName` on every component, so serialization survives obfuscation.
  The value types expected to grow (`AltAccount`, `MicrosoftAuthConfig`, `BulkOptions`, `NetworkScope`,
  `ClaimOptions`, `AltsFailure`, `BulkEntryResult`) are final classes with factories instead, because a
  record cannot gain a component within a major version; `AltAccount` carries `@SerializedName` on its
  fields, whose names and order are the store file's format.
- Optional capabilities (avatars, game stats) degrade to `null` when their seam is absent.
- The runtime owns its state; nothing is reached through a static.
- Every request goes through the runtime's transport, and every blocking task and wait through its executor.
- Resolution of a host-supplied proxy or store key fails closed.
- Implementation lives under `internal`, which is never exported, and the exported API changes only as the dump allows.

# Architecture

**lol.trq.alts** is an account library for Minecraft: Java Edition, usable from a launcher, a tool, the host application of a bot, or an account manager. It is consumer-agnostic and holds no Minecraft or renderer types; everything platform-specific crosses a seam the host implements.

## Layers

```
            ┌──────────────────────────────────────────────────────────────┐
  host      │  seam implementations (SessionInjector, ProxyProvider, ...)   │
            └───────────────▲──────────────────────────────────────────────┘
                            │ spi/ interfaces
            ┌───────────────┴──────────────────────────────────────────────┐
            │  AltsRuntime: wiring root + Builder                           │
            ├───────────────────────────────────────────────────────────────┤
  library   │ spi/      the host seams: session, directory, main thread, toasts,
            │           textures, avatars, stats, proxy, store key, device-code prompt
            │ auth/     sign-in routes, check/refresh, MicrosoftAuthConfig, cookies
            │ account/  services over a token: profile, entitlements, name, skin, cape,
            │           attributes, certificates, blocklist; public profile lookup
            │ bulk/     one operation over many accounts: pacing, retries, progress
            │ store/    AltStore + SecretStore over one encrypted-file writer
            │ net/      HttpUtil (the one way out), proxy tunnel, IoExecutor, FailureText
            │ time/     TimeSource, SystemTimeSource, NtpTimeSource
            │ cache/    AsyncCache<K,V>
            │ skin/     SkinAvatarCache<H>, MojangAvatarSource, UrlTemplateAvatarSource
            │ model/    AltAccount, SessionData, GameStats, BanInfo, enums
            │ format/   text helpers for account UIs
            │ crypto/   VaultIdentity, PayloadCipher, KeyWrapScheme, ...
            │ vault/    SharedVault, RepoPin + transport/ DTOs + federation/ addressing
            └───────────────────────────────────────────────────────────────┘
```

## Key pieces

- **`AltsRuntime<H>`** is the single wiring root. Its builder takes the seam implementations and validates the required ones (`SessionInjector`, `VaultDirectoryProvider`, `MainThreadExecutor`, `ToastSink`). `build()` binds the proxy provider and the executor, binds both stores to the directory and the store key in one step, turns on coalesced writes, loads whatever the stores hold on disk, and constructs the services and caches. `H` is the host's texture-handle type, threaded through `SkinAvatarCache<H>` so the cache is type-safe without the library knowing what a texture is. The proxy provider, the executor, the stores and the store key are process-wide statics behind the runtime: a second runtime shares them, and leaving one unset on a later builder never removes what an earlier one installed.

- **`spi/`** is the entire host boundary. The library calls these interfaces and never imports a host class. Required: `SessionInjector`, `VaultDirectoryProvider`, `MainThreadExecutor`, `ToastSink`. Optional: `TextureUploader<H>`, `AvatarSource`, `GameStatsSource`, `ProxyProvider`, `StoreKeyProvider`, `VaultTransportResolver`, and `DeviceCodePrompt`, which is passed per login rather than to the builder.

- **`auth/`**. `AltLoginService` exposes eight `CompletableFuture`-based methods: seven sign-in routes (Microsoft browser, Microsoft device code, refresh token, cookie text, cookie file, session token, offline) plus `loginAccount`, which logs into a record the caller already holds. Each resolves off the caller's thread and hands the identity to the host's `SessionInjector` as a transport-neutral `SessionData`. The browser route is the authorization-code flow with PKCE and a loopback callback server that only a request carrying the login's `state` can complete. The device-code route polls the token endpoint at the advertised interval until approval, refusal or expiry. `loginAccount` renews an expired session from the account's stored refresh token, proactively when `TokenExpiry` says the access token is spent and once reactively when the services refuse it, persisting the rotated credential before installing the session.

  `AltAccountService` is the same machinery with the injection removed: `check` asks whether a stored token still works and changes nothing, `refresh` renews it and persists the rotation, and neither installs a session. The split exists because a sweep over every stored account cannot be a loop over `loginAccount`, which switches session once per account, and because rotation is not free: the token endpoint issues a new refresh token on every redemption.

  `MicrosoftAuthConfig` carries the dialect as well as the endpoints. An Azure OAuth application and a legacy MSA one differ in the redirect the grant must declare, the scope it asks for, and the RPS ticket prefix Xbox Live wants, so `legacyMsa(clientId)` exists alongside `of(clientId)`. The config also carries the device-code endpoints and the Minecraft services URLs the cookie route and the account services use.

- **`account/`** is the surface over a live access token, built by `AccountServices.of(...)` or `alts.accountServices(account)`: `profile()` (read, read-if-present, create), `entitlements()`, `name()` (availability, eligibility, change, scheduled claim), `skin()`, `cape()`, `attributes()` (privileges, preferences, platform ban status), `certificates()` (the chat-signing key pair) and `blocklist()`. None of them installs a session or touches the store. `ProfileLookupService`, reached as `alts.profileLookup()`, is the anonymous counterpart: name or UUID to public identity, with no token. The `*Impl` classes are package-private.

- **`bulk/`** runs `checkAll`, `refreshAll`, `entitlementsAll` and `importCredentials` over a list. See [Bulk runs](#bulk-runs).

- **`store/`**, **`net/`**: see [Store persistence](#store-persistence) and [Transport](#transport).

- **`time/`**. `TimeSource` is the clock the scheduled name claim reads. `NtpTimeSource.now()` is arithmetic over the last measured offset and never touches the network; measurement runs in the background, and `sync()` is the blocking form. It is the library's only non-HTTP network use: one UDP datagram, sent directly, not through the `ProxyProvider`.

- **`cache/AsyncCache<K,V>`** is the async-lookup primitive. `get(key)` never blocks: it returns the cached value or `null` and starts a background fetch on a miss. A positive TTL makes it stale-while-revalidate. A failed first fetch is retried after a backoff that grows from five seconds to five minutes; a failed refresh keeps the stale value. The cache is bounded (4096 entries by default), dropping the entries read longest ago. The per-server game-stats caches are built on it.

- **`skin/SkinAvatarCache<H>`** is keyed by UUID. The default `MojangAvatarSource` resolves the skin from Mojang's session server, requires the texture address to name the Mojang texture host, fetches it over HTTPS with redirects held to that host, checks the declared image dimensions before decoding, and crops the face locally. At most six downloads are in flight; the rest queue. A failed fetch retries on a growing backoff.

- **`crypto/` + `vault/`**: see [Shared vault](#shared-vault).

## Threading

- **The library executor.** Every blocking call, and everything that waits on one, runs on `IoExecutor.executor()`: one virtual thread per task by default, or the executor the host passed to `Builder.executor(...)`. Nothing runs on `ForkJoinPool.commonPool()`. Continuations a host attaches to a returned future without naming an executor run there too, as do `AsyncCache` loaders, `GameStatsSource.fetch`, `AvatarSource`, and `DeviceCodePrompt.show`.
- **The session injector is called off the main thread.** A `SessionInjector` that touches main-thread state marshals onto it itself. The library uses the `MainThreadExecutor` for texture uploads.
- **The store writer.** Coalesced store writes run on a single daemon thread, `alts-store-writer`, separate from the library executor so that a slow disk does not hold a request thread and a busy executor does not delay a write. A shutdown hook flushes whatever is still pending.
- **Avatar fetches** are bounded to six in flight. The bound is a queue, not blocked threads.
- **Bulk runs** create no executor. The concurrency bound is structural: that many worker chains each pull the next entry off a shared cursor.
- **Store state.** `AltStore`'s account list is copy-on-write and `SecretStore`'s map is concurrent, because a login resolving on an executor thread mutates them while the host reads them from its own thread. `accounts()` is a live list, and iterating it during a login sees a snapshot. Mutators are atomic with respect to each other and to a save.

## Store persistence

`AltStore` (accounts) and `SecretStore` (per-user secrets that must never enter a shared repository) are static facades over one package-private writer, `StoreFile`, each with its own file.

- **Format and key.** AES-256-GCM under a PBKDF2-derived key. Without a `StoreKeyProvider` the PBKDF2 password is derived from machine properties and a host-configurable key-binding constant, which is obfuscation (see [SECURITY.md](../SECURITY.md)). With one, the password is the host's key material bound to the same constant. The key is derived once per process and reused with a fresh nonce per write.
- **Atomic write.** A snapshot is encrypted, written to `<name>.tmp`, forced to disk, and moved over the store in one step, falling back to a plain replace where the file system has no atomic move. Writers are serialized, and each snapshot carries its order, so a late writer cannot put an older state over a newer one. On POSIX file systems the file is owner-only.
- **Rolling backup.** The file a write replaces is kept as `<name>.bak`, when that file was known to be good.
- **Unreadable files.** "Cannot read" and "nothing stored" are different states. A failed load leaves the in-memory collection alone and records why on `loadError()`, as the file name and a fixed phrase with no path. Before any write replaces such a file it is copied to `<name>.unreadable.<time>`; a file whose exact bytes are already kept is not copied again, and the newest five copies are kept. A write that cannot make the copy does not happen.
- **Key provider.** With a provider installed, a file opens under the host's key or is unreadable. A provider that throws, or returns too little, fails closed: nothing falls back to the machine-derived key.
- **Write refusal.** While the last load failed because the store key was unavailable, every write is refused and reported on `saveError()`, even once the provider answers again. The file on disk is intact and merely unread, and writing what is in memory would replace it. A later `load()` that succeeds lifts the refusal.
- **Migration.** With `migrateFromMachineKey(true)`, a file that opens only under the machine-derived key is loaded and rewritten under the host's key, and the rolling backup and every unreadable copy are resealed or removed before the new file is moved into place. It is meant for the one launch that adopts a provider.
- **Write delay and flush.** A store bound directly writes synchronously inside the mutator. A runtime built through the builder sets a write delay of 100 ms (`AltStore.DEFAULT_WRITE_DELAY`): mutations within the window are covered by one write on the writer thread. `save()` and `flush()` write at once and return when the snapshot is on disk; a shutdown hook flushes on a normal exit. A write that fails is reported on `saveError()` and retried by the next mutation, `save()` or `flush()`.
- **Load warnings.** A stored entry with no UUID, or a duplicate, is skipped and noted on `AltStore.loadWarning()`; the rest of the store loads.

## Transport

Every HTTP request goes through `net/HttpUtil`, which is what makes the rules enforceable in one place.

- **Timeouts** are ten seconds to connect and thirty to read.
- **Routing.** Each request resolves a `ProxyRoute` from its `NetworkScope` (the purpose, and the account when there is one) through the host's `ProxyProvider`. Resolution fails closed: a provider that throws or returns `null` fails the request. A direct route opens without naming a proxy, so the JVM's own proxy configuration still applies to it.
- **Proxy tunnel.** An HTTPS target behind an HTTP proxy is tunnelled by `ProxyTunnelSocketFactory`, not by the JDK, because the JDK cannot authenticate a `CONNECT` per request without process-global state. The factory connects to the proxy, sends `CONNECT` with the credential, requires a `2xx` within one deadline, and only then lets the JVM's own factory layer TLS with endpoint identification on. One factory serves one proxy identity (host, port, credential) and the JDK pools kept-alive connections per factory, so identities never share a tunnel; the factory cache holds 64 identities. The JVM still resolves the origin host name locally before the tunnel is opened; the answer is unused. A plain `http` target through an authenticated proxy carries the credential as a header and is not kept alive. SOCKS5 routes go through the JDK and cannot carry credentials.
- **Redirects.** The JDK's redirect following is always off. Only the binary fetch follows redirects, by hand: never with an `Authorization` header, dropping credential headers when a hop leaves the origin, refusing `https` to `http`, at most five hops, with an optional per-hop predicate. The cookie route follows its own chain a step at a time with `getHeader`.
- **Body cap.** A JSON or text body is read up to 1 MiB; a longer one fails the request. The binary fetch takes its cap from the caller.
- **Headers.** A header name or value holding a control character is refused before the JDK sees it.
- **Rate-limit signalling.** The status-carrying calls (`postFormForStatus`, `postJsonForStatus`, `postJsonForElement`, `getForStatus`, `sendForStatus`, `getBytesForStatus`, `getHeader`) return the status with the body, and `rateLimited()` is true for any `429`. `retryAfter` is the `Retry-After` header read as seconds or as an HTTP-date measured against the response's own `Date`; it is `null` when the service named no wait.
- **No global state.** No system property, default authenticator, default `SSLContext` or proxy selector is installed.

## Error model

There is not one error model yet; there are four, by layer. Unifying them is part of the 1.0 work.

- **Sign-in: `LoginResult` and `FailureReason`.** Login futures do not complete exceptionally for an expected failure; they complete with a `LoginResult` whose `reason()` is one of `NONE`, `UNKNOWN`, `REAUTH_REQUIRED`, `INVALID_TOKEN`, `NETWORK`, `NOT_CONFIGURED`, `NOT_ENTITLED`, `RATE_LIMITED`, `XBOX_DENIED`, `DECLINED`, `TIMED_OUT`. `xstsError()` carries the decoded Xbox Live refusal for `XBOX_DENIED`, and `retryAfter()` the stated wait for `RATE_LIMITED`, when one was stated.
- **Check and refresh: `AccountStatus`.** `state()` is `VALID`, `RENEWED`, `EXPIRED` (spent but holding a refresh token; only `check` reports it), `REAUTH_REQUIRED`, `NOT_ENTITLED` (no Minecraft profile, or Xbox Live refused the account), `UNREACHABLE` (an outage or a rate limit; `rateLimited()` tells them apart) or `UNKNOWN`. The status also carries the `FailureReason`, a message, and `retryAfter`.
- **Account services: `AccountException`.** A read throws this checked exception, which carries the HTTP status, `tokenRefused()`, `rateLimited()`, `notFound()` and `retryAfter()`. `SkinValidationException` extends it for an upload refused locally. A mutation whose refusal is an ordinary outcome returns a classified result and does not throw: `NameChangeResult`, `ProfileCreationResult`, `ClaimResult`.
- **Vault: `CryptoException` and `VaultException`**, both checked. Malformed input from a server or another member, a refused key binding, a manifest below the pin, and a scheme or epoch mismatch are `VaultException`.
- **Stores** throw nothing for I/O; they report on `loadError()`, `loadWarning()` and `saveError()`.

Messages are for people and are not a contract. A message that can reach a host never repeats a transport exception's own text: `net/FailureText` maps a failure to a fixed phrase for its kind, and the original stays reachable as the cause.

## Bulk runs

`bulk/` runs one operation per entry with a concurrency bound, a minimum spacing between starts, a retry budget and per-entry progress. `BulkOptions.defaults()` is four at a time, a quarter second apart, two retries growing from two seconds, stopping on a rate limit.

- Only `NETWORK` failures are retried, on an exponential, jittered backoff. A refused or spent credential is never retried.
- A rate limit is recognised by its reason, with or without a stated wait. With `stopOnRateLimit` (the default) it ends the run: nothing further starts, and the report says `stoppedEarly()`. Without it, the whole run is held back for the stated wait, or a growing one when none was stated, and the entry then tries again within its retry budget. It is never retried at once.
- Spacing is global, not per proxy route.
- Cancelling stops new entries from starting; entries in flight finish and appear in the report.
- `entitlementsAll` reads each account with the token it currently holds and does not renew it.
- Labels are a resolved username or a position, never the input line.

## Shared vault

A member is an Ed25519 identity (the stable id) paired with an X25519 key. `SharedVault` does client-side crypto over plain DTOs and never touches the network: it generates a per-repository data key, wraps it to each member's X25519 key (`KeyWrapScheme`), and encrypts the account payload under AES-256-GCM with the repository id, version and key epoch bound into the AAD, so stale or spliced ciphertext fails to authenticate.

- **Verification before wrap.** `SharedVault` takes a `KeyBindingVerifier` at construction and runs it before wrapping the data key to any other member, in `addMember`, `rotateKey` and `removeMember`; it wraps only to the keys the verifier returned. `IssuerSignedKeyBindingVerifier` requires an identity-provider signature over the keys. `KeyBindingVerifier.trustTransport()` skips the check and has to be chosen on purpose.
- **Pins.** `RepoPin` is a host-persisted floor on key epoch and payload version. `openRepo(manifest, identity, pin)` refuses a manifest below it, and `RepoContext.pin()` returns the value to persist after the context advances. Without a pin the client trusts the server's counters.
- **Consistency checks.** `openRepo` refuses a manifest whose scheme id is not the configured scheme or whose member entry names a different key epoch; `decryptPayload` refuses an envelope from another epoch. A stored identity's public keys are checked against its private material on unlock.
- **Refresh-token policy.** The manifest's `shareRefreshTokens` flag gates whether refresh tokens travel through the repository. It defaults to withholding, and the strip runs on both write and read, so the policy binds members. It does not bind the server: the flag is unsigned manifest metadata.
- **What is not covered.** Nothing signs a wrapped key, a manifest or an envelope, so an actively malicious server can substitute a data key on join or flip the sharing flag. [SECURITY.md](../SECURITY.md) states this in full. Signed wraps and manifests need a protocol revision.

`vault/transport/` is the network boundary as plain DTOs and a `VaultTransport` interface. The library names no server or wire protocol; a host plugs in its own transport or a test double.

## Federation

Shared repositories are federated by portable identity and addressing, not server-to-server replication. A repository is addressed `avp://host/repoId` (`vault/federation/RepoAddress`); the host must be a DNS name, an IPv4 address or a bracketed IPv6 literal with an optional port, and the repository id a single path segment. Because identity is a server-agnostic key pair, the same member authenticates against any conformant server. To join a repository hosted elsewhere, a member resolves a transport for that repository's host through the `VaultTransportResolver` seam and authenticates there with its own identity. The join handshake is two tokens: an `InviteRequest` (the joiner's public keys) and a `RepoLocator` (where the repository lives plus the issuer to trust). Server-to-server replication is out of scope.

## Design rules

- No Minecraft, renderer or consumer imports anywhere in the library; only the JDK and Gson.
- DTOs are records with `@SerializedName` on every component, so serialization survives obfuscation.
- Optional capabilities (avatars, game stats) degrade to `null` when their seam is absent.
- Every request goes through `HttpUtil`, and every blocking task through `IoExecutor`.
- Resolution of a host-supplied proxy or store key fails closed, and is never undone by a later `null`.

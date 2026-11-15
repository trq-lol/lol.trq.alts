# CLAUDE.md

Guidance for AI coding agents working **on** this library or **with** it from a host.

**lol.trq.alts** is a general account library for Minecraft: Java Edition: sign-in, account management
over a token, bulk operations, an encrypted local store and a shared vault. Hosts are launchers, tools,
the host applications of bots, and account managers alike. It is consumed as a JitPack dependency
(`com.github.trq-lol:lol.trq.alts`) or a git submodule, and it must never depend on or reference any
specific consumer. Pure JDK plus Gson: no Minecraft types, no renderer types, no host imports. Package
and class names (`alts`, `AltAccount`, `VaultDirectoryProvider`) are historical and stay.

## 30-second mental model

One wiring root that owns everything it builds, a handful of host seams, the rest internal.

```java
try (AltsRuntime<H> alts = new AltsRuntime.Builder<H>()
        .sessionInjector(session -> ...)   // REQUIRED: make a SessionData the live session
        .vaultDirectory(() -> dataDir)     // REQUIRED: where the two encrypted store files live
        .mainThread(host::execute)         // REQUIRED: run a task on the host's main thread
        .toastSink(...)                    // REQUIRED: surface a notification
        .textureUploader(...)              // optional: PNG bytes -> your handle type H
        .avatarSource(...)                 // optional: defaults to Mojang, cropped locally
        .avatarUrlTemplate(...)            // optional: or a head-render service (discloses UUIDs)
        .gameStatsSource(...)              // optional: one per server
        .microsoftAuth(MicrosoftAuthConfig.of(yourAzureClientId))  // optional
        .accountEndpoints(...)             // optional: another base for the account services
        .vaultHostAddress(...)             // optional: vault host locator -> base URL (https/http or grpcs/grpc)
        .vaultRpcChannel(uri -> channel)   // optional: the host's gRPC channel for a grpcs/grpc vault address
        .proxyProvider(scope -> ...)       // optional: route each request; absent means direct
        .executor(hostExecutor)            // optional: where blocking work runs; default virtual threads
        .storeKeyProvider(() -> keyBytes)  // optional: real key material for the stores
        .migrateFromMachineKey(upgrade)    // optional: true on the ONE launch that adopts the key
        .build()) {  // validates, opens and locks this runtime's stores, loads them from disk

    alts.store();                  // AccountStore: the saved accounts and the current one
    alts.secrets();                // HostSecrets: per-user secrets, kept apart from the accounts
    alts.loginService();           // the entire sign-in surface
    alts.accountService();         // check / refresh, without touching the live session
    alts.bulk();                   // the same, over many accounts, paced
    alts.accountServices(account); // profile / entitlements / name / skin / cape / attributes / ... over the token
    alts.profileLookup();          // name or UUID -> public identity, no token
    alts.skinCache();              // UUID -> H
    alts.gameStats("example.net"); // AsyncCache<uuid, GameStats>, one per registered source
    alts.vault();                  // VaultHosts: connect to AVP 0.5 hosts, then open a SharedVault
    alts.toasts();                 // the host's ToastSink, the one route for a notification
}   // close(): flush and unlock the stores, close the transport, shut a library-made executor
```

`H` is the host's opaque texture-handle type. The library never inspects it; it only hands it back.

Nothing is process-wide. Each runtime builds and owns its `AccountStore`, its `HostSecrets`, its
transport (proxy provider, tunnel connections, timeouts) and its executor, and hands them to every
service through constructors. Two runtimes in one JVM, on two directories, share nothing; two on one
directory cannot both build, because each store file is locked for its runtime's life.

Package map (the exported packages are exactly what `module-info.java` exports and what
`api/lol.trq.alts.api` lists):

| Package | What lives there |
|---|---|
| `lol.trq.alts` | `AltsRuntime` and its `Builder`; the error model, `AltsFailure` (with `Kind`) and `AltsException` |
| `spi/` | the host seams, which are the entire boundary: `SessionInjector`, `VaultDirectoryProvider`, `MainThreadExecutor`, `ToastSink`, `TextureUploader`, `AvatarSource`, `GameStatsSource` (+ `StaticGameStatsSource`), `ProxyProvider`, `StoreKeyProvider`, `DeviceCodePrompt`, `VaultRpcChannel` |
| `auth/` | `AltLoginService`, `AltAccountService`, `LoginResult`, `AccountStatus`, `MicrosoftAuthConfig`, `CookieFile`, `XstsError` |
| `account/` | the surface over a token: profile (read, create), entitlements, name (+claim), skin (+`SkinProblem`), cape, attributes, certificates, blocklist, `AccountEndpoints`; plus the anonymous `ProfileLookupService` |
| `bulk/` | one operation over many accounts: `BulkOperations`, `BulkHandle`, `BulkOptions`, `BulkProgress`, `BulkReport`, `BulkEntryResult`, `CredentialKind` |
| `net/` | the value types a `ProxyProvider` sees: `NetworkScope` (purpose, account, route tag) and `ProxyRoute` |
| `store/` | `AccountStore` and `HostSecrets`, reached only as `alts.store()` / `alts.secrets()` |
| `time/` | `TimeSource` seam + `SystemTimeSource` / `NtpTimeSource`, for the scheduled name claim |
| `cache/` | `AsyncCache<K,V>`: lazy, non-blocking, stale-while-revalidate, bounded |
| `skin/` | `SkinAvatarCache<H>` (UUID-keyed), reached only as `alts.skinCache()` |
| `model/` | the stored account, `AltAccount` (a final class with a builder), and the records `SessionData`, `GameStats`, `BanInfo`; enums |
| `vault/` | the AVP 0.5 client API (`VaultHosts`, `VaultHost`, `SharedVault`, `SyncReport`, `VaultSnapshot`, `OwnerIdentity`, `LinkSession`, `VaultIdentity` and its stored forms, the tokens) and the read-only `LegacyVaultReader` |
| `internal/` | everything else: `internal.net` (`HttpTransport`, the tunnel, `FailureText`, ...), `internal.auth` (the sign-in chain), `internal.account`, `internal.bulk`, `internal.store` (`StoreFile`, `EncryptionUtil`), `internal.skin`, `internal.crypto` (the primitives), `internal.avp` (the AVP 0.5 constructions), `internal.vault` (the client engine; `legacy` is the 0.4 importer). Not exported, not documented, not covered by the API gate |

## Hard rules

- **No consumer references.** Never name, import, or describe any specific application, client,
  launcher, product, sync server, or hosted instance that consumes this, and never name or link another
  authentication library, launcher or tool. Keep examples generic (`your application`, `the host`,
  `example.net`, `vault.example`). This covers source, comments, Javadoc, docs, commit messages, tests,
  and the README. `AltAccount.sourceClient`/`sourceUser` and `avp://` locators define field *names*
  only; the values are host-supplied at runtime. CI enforces this (`.github/workflows/no-leak.yml`,
  against a denylist held as a repository secret).
- **Host-agnostic boundary.** Seam interfaces live in `spi/`; hosts implement them. Never reach into a
  host type. No `import` outside `lol.trq.alts`, the JDK, and Gson.
- **Never export `internal`.** Implementation goes under `lol.trq.alts.internal.<pkg>`, which
  `module-info.java` does not export and the published Javadoc leaves out (`javadocCheck` fails the
  build if it shows up). No exported signature may name an internal type: `apiCheck` fails outright.
- **The API is frozen by a dump.** `api/lol.trq.alts.api` is the committed list of every exported type,
  member and signature. `apiCheck` (part of `check`) fails when a line is removed or changed in the same
  major version, and when the jar has API the dump lacks. An intended addition is recorded with
  `./gradlew apiDump`; a removal is a 2.0 matter (see [CONTRIBUTING.md](CONTRIBUTING.md)). `apiDump`
  cannot launder a break: it refuses to erase lines within a major version, to replace a missing or
  headerless baseline, and to write a dump for a version ahead of the build's major. Only
  `-PapiAllowBreaking=<reason>` overrides these refusals, and the reason is written into the dump's
  header for review.
- **Secrets stay out.** No API keys, tokens, or credentials in source or history. A server API key lives
  host-side behind `GameStatsSource` (or another seam). Never commit `.idea/`, `*.iml`, or machine paths.
- **House style.** palantir-java-format (4-space, 120 column). Records for wire DTOs with
  `@SerializedName` on every component; `AltAccount`, a final class, carries it on every field. Full Javadoc on public and protected members, with exactly one `@since` naming the
  release each one first shipped in (`SinceTagsTest` checks every exported declaration).
- **Conventional Commits**, one logical change each, and **never** a `Co-Authored-By` or any other
  AI-attribution trailer. See [CONTRIBUTING.md](CONTRIBUTING.md). A breaking commit carries `!` after
  its type or scope and a `BREAKING CHANGE:` footer saying what a host has to change.

## Patterns that matter

**Sign-in is one interface: seven routes plus one.** `AltLoginService` exposes `loginMicrosoft`
(browser, authorization code with PKCE), `loginDeviceCode` (no browser, no port; the host shows a code
through `DeviceCodePrompt`), `loginRefreshToken`, `loginCookie`, `loginCookieFile`, `loginSession`,
`loginOffline`, and `loginAccount` (log into a record you already hold). All return
`CompletableFuture<LoginResult>`; none throw at the caller, and none complete exceptionally.
`routed(tag)` returns a view whose every request carries a route tag, for a first sign-in that has no
account UUID to route on yet. A new route follows the same shape: resolve on the runtime's executor,
finish through `finalizeLogin`, return a classified result.

**One error model.** A failure anywhere is an `AltsFailure`: a `kind()` to branch on, a library-built
`message()`, `retryAfter()` / `retryAt()` when the service stated a wait, `xstsError()` on
`XBOX_DENIED`, and `retryable()`. Where the caller is expected to branch on the outcome (`LoginResult`,
`AccountStatus`, `NameChangeResult`, `ProfileCreationResult`, `ClaimResult`, `BulkEntryResult`) the
result carries it as `Optional<AltsFailure> failure()`; everywhere else it is thrown as the unchecked
`AltsException`, and a library future completes exceptionally only with one (inside a
`CompletionException`). `AltsFailure.Kind` is one enum for the whole library:

| Kind | Meaning |
|---|---|
| `NETWORK` | unreachable, timed out, a 5xx or a 408; retry |
| `RATE_LIMITED` | a `429`; wait (`retryAfter()` when stated) |
| `UNAUTHORIZED` | empty, malformed or refused; a refresh token may still renew |
| `REAUTH_REQUIRED` | a stated `invalid_grant`: the credential is spent and was discarded |
| `NOT_ENTITLED` | authenticated, no Minecraft profile (sign-in, check and `ProfileService.fetch` alike) |
| `NOT_FOUND` | a `404` on anything but the profile read |
| `XBOX_DENIED` | Xbox Live refused; `xstsError()` says why |
| `DECLINED` | the user refused an interactive sign-in |
| `TIMED_OUT` | an interactive sign-in was not finished in time |
| `CANCELLED` | stopped on the caller's side: cancelled, the runtime closed, the executor refused |
| `INVALID_INPUT` | what the caller supplied cannot be used; nothing was sent |
| `CONFLICT` | a `409`, or a store file held by another runtime |
| `NOT_CONFIGURED` | no `MicrosoftAuthConfig`, no device-code support, or the client registration refused |
| `STORAGE` | a store file could not be read or written |
| `CRYPTO` | a key did not unwrap, a ciphertext did not authenticate |
| `PROTOCOL` | an answer the protocol does not allow; every rejected vault host item |
| `UNKNOWN` | unclassified; the enum ends here so a host's `default` covers a later constant |

Hosts branch on the kind; a message string survives neither obfuscation nor localization. Classify a
*refusal* apart from an *unreachable service* apart from a *throttle*: the first means the credential is
the problem, the second means retry, the third means wait, and conflating them sends the user through a
browser login to fix an outage or retries into a ban. `AccountStatus.State` maps `RATE_LIMITED` and
`NETWORK` to `UNREACHABLE` and `XBOX_DENIED` to `NOT_ENTITLED`; that mapping is the exhaustive switch
in `internal.auth.AltAccountServiceImpl.stateFor`, so a new kind has to be placed there. `ErrorKindMigrationTableTest` pins every 0.12 constant's kind against
the CHANGELOG table, row for row.

**Absence is an `Optional`; the nulls that remain are listed.** A public method that may find nothing
returns `Optional` and never `null`: `HostSecrets.find`, `AccountStore.currentAccount()`, `loadError()`,
`failure()`, `retryAfter()`, `xstsError()`. New API follows that. The `null`-returners kept as they are
fall in four groups, and none grows: `HostSecrets.get` (prefer `find`); the cache reads polled every
frame, `AsyncCache.get` and `SkinAvatarCache.get`, where `null` means "not ready yet"; accessors of an
optional field on a wire record (`PlayerProfile.activeSkin()`, `NameEligibility.ageAt(now)`, a
mutation that returns no profile); and the `spi` seams a host implements (`AvatarSource`,
`GameStatsSource`, `TextureUploader`), whose `null` means "nothing", so a host need not build an
`Optional` on its hot path.

**A refresh token is a durable credential, not another access token.** It renews a session for as long as
it is valid, so it is redacted from every `toString`, never persisted for an account the store does not
already hold, discarded only on a *stated* `invalid_grant` (never on a 429, a 408, or a 5xx), and
withheld from a shared repository unless its latest owner-signed state opts in. Keep all four
properties when touching `AltAccount`, `AccountStore`, the sign-in chain (`internal.auth`) or the vault.

**DTOs are records with `@SerializedName` on every component**, so (de)serialization survives shrinking
and obfuscation. Any record carrying a credential, a response body or a header value overrides
`toString` to leave it out. A public record does not grow within a major version: an added component
changes the canonical constructor and breaks every deconstruction pattern over it, so `apiCheck` fails
on it, and `apiDump` refuses to record it, even when a constructor of the old arity is kept (the gate
compares the components of every record the dump already lists). A type that is expected to grow is a
final class with static factories and withers instead: `AltAccount`, `MicrosoftAuthConfig`,
`BulkOptions`, `NetworkScope`, `ClaimOptions`, `AltsFailure` and `BulkEntryResult` are, with the
accessors, value `equals`/`hashCode` and (redacted where it applies) `toString` a record would have.
`AltAccount`'s private fields carry the `@SerializedName`s, and their names and order are the store
file's format, but Gson never writes them: the stores read and write an account through the record
`internal.store.AltAccountJson.Stored`, same components, same order, so no final field is set by
reflection (a later JDK refuses that). Keep the two in step; `StoreFormatCompatTest` loads a file 0.12
wrote and requires the same bytes back. `AltsFailure` and `MicrosoftAuthConfig` are values, not wire
DTOs, and carry no annotations.

**Logging in is one step more than operating on an account.** `AltAccountService.check`/`refresh` never
touch the live session; `loginAccount` is `refresh` plus the injection. Keep it that way: anything that
works over many accounts is unbuildable the moment a session install creeps back into the middle of the
chain. Prefer `check` over `refresh` when only looking: renewal rotates the refresh token every time.

**The runtime owns its state, and hands it down.** `AltsRuntime` constructs its stores, its
`HttpTransport` and its executor and passes them to each service through its constructor; nothing in
the library reads a static to reach a store, the network or a thread. Public types that need
construction the host must not do themselves (the stores, `AccountServices`, `ProfileLookupService`,
`SkinAvatarCache`, `VaultHosts`) have no public factory: a package-private bridge in their package
(`StoreBridge`, `AccountBridge`, `SkinBridge`, `VaultBridge`) installs into an `internal.*Access` class
that accepts only that bridge, once, and the runtime builds through it. Follow the same pattern for a
new runtime-built type.

**Every request goes through the runtime's `HttpTransport`** (`internal.net`). That is where the finite
timeouts, the redirect rules, the 1 MiB body cap (16 MiB for vault exchanges), the header checks (no
control character, no caller-set `Proxy-Authorization`), and the host's proxy live. A new call site that
opens its own connection opts out of all of them. Pass a `NetworkScope` naming the purpose and, when
there is one, the account, on every hop; a routed view adds its tag. The one exception is a vault host
mapped to `grpcs://` or `grpc://`: its calls go through the host's `spi.VaultRpcChannel`
(`internal.vault.GrpcWire`), since the JDK client can speak neither HTTP/2 trailers nor h2c and the library
ships no gRPC client. The host's channel then owns routing, TLS and the inbound limit; the library still
frames and verifies every call, caps a reply at 16 MiB, and cancels the call on its deadline, an interrupt
or `close()`. `HostClient` holds every AVP client rule over a `HostWire` (`HttpWire` or `GrpcWire`), so a
rule changes in one place for both profiles; `internal.vault.rpc.ProtoJson` is the hand-written proto codec,
pinned by the vendored `grpc.json`.

**Every blocking task runs on the runtime's executor**, `transport.executor()`. Pass it as the executor
argument of `supplyAsync`, `runAsync` and `delayedExecutor`; the one-argument forms run on the common
pool, which the library does not use. Every wait goes through `transport.delay(...)` /
`schedule(...)`, which `close()` ends: the JDK's own delayed executor would swallow the rejection.

**`close()` ends everything.** It flushes and unlocks both stores, drops the vault's tokens, closes the
transport (pooled tunnels; every later request refused), and shuts down an executor the runtime created
(a host's executor is left alone). Whatever waited on the runtime fails on the closing thread: a paced
bulk run, a device-code poll, a scheduled claim, a browser sign-in's callback. A route started after
close returns `CANCELLED` (result types) or throws `AltsException(CANCELLED)` (account services). It is
idempotent, and a shutdown hook still flushes for a host that never calls it.

**Proxy resolution fails closed.** A `ProxyProvider` that throws or returns null fails the request; it
must never fall back to a direct connection. No provider means direct, per runtime. An HTTPS target
behind an HTTP proxy goes through `ProxyTunnelSocketFactory`, which sends the credential on the
`CONNECT` only and keeps connections apart per proxy identity, within one transport. The JVM still
resolves the origin host name locally on that path; that is a documented limit, not something to paper
over.

**The account services live over a token and never touch the session or store.** `account/` is a set of
one-job services built from a live access token through `alts.accountServices(account)` (or
`(token, uuid)`), aimed at `Builder#accountEndpoints` or the origin of the configured profile URL. The
implementations are in `internal.account`. `ProfileLookupService` sends no token at all.

**A scheduled claim's wait is real-time.** `NameService.claimAt` sleeps to the final stretch then spins
briefly; its clock is a `time/TimeSource` seam so a host can correct drift, but the sleep is wall-clock.
Test it with the real clock and short durations, not a frozen one. `NtpTimeSource.now()` never touches
the network. Keep "the name was claimed" separate from "the run stopped": `ClaimResult.stopReason()`
says which, and a `TERMINAL_FAILURE` carries the failure (a rate limit or a closed runtime included).

**Avatars key on UUID and default to Mojang.** `skinCache().get(uuid)`, never the username. The default
source (`internal.skin.MojangAvatarSource`) crops the face from Mojang directly, so no third party sees
the account list; `Builder#avatarUrlTemplate` is the opt-in back. At most six downloads are in flight,
and a failed fetch retries on a backoff.

**An unreadable store is not an empty store.** `AccountStore`/`HostSecrets` never overwrite a file they
failed to read, whatever the reason (the wrong key, an unavailable key, a damaged file, a read error):
they report why on `loadError()` (kind `STORAGE`), copy it aside to `<name>.unreadable.<time>` (newest
five kept; a file unread only for want of the key is copied when discarded), and refuse every write,
reported on `saveError()`, until a `load()` succeeds, the file is gone, or the host calls
`discardUnreadable()`. With the default machine-derived key, a renamed OS user is enough to make a good
file unreadable. With a `StoreKeyProvider`, a file opens under the host's key or not at all, and the
machine-derived key is accepted only while `migrateFromMachineKey(true)` is set. Preserve all of that in
any change to persistence.

**A store file has one owner.** Each store takes an exclusive `FileChannel` lock on a sidecar
`<name>.lock` for its runtime's life. A second runtime on the same file, in this process or another,
fails `build()` with `CONFLICT` (the message names the file, never the path), and a build that fails
holds no lock. `close()` releases it.

**Store writes are atomic and coalesced.** `StoreFile` stages, syncs and moves, and keeps a `.bak`. A
runtime writes 100 ms after a mutation on the store's writer thread; `save()` and `flush()` write at
once. After `close()` a mutator changes memory only and records "the store is closed" on `saveError()`.

**The vault verifies everything, trusts no host.** It speaks AVP 0.5: an owner-signed manifest chain
(members, wrapped keys, epoch, policy, hosts), member-signed commits, strict Ed25519, the pin and the
tie rule, wraps only to invite-token keys. A forged state or a rollback fails the whole operation with
`PROTOCOL`, and the pull that met it adopts nothing of what the host served (a deliberate departure
from the reference client, which keeps the valid prefix). A forged commit is not a failure: it is
neither merged nor a parent, and it is counted in the report (`SyncReport.discardedCommits()`).
`VaultHosts.connect` passes the expected host key wherever one is known; `connectFirstContact` is for a
first contact only. The library never sends a host the owner phrase, its entropy or seed, a private
key, a data key or a plaintext. `VaultSnapshot` and the `OwnerIdentity` entropy are secrets the host
persists encrypted, recommended in `HostSecrets`.
`LegacyVaultReader` reads a 0.4 repository once and writes nothing. [SECURITY.md](SECURITY.md) says
exactly what the protocol does and does not resist.

**Microsoft login needs a host-supplied client id.** There is no built-in default. `MicrosoftAuthConfig.of`
is the Azure OAuth dialect; `legacyMsa` is the pre-Azure one, which differs in its redirect, its scope,
and its RPS ticket prefix.

## Pitfalls

- **Do not add a Minecraft, renderer, or consumer import.** If a change seems to need one, it belongs
  behind a new `spi/` seam.
- **Do not export or leak `internal`.** A public signature that names an internal type, a new `exports`
  line, or a public class added to an exported package without a dump update fails `apiCheck` or
  `javadocCheck`. Decide first whether a new type is API; if it is, run `apiDump` and review the diff.
- **Do not add a method to an `spi` seam without a default.** A host implements those; an abstract
  addition breaks it, which the line-based gate does not catch. The service interfaces (`AltLoginService`,
  `AltAccountService`, `BulkOperations`, `BulkHandle`, `ProfileLookupService`, the `account` services)
  are implemented by the library only and say so, so a method may be added there.
- **Do not branch on a failure message** anywhere, including in tests. Branch on the kind; add a `Kind`
  only if none fits, and place it in `internal.auth.AltAccountServiceImpl.stateFor` (the
  `AccountStatus.State` switch), in `internal.bulk.BulkOperationsImpl`'s kind decisions (only
  `NETWORK` is retried; `RATE_LIMITED` stops or pauses a run), and in the CHANGELOG.
- **Do not throw anything but `AltsException` out of a future**, and do not throw at the caller from a
  result-typed route: a sign-in, check or refresh returns its failure.
- **Do not append a transport exception's message to user-facing text.** The JDK quotes the offending
  input in its messages, and here that input is a token, a sign-in address or a path. Use
  `internal.net.FailureText.of(failure)`, which returns a fixed phrase for the kind of failure, and keep
  the original as the cause.
- **Do not put a control character in a header**, or set `Proxy-Authorization` yourself. `HttpTransport`
  refuses both with a message that quotes nothing. Strip pasted tokens of whitespace and control
  characters first.
- **Do not use the common pool.** No one-argument `supplyAsync` / `runAsync`; pass the transport's
  executor. Logins resolve on it while the host reads `accounts()` from its own thread, which is why the
  store collections are concurrent and the mutators atomic.
- **Do not reach for a static.** There is no process-wide store, transport, executor or toast sink;
  take what you need through the constructor, from the runtime that built you.
- **Do not assume the session injector runs on the main thread.** It is called from the runtime's
  executor.
- **Do not write a store file any other way.** Go through `StoreFile`, and never write over a file whose
  last load failed.
- **Do not accept the machine-derived key under a provider** outside the migration opt-in.
- **Do not persist an account the store does not already hold.** `updateCredentials` is deliberately a
  no-op for an unknown UUID: a `DIRECT` login or an account from a shared repository is one the user
  chose not to save. Nothing the vault reads is written to the `AccountStore`.
- **Do not change a vault construction casually.** The canonical encodings, labels, AAD and wrap scheme
  are fixed by the [Alt Vault Protocol](https://github.com/trqlmao/avp) 0.5 and gated byte for byte by
  the vendored vectors (`src/test/resources/avp-vectors/`, pinned by `AvpVectorFilesTest`): the vector
  tests under `internal.avp` (`PrimitiveVectorsTest`, `ManifestVectorsTest`, `CommitVectorsTest`,
  `MergeVectorsTest`, `FederationVectorsTest`, `Bip39OwnerVectorsTest`, `NegativeVectorsTest`,
  `AcceptanceReplayTest`), and `AvpConformanceVectorsTest` in `internal.crypto` for the 0.4 primitives
  the identity and the importer rest on.
- **Do not sign raw host bytes.** 0.5 signs only canonical-encoding constructions (the challenge is
  `CE("avp/challenge/v1", hostKey, memberKey, nonce)`). `VaultIdentity.signChallenge` is the 0.4 export
  aid and refuses `avp/`-prefixed or out-of-range input; keep that guard.
- **Test seams are package-private and need nothing else.** There is no `lol.trq.alts.testSeams`
  property and no process-wide reset: a test builds its own runtime, store or transport and closes it.
  From another package, reach the seams through the helpers in the test sources: `StoreTestHooks`
  (`store`: open a store directly, its write delay, close it, list unreadable copies), `StoreFileSeams`
  (`internal.store`: the `StoreFile` hooks), `TestTransports` (`internal.net`: a transport per test,
  routed, on a given executor, or trusting a loopback TLS certificate), `AccountStoreTestSupport`
  (`internal.auth`), and `TestAvpHost` / `VaultWorld` for the vault. The hooks themselves
  (`Builder.afterStoresOpenForTests`, `StoreFile.beforeWriteForTests`, `fileForTests`,
  `SharedVault.engineForTests`) stay package-private.
- **Every test runs twice.** `check` runs the suite on the class path (`test`) and again with the jar as
  a named module (`moduleTest`), so a missing `requires` or `opens` fails there. Gson builds private
  records by reflection only in `store`, `internal.auth` and `internal.store` (the record an
  `AltAccount` goes through), which the descriptor opens to Gson alone. Never make Gson fill a final
  field: give the type a record form instead.
- **Do not edit a docs snippet directly.** Every multi-line Java block in `docs/GETTING_STARTED.md` is
  inlined from a method in `examples/`, which `check` compiles with `-Xlint:deprecation -Werror`. Change
  the example first, then the guide, character for character.
- **Do not skip the `@since`.** New public and protected members carry the version they will first ship
  in, and a `CHANGELOG.md` entry under `[Unreleased]`.
- **Do not claim live verification you do not have.** The device-code flow and the cookie chain are
  tested against loopback and scripted servers only; the vault against an in-process test host.

## Build

```bash
./gradlew build          # compile + test + moduleTest + apiCheck + apiToolTest + javadocCheck + spotlessCheck + examples
./gradlew check          # the same gate CI runs
./gradlew spotlessApply  # format (run before committing)
./gradlew apiDump        # record an intended API addition in api/lol.trq.alts.api
```

JDK 25 required. The library has no Minecraft dependency, so it builds standalone. A release is a
`build: release X.Y.Z` commit (version in `build.gradle`, dated changelog heading, the API dump's
version) followed by a `vX.Y.Z` tag; the tag's CI run publishes the GitHub release from that changelog
section, once the build and the no-leak scan of that commit have passed.

## Further reading

[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the internals,
[docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) for host integration,
[llms.txt](llms.txt) for a structured index of everything,
[SECURITY.md](SECURITY.md) for the threat model and its stated boundaries,
[api/lol.trq.alts.api](api/lol.trq.alts.api) for the frozen public surface, every exported type and member.

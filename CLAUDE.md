# CLAUDE.md

Guidance for AI coding agents working **on** this library or **with** it from a host.

**lol.trq.alts** is a general account library for Minecraft: Java Edition: sign-in, account management
over a token, bulk operations, an encrypted local store and a shared vault. Hosts are launchers, tools,
the host applications of bots, and account managers alike. It is consumed as a JitPack dependency
(`com.github.trq-lol:lol.trq.alts`) or a git submodule, and it must never depend on or reference any
specific consumer. Pure JDK plus Gson: no Minecraft types, no renderer types, no host imports. Package
and class names (`alts`, `AltStore`, `AltAccount`) are historical and stay.

## 30-second mental model

One wiring root, a handful of host seams, everything else behind them.

```java
AltsRuntime<H> alts = new AltsRuntime.Builder<H>()
        .sessionInjector(session -> ...)   // REQUIRED: make a SessionData the live session
        .vaultDirectory(() -> dataDir)     // REQUIRED: where the encrypted account file lives
        .mainThread(host::execute)         // REQUIRED: run a task on the host's main thread
        .toastSink(...)                    // REQUIRED: surface a notification
        .textureUploader(...)              // optional: PNG bytes -> your handle type H
        .avatarSource(...)                 // optional: defaults to Mojang, cropped locally
        .gameStatsSource(...)              // optional: one per server
        .microsoftAuth(MicrosoftAuthConfig.of(yourAzureClientId))  // optional
        .vaultTransportResolver(...)       // optional: avp:// authority -> transport
        .proxyProvider(scope -> ...)       // optional: route each request; absent means direct
        .executor(hostExecutor)            // optional: where blocking work runs; default virtual threads
        .storeKeyProvider(() -> keyBytes)  // optional: real key material for the stores
        .migrateFromMachineKey(upgrade)    // optional: true on the ONE launch that adopts the key
        .build();   // validates, binds the static stores, and loads them from disk

alts.loginService();           // the entire sign-in surface
alts.accountService();         // check / refresh, without touching the live session
alts.bulk();                   // the same, over many accounts, paced
alts.accountServices(account); // profile / entitlements / name / skin / cape / attributes / ... over the token
alts.profileLookup();          // name or UUID -> public identity, no token
alts.skinCache();              // UUID -> H
alts.gameStats("example.net")  // AsyncCache<uuid, GameStats>, one per registered source
```

`H` is the host's opaque texture-handle type. The library never inspects it; it only hands it back.

The proxy provider, the executor, the stores and the store key are process-wide statics behind the
runtime. A later `null` (or a second runtime that leaves one unset) never removes what is installed.

Package map:

| Package | What lives there |
|---|---|
| `spi/` | the host seams, which are the entire boundary: `SessionInjector`, `VaultDirectoryProvider`, `MainThreadExecutor`, `ToastSink`, `TextureUploader`, `AvatarSource`, `GameStatsSource`, `ProxyProvider`, `StoreKeyProvider`, `DeviceCodePrompt`, `VaultTransportResolver` |
| `auth/` | the sign-in routes, account check/refresh, `MicrosoftAuthConfig`, token expiry, cookies, `XstsError` |
| `account/` | the surface over a token: profile (read, create), entitlements, name (+claim), skin, cape, attributes, certificates, blocklist; plus the anonymous `ProfileLookupService` |
| `bulk/` | one operation over many accounts: pacing, retries, progress, cancellation, rate-limit handling |
| `net/` | `HttpUtil` (the one way out), `ProxyTunnelSocketFactory`, `IoExecutor` (the one executor), `FailureText`, `NetworkScope`, `ProxyRoute`, `Backoff`, `Multipart` |
| `store/` | `AltStore` (accounts) and `SecretStore` (per-user secrets) over the shared `StoreFile` writer |
| `time/` | `TimeSource` seam + `SystemTimeSource` / `NtpTimeSource`, for the scheduled name claim |
| `cache/` | `AsyncCache<K,V>`: lazy, non-blocking, stale-while-revalidate, bounded |
| `skin/` | `SkinAvatarCache<H>` (UUID-keyed) + `MojangAvatarSource` / `UrlTemplateAvatarSource` |
| `model/` | the records: `AltAccount`, `SessionData`, `GameStats`, `BanInfo`, enums |
| `format/` | text and colour helpers for account UIs |
| `crypto/`, `vault/` | the shared repository; `vault/transport/` is the DTO boundary, `vault/federation/` is `avp://` addressing |

## Hard rules

- **No consumer references.** Never name, import, or describe any specific application, client,
  launcher, product, sync server, or hosted instance that consumes this, and never name or link another
  authentication library, launcher or tool. Keep examples generic (`your application`, `the host`,
  `example.net`, `vault.example`). This covers source, comments, Javadoc, docs, commit messages, tests,
  and the README. `AltAccount.sourceClient`/`sourceUser` and `avp://host/repoId` define field *names*
  only; the values are host-supplied at runtime. CI enforces this (`.github/workflows/no-leak.yml`,
  against a denylist held as a repository secret).
- **Host-agnostic boundary.** Seam interfaces live in `spi/`; hosts implement them. Never reach into a
  host type. No `import` outside `lol.trq.alts`, the JDK, and Gson.
- **Secrets stay out.** No API keys, tokens, or credentials in source or history. A server API key lives
  host-side behind `GameStatsSource` (or another seam). Never commit `.idea/`, `*.iml`, or machine paths.
- **House style.** palantir-java-format (4-space, 120 column). Records for DTOs with `@SerializedName`
  on every component. Full Javadoc on public and protected members, with `@since` on each new one.
- **Conventional Commits**, one logical change each, and **never** a `Co-Authored-By` or any other
  AI-attribution trailer. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Patterns that matter

**Sign-in is one interface: seven routes plus one.** `AltLoginService` exposes `loginMicrosoft`
(browser, authorization code with PKCE), `loginDeviceCode` (no browser, no port; the host shows a code
through `DeviceCodePrompt`), `loginRefreshToken`, `loginCookie`, `loginCookieFile`, `loginSession`,
`loginOffline`, and `loginAccount` (log into a record you already hold). All return
`CompletableFuture<LoginResult>`; none throw at the caller. A new route follows the same shape: resolve
on the library executor, finish through `finalizeLogin`, return a classified result.

**Outcomes are typed, messages are not.** Every `LoginResult` carries an `AltLoginCallback.FailureReason`:

| Reason | Meaning |
|---|---|
| `NONE` | success |
| `UNKNOWN` | unclassified |
| `REAUTH_REQUIRED` | the stored credential is permanently spent and was discarded |
| `INVALID_TOKEN` | empty, malformed or refused |
| `NETWORK` | unreachable or a 5xx; retry |
| `NOT_CONFIGURED` | no `MicrosoftAuthConfig` |
| `NOT_ENTITLED` | authenticated, no Minecraft profile |
| `RATE_LIMITED` | a `429`; wait (`retryAfter()` when stated) |
| `XBOX_DENIED` | Xbox Live refused; `xstsError()` says why |
| `DECLINED` | the user refused an interactive sign-in |
| `TIMED_OUT` | an interactive sign-in was not finished in time |

Hosts branch on the reason; a message string survives neither obfuscation nor localization. Classify a
*refusal* apart from an *unreachable service* apart from a *throttle*: the first means the credential is
spent, the second means retry, the third means wait, and conflating them sends the user through a
browser login to fix an outage or retries into a ban. `AccountStatus.State` maps `RATE_LIMITED` to
`UNREACHABLE` (with `rateLimited()` true) and `XBOX_DENIED` to `NOT_ENTITLED`; that mapping is an
exhaustive switch, so a new reason has to be placed.

**There are four error models, by layer.** `LoginResult` for sign-in, `AccountStatus` for check and
refresh, the checked `AccountException` (with status, `rateLimited()`, `notFound()`, `retryAfter()`) for
account reads, and the checked `CryptoException` / `VaultException` for the vault. Mutations whose
refusal is an ordinary outcome return a classified result (`NameChangeResult`, `ProfileCreationResult`,
`ClaimResult`). The stores throw nothing for I/O and report on `loadError()` / `saveError()`.

**A refresh token is a durable credential, not another access token.** It renews a session for as long as
it is valid, so it is redacted from every `toString`, never persisted for an account the store does not
already hold, discarded only on a *stated* `invalid_grant` (never on a 429, a 408, or a 5xx), and
withheld from a shared repository unless the manifest opts in. Keep all four properties when touching
`AltAccount`, `AltStore`, `MicrosoftAuthUtil`, or `SharedVault`.

**DTOs are records with `@SerializedName` on every component**, so (de)serialization survives shrinking
and obfuscation. Any record carrying a credential, a response body or a header value overrides
`toString` to leave it out. Adding a component breaks deconstruction patterns: keep a constructor with
the previous arity and note the change in the changelog.

**Logging in is one step more than operating on an account.** `AltAccountService.check`/`refresh` never
touch the live session; `loginAccount` is `refresh` plus the injection. Keep it that way: anything that
works over many accounts is unbuildable the moment a session install creeps back into the middle of the
chain. Prefer `check` over `refresh` when only looking: renewal rotates the refresh token every time.

**Every request goes through `HttpUtil`.** That is where the finite timeouts, the redirect rules, the
1 MiB body cap, the header check, and the host's proxy live. A new call site that opens its own
connection opts out of all of them. Pass a `NetworkScope` naming the purpose and, when there is one, the
account, on every hop.

**Every blocking task goes through `IoExecutor.executor()`.** Pass it as the executor argument of
`supplyAsync`, `runAsync` and `delayedExecutor`. The one-argument forms run on the common pool, which the
library does not use.

**Proxy resolution fails closed.** An installed `ProxyProvider` that throws or returns null fails the
request; it must never fall back to a direct connection. An HTTPS target behind an HTTP proxy goes
through `ProxyTunnelSocketFactory`, which sends the credential on the `CONNECT` only and keeps
connections apart per proxy identity. The JVM still resolves the origin host name locally on that path;
that is a documented limit, not something to paper over.

**The account services live over a token and never touch the session or store.** `account/` is a set of
one-job services built from a live access token through `AccountServices.of(...)` or
`alts.accountServices(account)`. Reach them through the facade; the `*Impl` classes are package-private
on purpose. `ProfileLookupService` sends no token at all.

**A scheduled claim's wait is real-time.** `NameService.claimAt` sleeps to the final stretch then spins
briefly; its clock is a `time/TimeSource` seam so a host can correct drift, but the sleep is wall-clock.
Test it with the real clock and short durations, not a frozen one. `NtpTimeSource.now()` never touches
the network. Keep "the name was claimed" separate from "the run stopped": `ClaimResult.stopReason()`
says which, and a rate limit or a cancellation ends the run.

**Avatars key on UUID and default to Mojang.** `skinCache().get(uuid)`, never the username. The default
`AvatarSource` crops the face from Mojang directly, so no third party sees the account list;
`UrlTemplateAvatarSource` is the opt-in back. At most six downloads are in flight, and a failed fetch
retries on a backoff.

**An unreadable store is not an empty store.** `AltStore`/`SecretStore` never overwrite a file they
failed to read: they report why on `loadError()` and copy it aside to `<name>.unreadable.<time>` first
(newest five kept). With the default machine-derived key, a renamed OS user is enough to make a good file
unreadable. With a `StoreKeyProvider`, a file opens under the host's key or not at all; the
machine-derived key is accepted only while `migrateFromMachineKey(true)` is set; and while a load failed
because the key was unavailable, every write is refused until a `load()` succeeds. Preserve all of that
in any change to persistence.

**Store writes are atomic and, under the builder, coalesced.** `StoreFile` stages, syncs and moves, and
keeps a `.bak`. A runtime built through the builder writes 100 ms after a mutation on the
`alts-store-writer` thread; `save()` and `flush()` write at once.

**The vault verifies before it wraps.** `SharedVault` takes a `KeyBindingVerifier` and has no default:
`trustTransport()` is an explicit choice. `RepoPin` is the host-persisted rollback floor. The protocol
does not resist a malicious server; [SECURITY.md](SECURITY.md) says exactly where.

**Microsoft login needs a host-supplied client id.** There is no built-in default. `MicrosoftAuthConfig.of`
is the Azure OAuth dialect; `legacyMsa` is the pre-Azure one, which differs in its redirect, its scope,
and its RPS ticket prefix.

## Pitfalls

- **Do not add a Minecraft, renderer, or consumer import.** If a change seems to need one, it belongs
  behind a new `spi/` seam.
- **Do not branch on a failure message** anywhere, including in tests. Add a `FailureReason` if the
  existing ones do not fit.
- **Do not append a transport exception's message to user-facing text.** The JDK quotes the offending
  input in its messages, and here that input is a token, a sign-in address or a path. Use
  `FailureText.of(failure)`, which returns a fixed phrase for the kind of failure, and keep the original
  as the cause.
- **Do not put a control character in a header.** `HttpUtil` refuses a header name or value holding one
  with a message that quotes nothing. Strip pasted tokens of whitespace and control characters first.
- **Do not use the common pool.** No one-argument `supplyAsync` / `runAsync`; pass
  `IoExecutor.executor()`. Logins resolve on that executor while the host reads `accounts()` from its own
  thread, which is why the store collections are concurrent and the mutators atomic.
- **Do not assume the session injector runs on the main thread.** It is called from the library
  executor.
- **Do not write a store file any other way.** Go through `StoreFile`, and never write after an
  unreadable load without the copy aside, or at all while the key was unavailable.
- **Do not accept the machine-derived key under a provider** outside the migration opt-in, and never let
  a `null` remove an installed proxy provider, executor or store key.
- **Do not persist an account the store does not already hold.** `updateCredentials` is deliberately a
  no-op for an unknown UUID: a `DIRECT` login or an account from a shared repository is one the user
  chose not to save.
- **Do not change a crypto construction casually.** The scheme ids, AAD, and key-binding bytes are fixed
  by the [Alt Vault Protocol](https://github.com/trqlmao/avp) and gated byte-for-byte by
  `AvpConformanceVectorsTest` against vendored vectors.
- **Test seams need the test JVM.** `HttpUtil.resetForTests`, `IoExecutor.resetForTests`, the store
  resets and the TLS override are package-private and throw unless the JVM carries
  `-Dlol.trq.alts.testSeams=true`. The Gradle `test` task sets it; a test run from an IDE must add it.
  From another test package, reach them through the helpers in the test sources: `NetTestHooks`
  (`resetHttp`, `resetExecutor`) and `StoreTestHooks` (`reset`). Tests that install a provider, an
  executor or a write delay reset it afterwards; `bind(null)` does not.
- **Do not edit a docs snippet directly.** Every multi-line Java block in `docs/GETTING_STARTED.md` is
  inlined from a method in `examples/`, which `check` compiles with `-Xlint:deprecation -Werror`. Change
  the example first, then the guide, and never show deprecated API.
- **Do not skip the `@since`.** New public and protected members carry the version they will first ship
  in, and a `CHANGELOG.md` entry under `[Unreleased]`.
- **Do not claim live verification you do not have.** The device-code flow and the cookie chain are
  tested against loopback and scripted servers only.

## Build

```bash
./gradlew build          # compile + test + spotlessCheck + compile examples/
./gradlew check          # the same gate CI runs
./gradlew spotlessApply  # format (run before committing)
```

JDK 25 required. The library has no Minecraft dependency, so it builds standalone. A release is a
`build: release X.Y.Z` commit (version in `build.gradle`, dated changelog heading) followed by a `vX.Y.Z`
tag; the tag's CI run publishes the GitHub release from that changelog section.

## Further reading

[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the internals,
[docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) for host integration,
[llms.txt](llms.txt) for a structured index of everything,
[SECURITY.md](SECURITY.md) for the threat model and its stated boundaries,
[docs/specs/](docs/specs/) for the design records, including what remains before the 1.0 API freeze.

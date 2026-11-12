# lol.trq.alts

[![](https://jitpack.io/v/trq-lol/lol.trq.alts.svg)](https://jitpack.io/#trq-lol/lol.trq.alts)
[![Build](https://github.com/trq-lol/lol.trq.alts/actions/workflows/build.yml/badge.svg)](https://github.com/trq-lol/lol.trq.alts/actions/workflows/build.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> A Minecraft: Java Edition account library: sign-in, account management over a token, bulk operations, an encrypted local store and a shared vault, behind a small set of host seams.

**lol.trq.alts** is a general account library for Minecraft: Java Edition. It signs accounts in, keeps them, renews them, and operates on them through the public Minecraft services. It is meant for any host that handles accounts: a launcher, a command-line tool, the host application of a bot, or an account manager. It is consumer-agnostic and has no Minecraft or renderer types of its own: it is pure JDK plus Gson, and everything platform-specific crosses an interface the host implements.

## Features

- **Sign-in routes.** Microsoft browser login (authorization code with PKCE), Microsoft device-code login for a host with no browser or loopback port, OAuth refresh token, browser-cookie text, an exported cookie file (Netscape or JSON, byte-order-mark aware, size-capped), session token, and offline. All return a `CompletableFuture` from one `AltLoginService`. You supply your own Azure application client id (`MicrosoftAuthConfig`); the library ships no default, and a legacy MSA application is a supported dialect through `MicrosoftAuthConfig.legacyMsa`.
- **Typed outcomes.** Every result carries a `FailureReason` (`INVALID_TOKEN`, `REAUTH_REQUIRED`, `NETWORK`, `RATE_LIMITED`, `NOT_ENTITLED`, `XBOX_DENIED`, `DECLINED`, `TIMED_OUT`, ...), the decoded Xbox Live refusal when there is one, and the wait a rate limit stated.
- **Account management over a token.** `accountServices(account)` reads the full profile (skins, capes, pending actions), entitlements as a product set, player attributes and platform ban status, the chat-signing certificate and the blocklist; creates a profile for an entitled account that has none; and changes the name, skin and cape, including a scheduled name claim around a known time. None of it installs a session.
- **Public profile lookup.** `profileLookup()` resolves a player by name or UUID, and a list of names ten per request, with no token and no account.
- **Operate on accounts without logging into them.** `accountService().check(...)` asks whether a stored token still works; `refresh(...)` renews it and persists the rotation. Stored Microsoft sessions renew from their refresh token, so a saved account does not need a browser round each time its access token lapses.
- **Bulk operations.** `bulk().checkAll(...)`, `refreshAll(...)`, `entitlementsAll(...)` and `importCredentials(...)` run one operation over many accounts with bounded concurrency, spacing, a retry budget, progress and cancellation. A rate limit stops the run or pauses it, as configured.
- **Encrypted local store.** Accounts are kept in an AES-256-GCM file in a host-chosen directory, written atomically with a rolling backup. By default the key is derived from machine properties, which keeps credentials out of plaintext but is obfuscation only; a host can supply real key material through `StoreKeyProvider`. A file that cannot be read is never treated as an empty store: it is reported on `AltStore.loadError()` and copied aside before anything replaces it. [SECURITY.md](SECURITY.md) states what each key does and does not protect against.
- **Per-account proxy routing.** A `ProxyProvider` names the route of each request. HTTP proxies, with or without a username and password, tunnel HTTPS targets through `CONNECT`; unauthenticated SOCKS5 is supported, authenticated SOCKS5 is not. Resolution fails closed, the proxy credential is sent on the `CONNECT` only, and connections are not shared between proxy identities. One limit: on the tunnel path the JVM still resolves the target host name through the local resolver.
- **Shared vault.** Share a set of accounts between members with client-side encryption (Ed25519 identities, X25519-wrapped per-repository keys, AES-256-GCM payloads). A server that stores and relays faithfully sees only ciphertext, wrapped keys, public keys and counters. A `KeyBindingVerifier` runs before every key wrap, and a host-persisted `RepoPin` rejects a rolled-back manifest. The protocol does not yet resist an actively malicious server; [SECURITY.md](SECURITY.md) states the gaps. Refresh tokens are withheld from a repository unless its manifest opts in.
- **Federated addressing.** Repositories are addressed `avp://host/repoId` and reachable across independently hosted servers with one portable identity. The wire contract is the open [Alt Vault Protocol](https://github.com/trqlmao/avp).
- **Async caches.** `AsyncCache<K,V>` (lazy, non-blocking, stale-while-revalidate, bounded) backs player-head avatars, keyed by UUID and fetched from Mojang by default, and optional per-server game stats that a host supplies through `GameStatsSource`.
- **A library executor.** Blocking work runs on one virtual thread per task, or on the executor the host passes to the builder. Nothing runs on the common pool.
- **Host-agnostic.** The library never imports a host type. The host implements a few seams (session injection, storage directory, main-thread executor, notifications, and optionally texture upload, stats, proxy routing, store key, device-code prompt) and wires them once.
- **Obfuscation-safe.** DTOs are records with `@SerializedName` on every component.

The device-code route and the cookie route were tested against loopback and scripted servers, not against the live services; see the [changelog](CHANGELOG.md).

## Installation

[![](https://jitpack.io/v/trq-lol/lol.trq.alts.svg)](https://jitpack.io/#trq-lol/lol.trq.alts)

The coordinate is `com.github.trq-lol:lol.trq.alts`. Replace `VERSION` with the release tag, for example `v0.12.0`. Releases up to 0.11.1 were published under the repository's previous owner and are not served under this coordinate.

<details>
<summary>Gradle (Groovy)</summary>

```gradle
repositories {
    maven { url 'https://jitpack.io' }
}

dependencies {
    implementation 'com.github.trq-lol:lol.trq.alts:VERSION'
}
```
</details>

<details>
<summary>Gradle (Kotlin)</summary>

```kotlin
repositories {
    maven("https://jitpack.io")
}

dependencies {
    implementation("com.github.trq-lol:lol.trq.alts:VERSION")
}
```
</details>

Requirements:

- **Java 25.** The library is compiled for Java 25 and uses virtual threads.
- **Gson at runtime.** Gson types appear in the public API, so the library declares Gson as a compile-time API dependency (`compileOnlyApi`): a Gradle consumer gets it on the compile classpath and not on the runtime one. The host provides Gson at runtime. An application that already ships Gson needs nothing more; any other adds `com.google.code.gson:gson` itself. A Maven consumer reads the POM, where the same dependency has compile scope.
- **Module path.** The jar carries `Automatic-Module-Name: lol.trq.alts`. There is no module descriptor yet.

## Quick start

```java
// 1. Wire the host seams once at startup. H is your texture-handle type; a host that draws no
//    avatars can use any type and leave textureUploader unset.
//    build() also reads whatever store is already on disk, so AltStore.accounts()
//    is populated the moment it returns.
AltsRuntime<MyHandle> alts = new AltsRuntime.Builder<MyHandle>()
        .sessionInjector(new MySessionInjector())   // REQUIRED: install a SessionData as the live session
        .vaultDirectory(() -> myDataDir)             // REQUIRED: where the encrypted account file lives
        .mainThread(myExecutor::execute)             // REQUIRED: run a task on the host's main thread
        .toastSink(new MyToastSink())                // REQUIRED: surface a notification
        .textureUploader(new MyUploader())           // optional: avatar bytes -> host texture
        .microsoftAuth(MicrosoftAuthConfig.of(MY_AZURE_CLIENT_ID))  // optional: your own Azure app id
        .build();

// 2. Sign in through the browser.
alts.loginService().loginMicrosoft(LoginMode.ADD)
        .thenAccept(result -> { /* result.success(), result.account(), result.reason() */ });

// Or with a device code, when there is no browser to open.
alts.loginService().loginDeviceCode(
                (userCode, verificationUri, expiresAt) -> show(verificationUri, userCode),
                LoginMode.ADD)
        .thenAccept(result -> { /* result.success(), result.reason() */ });

// 3. Operate on a stored account without logging into it.
AccountServices services = alts.accountServices(account);
PlayerProfile profile = services.profile().fetch();
Entitlements owned = services.entitlements().fetch();
```

See [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) for a full walkthrough and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the internals.

## For AI agents

This repository is structured for you. Start with [`CLAUDE.md`](CLAUDE.md) (the mental model, the
patterns that matter, and the pitfalls), then [`llms.txt`](llms.txt), a structured index of the docs and
core source in the [llmstxt.org](https://llmstxt.org) format, then [`examples/`](examples/) for working
code. [`AGENTS.md`](AGENTS.md) is the condensed form of the same rules.

The points most often gotten wrong:

1. **Consumer-agnostic, always.** Never name a specific consuming application, product, or sponsor in
   source, comments, docs, or commit messages. Keep examples generic (`your application`, `the host`).
2. **Never reach into a host type.** The library imports only the JDK, Gson, and its own packages. Host
   platform behavior crosses the `spi/` seam interfaces, which the host implements.
3. **DTOs are records with `@SerializedName` on every component.** This keeps serialization stable under
   obfuscation. Do not drop the annotations or switch to field-name reflection.
4. **Microsoft login needs a host-supplied client id.** There is no built-in default; the host passes
   one through `MicrosoftAuthConfig`.
5. **A refresh token is a durable credential, not another access token.** It renews a session for as
   long as it is valid, so it is redacted from every `toString`, never persisted for an account the
   store does not already hold, and withheld from a shared repository unless the manifest opts in.
   Keep those three properties when touching `AltAccount`, `AltStore`, or `SharedVault`.
6. **Branch on `AltLoginCallback.FailureReason`, never on the message.** Messages change under
   obfuscation and localization; the reason is the contract. `NETWORK` means retry, `RATE_LIMITED` means
   wait, `INVALID_TOKEN` and `REAUTH_REQUIRED` mean the credential is the problem. Keep any new route
   classifying them apart.
7. **An unreadable store is not an empty store.** `AltStore`/`SecretStore` never overwrite a file they
   failed to read, report why on `loadError()`, and refuse to write at all while a host-supplied store
   key is unavailable. Preserve that whenever you touch persistence.
8. **Blocking work runs on the library executor.** Pass `IoExecutor.executor()` to every `supplyAsync`
   and `runAsync`; the one-argument forms run on the common pool, which the library no longer uses.
9. **House style.** palantir-java-format (4-space, 120 column), full Javadoc on public and protected
   members with an `@since` on each new one. Run `./gradlew spotlessApply` before committing, and
   `./gradlew build` (JDK 25) to test.
10. **Documentation snippets are compiled.** Every Java block in
    [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) is inlined from
    [`examples/`](examples/), which `check` compiles. Change the example first, then the guide.

The shared vault implements the [Alt Vault Protocol](https://github.com/trqlmao/avp); consult that
spec for the wire contract and the fixed byte constructions (AAD, key binding).

## Building

```bash
./gradlew build
```

Requires JDK 25. The library is pure JDK + Gson and has no Minecraft dependency, so it builds standalone.
The tests use package-private seams that are refused unless the JVM carries
`-Dlol.trq.alts.testSeams=true`. The Gradle `test` task sets it; a test run from an IDE has to add it.

## Versioning

This project follows [Semantic Versioning](https://semver.org/). See [CHANGELOG.md](CHANGELOG.md) for release history.

## License

[MIT](LICENSE) © trqlmao

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md). For security reports, see [SECURITY.md](SECURITY.md).

## Disclaimer

This is an independent, community library. It is not affiliated with, endorsed by, or associated with
Mojang or Microsoft. "Minecraft" and related marks belong to their respective owners and are used here
only to describe what the library interoperates with. The library is provided as is, without warranty of
any kind, under the MIT license. How a consuming application obtains and uses accounts, and whether that
complies with any service's terms or with applicable law, is the consumer's responsibility. Full text:
[DISCLAIMER.md](DISCLAIMER.md).

## Activity

![Repobeats analytics image](https://repobeats.axiom.co/api/embed/160f59cd4e1a963270464593e999684fe379c368.svg "Repobeats analytics image")

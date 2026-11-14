# lol.trq.alts

[![](https://jitpack.io/v/trq-lol/lol.trq.alts.svg)](https://jitpack.io/#trq-lol/lol.trq.alts)
[![Build](https://github.com/trq-lol/lol.trq.alts/actions/workflows/build.yml/badge.svg)](https://github.com/trq-lol/lol.trq.alts/actions/workflows/build.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> A Minecraft: Java Edition account library: sign-in, account management over a token, bulk operations, an encrypted local store and a shared vault, behind a small set of host seams.

**lol.trq.alts** is a general account library for Minecraft: Java Edition. It signs accounts in, keeps them, renews them, and operates on them through the public Minecraft services. It is meant for any host that handles accounts: a launcher, a command-line tool, the host application of a bot, or an account manager. It is consumer-agnostic and has no Minecraft or renderer types of its own: it is pure JDK plus Gson, and everything platform-specific crosses an interface the host implements.

## Features

- **Sign-in routes.** Microsoft browser login (authorization code with PKCE), Microsoft device-code login for a host with no browser or loopback port, OAuth refresh token, browser-cookie text, an exported cookie file (Netscape or JSON, byte-order-mark aware, size-capped), session token, and offline. All return a `CompletableFuture` from one `AltLoginService`. You supply your own Azure application client id (`MicrosoftAuthConfig`); the library ships no default, and a legacy MSA application is a supported dialect through `MicrosoftAuthConfig.legacyMsa`.
- **One error model.** Every failure in the library is an `AltsFailure`: a `Kind` to branch on (`UNAUTHORIZED`, `REAUTH_REQUIRED`, `NETWORK`, `RATE_LIMITED`, `NOT_ENTITLED`, `XBOX_DENIED`, `DECLINED`, `TIMED_OUT`, `CANCELLED`, ...), a message the library builds and that never carries a token or a path, the wait a rate limit stated, and the decoded Xbox Live refusal when there is one. A result a host branches on carries it as `failure()`; everything else throws the unchecked `AltsException`.
- **Account management over a token.** `accountServices(account)` reads the full profile (skins, capes, pending actions), entitlements as a product set, player attributes and platform ban status, the chat-signing certificate and the blocklist; creates a profile for an entitled account that has none; and changes the name, skin and cape, including a scheduled name claim around a known time. None of it installs a session.
- **Public profile lookup.** `profileLookup()` resolves a player by name or UUID, and a list of names ten per request, with no token and no account.
- **Operate on accounts without logging into them.** `accountService().check(...)` asks whether a stored token still works; `refresh(...)` renews it and persists the rotation. Stored Microsoft sessions renew from their refresh token, so a saved account does not need a browser round each time its access token lapses.
- **Bulk operations.** `bulk().checkAll(...)`, `refreshAll(...)`, `entitlementsAll(...)` and `importCredentials(...)` run one operation over many accounts with bounded concurrency, spacing, a retry budget, progress and cancellation. A rate limit stops the run or pauses it, as configured.
- **Encrypted local store.** Each runtime owns an `AccountStore` (`alts.store()`) and a `HostSecrets` (`alts.secrets()`), AES-256-GCM files in a host-chosen directory, written atomically with a rolling backup and locked to that runtime, so two runtimes, in one process or two, never write the same file. By default the key is derived from machine properties, which keeps credentials out of plaintext but is obfuscation only; a host can supply real key material through `StoreKeyProvider`. A file that cannot be read is never treated as an empty store: it is reported on `loadError()`, copied aside, and never written over until a load succeeds or the host calls `discardUnreadable()`. [SECURITY.md](SECURITY.md) states what each key does and does not protect against.
- **Per-account proxy routing.** A `ProxyProvider` names the route of each request, and a route tag routes a first sign-in that has no account yet. HTTP proxies, with or without a username and password, tunnel HTTPS targets through `CONNECT`; unauthenticated SOCKS5 is supported, authenticated SOCKS5 is not. Resolution fails closed, the proxy credential is sent on the `CONNECT` only, and connections are not shared between proxy identities or runtimes. One limit: on the tunnel path the JVM still resolves the target host name through the local resolver.
- **Shared vault on AVP 0.5.** Share a set of accounts between members through hosts that see only ciphertext, implementing the open [Alt Vault Protocol](https://github.com/trqlmao/avp) 0.5 (a draft specification). The owner's keys come from a 24-word BIP39 phrase, and every change to the members, the refresh-token policy or the hosts is a state the owner signs; every write is a commit a member signs; the client verifies the whole chain itself, wraps the data key only to keys from an invite token, and refuses a forged state or a rollback. A repository can live on several hosts, each matched by its key. Refresh tokens are withheld unless the owner turns sharing on. [SECURITY.md](SECURITY.md) states what this resists and what it does not (availability, metadata, a member who is the attacker). `LegacyVaultReader` reads a repository of the 0.4 vault once, so its accounts can move.
- **Async caches.** `AsyncCache<K,V>` (lazy, non-blocking, stale-while-revalidate, bounded) backs player-head avatars, keyed by UUID and fetched from Mojang by default, and optional per-server game stats that a host supplies through `GameStatsSource`.
- **A runtime executor.** Each runtime runs its blocking work on one virtual thread per task, or on the executor the host passes to the builder, and `close()` shuts down only the one it created. Nothing runs on the common pool.
- **A closeable runtime.** `AltsRuntime` is `AutoCloseable`: `close()` flushes and unlocks the stores, closes the transport, and ends whatever was still waiting on the runtime.
- **Host-agnostic.** The library never imports a host type. The host implements a few seams (session injection, storage directory, main-thread executor, notifications, and optionally texture upload, stats, proxy routing, store key, device-code prompt) and wires them once.
- **A frozen, narrow API.** The jar is the named module `lol.trq.alts`; the implementation lives under `lol.trq.alts.internal`, which is not exported or documented. A committed dump of the exported API gates every build, so 1.x does not break it.
- **Obfuscation-safe.** DTOs are records with `@SerializedName` on every component.

The device-code route and the cookie route were tested against loopback and scripted servers, not against the live services; see the [changelog](CHANGELOG.md).

## Installation

[![](https://jitpack.io/v/trq-lol/lol.trq.alts.svg)](https://jitpack.io/#trq-lol/lol.trq.alts)

The coordinate is `com.github.trq-lol:lol.trq.alts`. Replace `VERSION` with the release tag, for example `v1.0.0`. Releases up to 0.11.1 were published under the repository's previous owner and are not served under this coordinate.

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
- **Gson, as a transitive dependency.** `@SerializedName` sits on the public records, so Gson is part of the API and the library declares it as an ordinary `api` dependency: Gradle and Maven consumers receive `com.google.code.gson:gson` at compile and run time without declaring it. An application that ships its own Gson resolves the version as for any other dependency.
- **Module path.** The jar is the named module `lol.trq.alts` (a `module-info.java`, no `Automatic-Module-Name`). It exports the API packages only and `requires transitive com.google.gson`, so `requires lol.trq.alts;` is all a consumer module needs. On the class path the jar is sealed, so no other jar can add classes to its packages.

## Quick start

```java
// 1. Wire the host seams once at startup. H is your texture-handle type; a host that draws no
//    avatars can use any type and leave textureUploader unset.
//    build() also reads whatever store is already on disk, so alts.store().accounts()
//    is populated the moment it returns. Close the runtime when the host is done with it.
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
        .thenAccept(result -> { /* result.success(), result.account(), result.failure() */ });

// Or with a device code, when there is no browser to open.
alts.loginService().loginDeviceCode(
                (userCode, verificationUri, expiresAt) -> show(verificationUri, userCode),
                LoginMode.ADD)
        .thenAccept(result -> { /* result.success(), result.failure().map(AltsFailure::kind) */ });

// 3. Operate on a stored account without logging into it. A failure throws AltsException;
//    switch on e.kind().
AccountServices services = alts.accountServices(account);
PlayerProfile profile = services.profile().fetch();
Entitlements owned = services.entitlements().fetch();

// 4. On shutdown: write what is pending and release the store files.
alts.close();
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
   Keep those three properties when touching `AltAccount`, `AccountStore`, or the vault.
6. **Branch on `AltsFailure.Kind`, never on the message.** Messages change under obfuscation and
   localization; the kind is the contract. `NETWORK` means retry, `RATE_LIMITED` means wait,
   `UNAUTHORIZED` and `REAUTH_REQUIRED` mean the credential is the problem. Keep any new route
   classifying them apart, and throw nothing but `AltsException`.
7. **An unreadable store is not an empty store.** `AccountStore`/`HostSecrets` never overwrite a file
   they failed to read: they report why on `loadError()` and refuse every write until a load succeeds or
   the host calls `discardUnreadable()`. Preserve that whenever you touch persistence.
8. **The runtime owns its state.** The stores, the transport and the executor belong to one
   `AltsRuntime` and reach services through constructors; there are no statics. Blocking work runs on
   the runtime's executor, never the common pool.
9. **Never export `internal`.** Implementation lives under `lol.trq.alts.internal`. The exported API is
   frozen by `api/lol.trq.alts.api`, which `apiCheck` enforces; record an intended addition with
   `./gradlew apiDump`.
10. **House style.** palantir-java-format (4-space, 120 column), full Javadoc on public and protected
    members with an `@since` on each one. Run `./gradlew spotlessApply` before committing, and
    `./gradlew build` (JDK 25) to test.
11. **Documentation snippets are compiled.** Every Java block in
    [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) is inlined from
    [`examples/`](examples/), which `check` compiles. Change the example first, then the guide.

The shared vault implements the [Alt Vault Protocol](https://github.com/trqlmao/avp) 0.5; consult that
spec for the wire contract and the fixed byte constructions (canonical encoding, signatures, AAD).

## Building

```bash
./gradlew build
```

Requires JDK 25. The library is pure JDK + Gson and has no Minecraft dependency, so it builds standalone.
`check` runs the tests twice, on the class path and with the jar as a named module, and also checks the
exported API against `api/lol.trq.alts.api`, the published Javadoc for internal types, and the examples.
The tests need no system property: each builds its own runtime, store or transport.

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

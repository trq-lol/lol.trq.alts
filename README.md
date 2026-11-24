# lol.trq.alts

[![](https://jitpack.io/v/trq-lol/lol.trq.alts.svg)](https://jitpack.io/#trq-lol/lol.trq.alts)
[![Build](https://github.com/trq-lol/lol.trq.alts/actions/workflows/build.yml/badge.svg)](https://github.com/trq-lol/lol.trq.alts/actions/workflows/build.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A Java library for Minecraft: Java Edition accounts: sign in, manage, store and share them.

It is for launchers, tools, bots and account managers. It has no Minecraft or rendering types: you connect it to your
application through a few small interfaces.

## Features

- **Sign in** with a browser, device code, refresh token, cookies, session token, or offline.
- **Manage accounts**: profile, name, skin, cape, entitlements, bans and blocklist.
- **Run in bulk**: check, refresh or import many accounts, with pacing and progress.
- **Store locally** in encrypted files that are never overwritten when they cannot be read.
- **Route per account** through your own proxies.
- **Share a vault** between people, through hosts that see only ciphertext.

The device-code and cookie routes were tested against scripted servers, not the live services.

## Requirements

Java 25. Gson comes in as a dependency. Microsoft sign-in needs your own Azure application id.

## Installation

Replace `VERSION` with a [release tag](https://github.com/trq-lol/lol.trq.alts/releases), for example `v1.0.0`.

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

## Quick start

```java
// MyHandle is your texture type. Any type will do if you draw no avatars.
AltsRuntime<MyHandle> alts = new AltsRuntime.Builder<MyHandle>()
        .sessionInjector(new MySessionInjector()) // installs the signed-in session
        .vaultDirectory(() -> myDataDir)          // where the encrypted files go
        .mainThread(myExecutor::execute)
        .toastSink(new MyToastSink())             // shows a notification
        .microsoftAuth(MicrosoftAuthConfig.of(MY_AZURE_CLIENT_ID))
        .build();

alts.loginService().loginMicrosoft(LoginMode.ADD)
        .thenAccept(result -> { /* result.account() or result.failure() */ });

// Work with a stored account without signing in to it.
AccountServices services = alts.accountServices(account);
PlayerProfile profile = services.profile().fetch();

alts.close(); // on shutdown
```

## Documentation

| | |
|---|---|
| [Getting started](docs/GETTING_STARTED.md) | Install, build the runtime, sign in, handle failures |
| [Sign-in](docs/SIGN_IN.md) | Every route, refresh tokens |
| [Accounts](docs/ACCOUNTS.md) | Check, bulk runs, names, skins, lookup |
| [Storage and network](docs/STORAGE.md) | Encryption, proxies, threads |
| [Shared vault](docs/VAULT.md) | Create, invite, sync |
| [Architecture](docs/ARCHITECTURE.md) | How it works inside |
| [Security](SECURITY.md) | Threat model and reporting |

## For AI agents

Using it from Claude Code? Install the [trq-lol plugin](https://github.com/trq-lol/claude-plugin). The rest of this
section is for working on this repository.

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
   obfuscation. Do not drop the annotations or switch to field-name reflection. `AltAccount` is a final
   class whose fields carry them, in the order the store file has always had.
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
11. **Documentation snippets are compiled.** Every multi-line Java block in
    [`docs/`](docs/) except [ARCHITECTURE.md](docs/ARCHITECTURE.md) comes from
    [`examples/`](examples/), which `check` compiles. Change the example first, then the guide.

The shared vault implements the [Alt Vault Protocol](https://github.com/trqlmao/avp) 0.5; consult that
spec for the wire contract and the fixed byte constructions (canonical encoding, signatures, AAD).

## Building

```bash
./gradlew build
```

Needs JDK 25. This also checks the exported API, the Javadoc and the examples.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md). Releases follow
[Semantic Versioning](https://semver.org/); see the [changelog](CHANGELOG.md).

## License

[MIT](LICENSE) © trqlmao. Not affiliated with Mojang or Microsoft. You are responsible for how your application obtains
and uses accounts; see the [disclaimer](DISCLAIMER.md).

## Activity

![Repobeats analytics image](https://repobeats.axiom.co/api/embed/f3ac8147459846fd82dd73b490996799adee8500.svg "Repobeats analytics image")

# Getting started

Add the library, connect it to your application and sign in an account.

## Install

```gradle
repositories {
    maven { url 'https://jitpack.io' }
}

dependencies {
    implementation 'com.github.trq-lol:lol.trq.alts:VERSION'
}
```

Replace `VERSION` with a [release tag](https://github.com/trq-lol/lol.trq.alts/releases), for example `v1.0.0`. Releases
up to 0.11.1 are not served under this coordinate.

You need Java 25. Gson comes in as a dependency. In a named module, add `requires lol.trq.alts;`.

## Connect your application

You implement a few interfaces from `lol.trq.alts.spi`. The library never touches your types.

| Seam | What you provide |
|---|---|
| `SessionInjector` | Required. Turn a `SessionData` into your platform's live session and install it. Called off the main thread. |
| `VaultDirectoryProvider` | Required. The directory the two encrypted store files live in. Asked once, by `build()`. |
| `MainThreadExecutor` | Required. Run a task on your main thread. A host with no such thread passes `Runnable::run`. |
| `ToastSink` | Required. Surface a notification in your UI, or log it. |
| `TextureUploader<H>` | Optional. Upload PNG bytes and return your handle type `H`. Without it there are no avatars. |
| `AvatarSource` | Optional. Produce a face PNG for a UUID. Defaults to cropping the skin from Mojang directly. |
| `GameStatsSource` | Optional. Fetch one server's stats as display chips; you hold any API key. One per server. |
| `ProxyProvider` | Optional. Name the route each request takes. Without one, everything connects directly. |
| `StoreKeyProvider` | Optional. Supply the key material the stores are sealed under. |
| `DeviceCodePrompt` | Passed to `loginDeviceCode`, not to the builder. Show the user a code and an address. |

## Build the runtime

Build one `AltsRuntime` at startup. `build()` loads the saved accounts.

```java
return new AltsRuntime.Builder<MyHandle>()
        .sessionInjector(GettingStartedExample::installSession)
        .vaultDirectory(() -> dataDir)
        .textureUploader(imageBytes -> new MyHandle(0))
        .mainThread(Runnable::run)
        .toastSink((level, title, description, durationMs) -> show(level, title, description))
        .gameStatsSource(new ExampleNetGameStatsSource()) // optional, one per server
        // Required only for Microsoft login. Without it, Microsoft login fails cleanly and
        // offline / cookie / session login still work.
        .microsoftAuth(MicrosoftAuthConfig.of(azureClientId))
        // Optional: only if migrating an existing store written under a different filename /
        // key-binding, pass the legacy values so old files keep loading.
        .storeFileName("accounts.dat")
        .storeKeyBinding("your.mod.id")
        .build();
```

Microsoft sign-in needs your own
[Azure application](https://learn.microsoft.com/azure/active-directory/develop/quickstart-register-app) client id; the
library ships none.

One runtime owns a directory at a time. A second one fails `build()` with kind `CONFLICT`, and a directory that cannot
be created or locked fails it with `STORAGE`.

## Check that the accounts loaded

A saved file can exist and still not open, for example after the OS user is renamed. The library never treats it as
empty and never writes over it, so tell the user:

```java
alts.store()
        .loadError()
        .ifPresent(failure -> alts.toasts()
                .toast(
                        ToastSink.Level.ERROR,
                        "Accounts not loaded",
                        "The saved file could not be read: " + failure.message(),
                        8000));
```

[Storage](STORAGE.md#a-file-that-does-not-open) covers what to do next.

## Sign in

```java
// Log in (adds to the stored list and switches session).
alts.loginService().loginMicrosoft(LoginMode.ADD).thenAccept(result -> {
    if (result.success()) {
        // result.account() is now the current account.
        render(result.account().username());
    }
});

// Stored accounts.
List<AltAccount> saved = alts.store().accounts();

for (AltAccount account : saved) {
    // Lazy, cached avatar. Keyed by UUID, so a renamed account keeps its head; null until the
    // background fetch lands.
    MyHandle head = alts.skinCache().get(account.uuid());

    // Lazy, cached per-server game stats (null if no source for that server, or fetch pending).
    GameStats stats = alts.gameStats("example.net").get(account.uuid());

    renderCard(head, stats);
}
```

`loginMicrosoft` opens the system browser and waits up to five minutes. [Sign-in](SIGN_IN.md) covers the other routes.

## Handle failures

Every failure is an `AltsFailure`. Branch on its `kind()`, never on its message.

```java
alts.loginService().loginAccount(account).thenAccept(result -> {
    if (result.success()) {
        return;
    }
    switch (result.failure().orElseThrow().kind()) {
        // The credential is permanently spent and has been discarded. Send the user
        // through a fresh interactive login.
        case REAUTH_REQUIRED -> promptMicrosoftLogin(account);
        // Transient: the service was unreachable or failed. The stored refresh token is
        // untouched, so offer a retry.
        case NETWORK -> showRetry(result.message());
        // Also transient, but the remedy is to wait rather than to try again at once.
        case RATE_LIMITED -> showRetry("Too many requests; try again shortly");
        default -> showError(result.message());
    }
});
```

| Kind | Meaning | What to do |
|---|---|---|
| `NETWORK` | the service was unreachable, timed out, or answered with a server error | retry |
| `RATE_LIMITED` | the service said too many requests; `retryAfter()` has the wait when one was stated | wait |
| `UNAUTHORIZED` | the credential was empty, malformed or refused | ask for another, or renew |
| `REAUTH_REQUIRED` | the stored credential is permanently spent and was discarded | fresh interactive login |
| `NOT_ENTITLED` | signed in, but there is no Minecraft profile | nothing to retry |
| `NOT_FOUND` | the thing asked for does not exist | nothing to retry |
| `XBOX_DENIED` | signed in, but Xbox Live refused; `xstsError()` says why | the user fixes it at Xbox |
| `DECLINED` | the user refused an interactive sign-in | nothing until they ask again |
| `TIMED_OUT` | an interactive sign-in was not finished in time | start again |
| `CANCELLED` | stopped on your side: cancelled, or the runtime was closed | nothing on this runtime |
| `INVALID_INPUT` | what you supplied could not be used, and nothing was sent | fix the input |
| `CONFLICT` | the request conflicts with the current state, such as a store file in use | resolve the conflict |
| `NOT_CONFIGURED` | host configuration is missing or was refused, such as no `MicrosoftAuthConfig` | configure it |
| `STORAGE` | a store file could not be read or written | see the store's `loadError()` / `saveError()` |
| `CRYPTO` | a key did not unwrap or a ciphertext did not authenticate | wrong key, or tampered data |
| `PROTOCOL` | a service or vault host answered with something its protocol does not allow | report it; do not trust that answer |
| `UNKNOWN` | unclassified | show the message |

- A result you branch on (a sign-in, a status, a name change, a profile creation, a claim, a bulk entry) carries
  `failure()`. Everything else throws `AltsException`; a future completes exceptionally only with one, inside a
  `CompletionException`.
- `failure.retryable()` is true for `NETWORK`, and for `RATE_LIMITED` once a stated wait has passed.
- Keep a `default` branch. A later release may add a kind.

## Close it

```java
try (AltsRuntime<MyHandle> alts = buildRuntime(dataDir, azureClientId)) {
    // Open for as long as the host runs. Whatever still waits on the runtime when it closes (a
    // sign-in, a bulk run, a scheduled claim) ends as a failure.
    runHostUntilExit(alts);
}
// The files are released: another runtime may now open the same directory.
```

`close()` writes pending changes, releases the files and ends anything still waiting as a failure.
[Storage and network](STORAGE.md#threads-and-shutdown) has the details.

## Next

- [Sign-in](SIGN_IN.md): device code, refresh tokens, cookie files
- [Accounts](ACCOUNTS.md): check, refresh, bulk runs, names, skins, lookup
- [Storage and network](STORAGE.md): encryption, proxies, threads
- [Shared vault](VAULT.md): share accounts between people

The samples come from [`examples/`](../examples/README.md), which every build compiles. `render`, `showError` and
similar names stand for your own code.

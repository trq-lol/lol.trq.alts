# Getting started

This guide walks through wiring **lol.trq.alts** into a host application: a launcher, a tool, the host
of a bot, or an account manager.

Every multi-line Java snippet below is inlined from
[`examples/GettingStartedExample.java`](../examples/GettingStartedExample.java),
[`examples/SharedVaultExample.java`](../examples/SharedVaultExample.java) or
[`examples/ExampleNetGameStatsSource.java`](../examples/ExampleNetGameStatsSource.java), which the
`examples` Gradle source set compiles on every build with `-Xlint:deprecation -Werror`. The two one-line
fragments (the cookie-file extension list and the `avatarUrlTemplate` option) are the only exceptions.
Those files are the authoritative copy: if a snippet here and the example ever disagree, the example is
right. Helpers such as `render`, `showError`, `showRetry` and `GettingStartedExample::installSession`
stand in for the host's own code.

## 1. Add the dependency

```gradle
repositories {
    maven { url 'https://jitpack.io' }
}

dependencies {
    implementation 'com.github.trq-lol:lol.trq.alts:VERSION'
}
```

Replace `VERSION` with the release tag, for example `v1.0.0`. Releases up to 0.11.1 were
published under the repository's previous owner and are not served under this coordinate.

The library needs Java 25 and is pure JDK plus Gson. Gson is part of the API (`@SerializedName` sits on
the public records), so the library declares it as an ordinary `api` dependency: Gradle and Maven both
bring `com.google.code.gson:gson` in for you, at compile and at run time. An application that ships its
own Gson resolves the version in its build as for any other dependency.

The jar is the named module `lol.trq.alts`. On the module path, add `requires lol.trq.alts;`, which also
makes Gson readable (`requires transitive com.google.gson`). Only the API packages are exported: the
implementation lives under `lol.trq.alts.internal`, which is not exported, not documented and not
covered by the compatibility promise. On the class path nothing stops a call into `internal`, but
nothing promises it either, and the sealed jar keeps other code out of the library's packages.

## 2. Implement the host seams

The library never touches your types. You implement a small set of seams in `lol.trq.alts.spi`:

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

## 3. Build the runtime

Construct one `AltsRuntime` at startup, before anything reads accounts:

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

Compiled as `GettingStartedExample.buildRuntime`.

For Microsoft login you must register your own [Azure application](https://learn.microsoft.com/azure/active-directory/develop/quickstart-register-app) and pass its client id; the library ships no default. Keep the id out of source control, and override the scope or endpoints with `MicrosoftAuthConfig.of(id).withScope(...)`, `.withEndpoints(...)` or `.withDeviceCodeEndpoints(...)` only if you front the services yourself.

If your credential was minted by a **legacy MSA** application and not an Azure OAuth one, use `MicrosoftAuthConfig.legacyMsa(id)` in place of `of(id)`. The two are different dialects of the same flow: the grant must declare the desktop redirect the application registered, ask for the `MBI_SSL` scope, and hand Xbox Live a `t=`-prefixed RPS ticket. Sending the OAuth shape to a legacy application is answered with a flat `400`. Refresh tokens are the practical use: the browser flow needs the desktop redirect these applications declare, which the loopback callback server cannot serve.

Other builder options, all optional: `proxyProvider` (see [Routing requests through a proxy](#routing-requests-through-a-proxy)), `avatarSource` or `avatarUrlTemplate` (see [Avatars](#avatars)), `accountEndpoints` (points the account services and the profile lookup at another base, such as your own gateway), `executor` (see [Threads and shutdown](#threads-and-shutdown)), `storeKeyProvider` and `migrateFromMachineKey` (see [Protecting the stored file](#protecting-the-stored-file)), `vaultHostAddress` (where `alts.vault()` reaches a vault host), `secretsFileName` and `secretsKeyBinding`.

Everything the runtime configures is its own. It owns an `AccountStore` (`alts.store()`) and a `HostSecrets` (`alts.secrets()`) on the directory you named, a transport with your proxy provider, and an executor, and two runtimes in one process, on two directories, share none of it. `build()` reads whatever the stores already hold on disk, so `alts.store().accounts()` is populated by the time it returns; you do not call `load()` yourself.

Each store holds an exclusive lock on a sidecar `<file>.lock` for as long as its runtime is open, so a second runtime on the same directory, in this process or another, fails in `build()` with an `AltsException` of kind `CONFLICT`, and a directory that cannot be created or locked fails it with `STORAGE`. Close the runtime when you are done with it (see [Threads and shutdown](#threads-and-shutdown)).

A file that exists but cannot be read is a third state, and worth handling. With the default key, a renamed OS user or a moved home directory turns a good file unreadable; with a host key, so does a key that is unavailable or was rotated. The library never treats such a file as an empty store: it reports why on `loadError()`, copies the file aside to `<name>.unreadable.<time>`, and refuses every write until a later `load()` succeeds, so nothing is ever written over accounts that are merely unread. Only you can tell the user:

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

Showing an empty list reads as "my accounts are gone". The failure is of kind `STORAGE`, and its message names the file and a fixed phrase, never a path. Compiled as `GettingStartedExample.warnIfTheStoreDidNotLoad`.

When the user says the old file will never open again, `discardUnreadable()` is the explicit way past it: the file is copied aside, the refusal is lifted, and what memory holds is written as a new store at once.

```java
// Only on the user's word. The old file is copied aside first, and the next write starts a new store.
if (alts.store().loadError().isPresent() && !alts.store().discardUnreadable()) {
    // The copy aside failed, so the refusal stands; saveError() says why.
    alts.store().saveError().ifPresent(failure -> showError(failure.message()));
}
```

`alts.secrets()` has the same `loadError()`, `saveError()` and `discardUnreadable()`. Compiled as `GettingStartedExample.startOverWithoutTheOldFile`.

Two related accessors: `alts.store().loadWarning()` notes entries a successful load had to skip (no UUID, or a duplicate), and `alts.store().saveError()` says why the most recent write did not reach the disk.

## 4. Use it

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

`loginMicrosoft` opens the system browser and waits up to five minutes for the redirect on a loopback port. Compiled as `GettingStartedExample.logInAndRead`.

## Logging in with a device code

A host that cannot open a browser or listen on a port, such as a headless tool or a locked-down machine, uses the device-code route. The library fetches a short code; you show it with the address, and the user enters it on the identity provider's own page from any device:

```java
// Called once, off the render thread. Show the address exactly as given: the user has to be
// able to see that they are typing the code into the identity provider's page and nowhere else.
DeviceCodePrompt prompt = (userCode, verificationUri, expiresAt) ->
        render("Open " + verificationUri + " and enter " + userCode + " before " + expiresAt);

// Start this only on the user's own action. A device code signs in whoever started the flow,
// so a code shown to someone else is a phishing lure.
alts.loginService().loginDeviceCode(prompt, LoginMode.ADD).thenAccept(result -> {
    if (result.success()) {
        render(result.account().username());
        return;
    }
    AltsFailure failure = result.failure().orElseThrow();
    switch (failure.kind()) {
        // The user said no. Nothing to retry until they ask again.
        case DECLINED -> render("Sign-in cancelled");
        // The code ran out before it was entered; starting again issues a fresh one.
        case TIMED_OUT -> showRetry("The code expired");
        // The service asked to be left alone. Wait before starting another.
        case RATE_LIMITED -> showRetry("Too many attempts; try again shortly");
        // Signed in, but Xbox Live will not authorize the account; xstsError() says why.
        case XBOX_DENIED ->
            showError("Xbox Live refused this account: "
                    + failure.xstsError().orElseThrow());
        default -> showError(result.message());
    }
});
```

Things to know:

- The prompt is called once, off your main thread, and must return promptly; polling starts when it does.
- The library polls at the interval the service advertises and stops at the advertised expiry. Cancelling the returned future stops the polling.
- The account carries a refresh token, as with the browser route.
- The library never opens a browser or prints the code for this flow.
- This route was tested against a scripted server, not against the live service.

Compiled as `GettingStartedExample.logInWithDeviceCode`.

## Routing requests through a proxy

Microsoft and Mojang rate-limit by source address. Validating fifty accounts from one machine looks like one machine sending fifty requests, so a host that holds many accounts may want one proxy per account. Install a `ProxyProvider` and the library asks it before every request:

```java
return scope -> {
    // Avatars are not worth a proxy slot, and they carry no credential.
    if (scope.purpose() == NetworkScope.Purpose.AVATAR) {
        return ProxyRoute.direct();
    }
    ProxyRoute route = scope.accountUuid() == null ? null : poolByUuid.get(scope.accountUuid());
    // Returning null would fail the request. Say so explicitly when direct is what you meant.
    return route != null ? route : ProxyRoute.direct();
};
```

Wire it with `.proxyProvider(proxyPerAccount(myPool))`. The `NetworkScope` names what is being fetched (`AUTH`, `PROFILE`, `AVATAR`, `STATS`, `VAULT`) and, when there is one, the account it is for, which is what makes per-account pinning possible. Every hop of a renewal names its account. Rotation policy, pool health, and where proxies come from are yours; the library only asks.

A new account's first sign-in has no UUID yet to route on. For that, `alts.loginService().routed(tag)` returns a view of the login service whose every request, on every hop, reaches your provider with `scope.routeTag()` set to your tag, and `BulkOptions.defaults().withRouteTag(tag)` does the same for a bulk import. A blank tag is refused.

**Resolution fails closed.** Once a provider is installed, one that throws or returns `null` fails the request and does not connect directly. A failed request can be retried; a disclosed address cannot be taken back. Say "direct is fine here" by returning `ProxyRoute.direct()`. The provider belongs to the runtime it was given to and is fixed for that runtime's life: a runtime built without one connects directly, whatever another runtime in the process was given.

Compiled as `GettingStartedExample.proxyPerAccount`.

What works and what does not:

- **HTTP proxies, with or without credentials.** `ProxyRoute.http(host, port)` and `.withCredentials(user, password)`. An HTTPS target is reached through a `CONNECT` tunnel the library opens itself; the credential is sent on the `CONNECT` and never to the origin. Two accounts on two different authenticated proxies, or two usernames on one gateway, never share a connection, and neither do two runtimes.
- **Unauthenticated SOCKS5** works. **Authenticated SOCKS5 is not supported:** `ProxyRoute.socks5(...).withCredentials(...)` throws. The JDK reads SOCKS credentials from process-global state, which a library should not install.
- **DNS.** On the tunnel path the proxy resolves the target host, but the JVM also looks the name up through the local resolver first. If you rely on the proxy to hide which services you contact, that lookup leaks the host names.
- **The proxy leg is plain TCP.** The Basic proxy credential crosses it unencrypted, as with any HTTP proxy.
- `NtpTimeSource` does not go through the provider.

## Checking accounts without logging in

Logging into an account installs it as the live session. That is right for one account and wrong for fifty: a sweep built on `loginAccount` switches session once per account, and whichever finishes last wins.

`alts.accountService()` is the same machinery without that last step:

```java
for (AltAccount account : alts.store().accounts()) {
    alts.accountService().refresh(account).thenAccept(status -> {
        switch (status.state()) {
            // Nothing to do; the account is good, and RENEWED already persisted its new token.
            case VALID, RENEWED -> render(status.account().username());
            // The stored token is spent but recoverable — only a read-only check reports this.
            case EXPIRED -> render(status.account().username() + " needs refreshing");
            // The credential is gone for good. Only a fresh interactive login fixes it.
            case REAUTH_REQUIRED -> promptMicrosoftLogin(status.account());
            // Authenticated fine, but there is no Minecraft profile behind it.
            case NOT_ENTITLED -> showError(status.account().username() + " does not own Minecraft");
            // Try again later. Nothing was spent. A rate limit lands here too, and says how long
            // to wait when the service named a wait.
            case UNREACHABLE ->
                showRetry(status.failure()
                        .flatMap(AltsFailure::retryAfter)
                        .map(wait -> "Rate limited for " + wait)
                        .orElse(status.message()));
            default -> showError(status.message());
        }
    });
}
```

Two methods, and the difference matters:

- **`check(account)`** asks the service whether the stored token still works and changes nothing.
- **`refresh(account)`** does that, and renews from the refresh token when the stored token is spent, persisting the rotated credential.

Reach for `check` when you are only looking. The token endpoint issues a new refresh token on every redemption, so a sweep built on `refresh` spends one rotation per account per sweep.

`UNREACHABLE` covers both an outage and a rate limit: `status.failure()` tells them apart by its kind (`NETWORK` or `RATE_LIMITED`), and carries the stated wait as `retryAfter()` when there was one. `NOT_ENTITLED` also covers an account Xbox Live refused to authorize (kind `XBOX_DENIED`).

`status.account()` is the record as it now stands, renewed credentials included. Compiled as `GettingStartedExample.sweepStoredAccounts`.

## Doing it to every account at once

A loop over fifty accounts needs pacing, because the service rate-limits by address; retries that know which failures are worth retrying; a way to stop; and a report that says which account failed. `alts.bulk()` provides those.

```java
BulkHandle handle = alts.bulk().refreshAll(alts.store().accounts(), BulkOptions.defaults(), new BulkProgress() {
    @Override
    public void started(int index, int total, String label) {
        render("checking " + label + " (" + (index + 1) + "/" + total + ")");
    }

    @Override
    public void completed(int index, int total, BulkEntryResult result) {
        if (!result.success()) {
            showError(result.label() + ": " + result.message());
        }
    }

    @Override
    public void finished(BulkReport report) {
        if (report.stoppedEarly()) {
            showRetry("Stopped early — the service asked us to slow down.");
        }
        render(report.succeeded() + " of " + report.results().size() + " refreshed");
    }
});
// handle.cancel() stops it starting anything further; whatever is in flight still finishes.
return handle;
```

Four operations, all of which leave the session alone:

| Method | What it does |
|---|---|
| `checkAll` | asks whether each stored token still works; renews nothing |
| `refreshAll` | that, and renews the spent ones, persisting each rotation |
| `entitlementsAll` | reads what each account owns; the product set is on `BulkEntryResult.entitlements()` |
| `importCredentials` | resolves a pasted list into accounts, storing them with `LoginMode.ADD` |

`BulkOptions.defaults()` is four at a time, a quarter second apart, two retries growing from two seconds, stopping if the service says to slow down.

Worth knowing:

- **`stopOnRateLimit` defaults to on.** Any rate limit, with or without a stated wait, ends the run. `report.stoppedEarly()` tells you it happened, which is different from `cancelled()` and from a run where everything ran and some entries failed. With `withoutStoppingOnRateLimit()` the whole run pauses for the stated wait, or a growing one when none was stated, and the entry then tries again.
- **Only transient failures are retried.** A refused or permanently spent credential is never retried.
- **Cancel stops it starting more.** Entries already in flight finish and appear in the report.
- **Every entry is reported.** A run the closing runtime cuts short reports each entry it did not finish as a failure of kind `CANCELLED`. Each `BulkEntryResult` carries its failure as `failure()`.
- **Labels are never credentials.** `BulkEntryResult.label` is a resolved username or `entry 4`, never the input line.
- **`entitlementsAll` does not renew.** It reads each account with the token it holds. An expired token fails its entry as `UNAUTHORIZED`; run `refreshAll` first when tokens may be stale.
- Spacing is global, not per proxy route. Shard your own runs if you need per-route pacing.

Importing works the same way, and each line is classified before it is sent anywhere:

```java
alts.bulk()
        .importCredentials(pastedLines, LoginMode.ADD, BulkOptions.defaults(), BulkProgress.NONE)
        .report()
        .thenAccept(report -> {
            render(report.succeeded() + " imported");
            for (BulkEntryResult failure : report.failures()) {
                // The label is a username or "entry 4" — never the line, which is a credential.
                showError(failure.label() + ": " + failure.message());
            }
        });
```

`CredentialKind.detect(line)` is public, so you can show a user what you are about to import before running it. A line it cannot place comes back `UNKNOWN` and fails that entry with kind `INVALID_INPUT`; it is not guessed at. A bare word is taken for an offline account only when it is a valid name of 3 to 16 letters, digits or underscores. Compiled as `GettingStartedExample.refreshEverything` and `GettingStartedExample.importPastedCredentials`.

## Managing an account

Once you hold a live account, `alts.accountServices(account)` is what you can do to it through the Minecraft services. None of it installs a session or touches the store; each call operates on the account the token belongs to.

```java
AccountServices services = alts.accountServices(account);

// What it looks like: name, skins, capes, and any pending moderation action.
PlayerProfile profile = services.profile().fetch();
render(profile.name() + (profile.hasPendingActions() ? " (flagged)" : ""));

// What it owns — the product set, not a boolean, so a lapsing Game Pass is told from ownership.
Entitlements owned = services.entitlements().fetch();
if (owned.viaGamePass() && !owned.ownsJavaOutright()) {
    showError(profile.name() + " plays Java through Game Pass, which can lapse");
}

// Change its name, if a name you want is free.
if (services.name().checkAvailability("DesiredName") == NameAvailability.AVAILABLE) {
    NameChangeResult change = services.name().change("DesiredName");
    if (!change.success()) {
        showError("Name change: " + change.message());
    }
}
```

The services and what each covers:

| Service | What it does |
|---|---|
| `profile()` | `fetch` (name, UUID, skins, capes, pending `profileActions`), `fetchIfPresent` (empty for an entitled account with no profile yet), `create(name)` |
| `entitlements()` | the product set (`ownsJava`, `ownsJavaOutright`, `viaGamePass`, `ownsBedrock`) |
| `name()` | `checkAvailability`, `eligibility` (with an estimated next change), `change`, and a scheduled `claimAt` |
| `skin()` | `setFromUrl`, `upload` (bytes or a `Path`), `reset` / `resetToDefault`, with the classic/slim model; `validate` checks bytes without sending them |
| `cape()` | `owned`, `setActive`, `hide` / `hideActive` |
| `attributes()` | privileges, preferences and platform ban status; `setProfanityFilter` |
| `certificates()` | the chat-signing key pair, with its expiry; never persisted |
| `blocklist()` | the players the account has blocked |

A read that fails throws the unchecked `AltsException`; switch on `e.kind()` (`UNAUTHORIZED` for a refused token, `RATE_LIMITED` with `e.failure().retryAfter()`, `NOT_FOUND`, `NETWORK`, ...), never on its message. A missing Minecraft profile is `NOT_ENTITLED`, as sign-in and check report it. A mutation whose refusal is an ordinary outcome does not throw: a name change returns a `NameChangeResult` (changed, invalid, unavailable, or `FAILED` with its `failure()`), and `profile().create(name)` a `ProfileCreationResult` whose outcome tells a taken name from a disallowed one, with `FAILED` carrying the failure of an unentitled account or a throttle.

A skin upload is checked locally before anything is sent: the data must be a PNG of 64x64 or 64x32 pixels, at most `SkinService.MAX_SKIN_BYTES`. `skin().validate(bytes)` returns the `SkinProblem` (`UNREADABLE`, `EMPTY`, `TOO_LARGE`, `NOT_PNG`, `WRONG_DIMENSIONS`) without sending anything, so you can say why a file is refused; an upload that fails the same check throws `AltsException` of kind `INVALID_INPUT`.

Compiled as `GettingStartedExample.manageAccount`.

### Player attributes and bans

`attributes()` reads what the account is allowed to do and whether the platform has banned it. This is the platform's own verdict, read over the account's token, and is distinct from the per-server bans a host records on the account itself.

```java
PlayerAttributes attributes = alts.accountServices(account).attributes().fetch();

if (!attributes.canPlayMultiplayer()) {
    showError(account.username() + " cannot join servers");
}
if (!attributes.canChat()) {
    render(account.username() + " has chat disabled");
}

// A ban is per scope. A null expiry is a permanent one.
PlayerAttributes.Ban ban = attributes.ban(PlayerAttributes.SCOPE_MULTIPLAYER);
if (ban != null && ban.activeAt(java.time.Instant.now())) {
    showError(account.username() + " is banned from multiplayer "
            + (ban.permanent() ? "permanently" : "until " + ban.expires()) + ": " + ban.reason());
}
```

Compiled as `GettingStartedExample.readAttributes`.

### Claiming a name at a drop

When a name frees up at a known time, `claimAt` fires a bounded burst of change attempts around that instant and stops on the first success:

```java
alts.accountServices(account)
        .name()
        .claimAt(name, dropsAt, ClaimOptions.defaults())
        .thenAccept(result -> {
            if (result.claimed()) {
                render("claimed " + name + " in " + result.attempts() + " attempts");
            } else {
                // Why the run ended; a terminal failure says what kind it was.
                showError("did not get " + name + ": " + result.stopReason()
                        + result.failure()
                                .map(f -> " (" + f.kind() + ")")
                                .orElse(""));
            }
        });
```

The drop time is an input: you read it off wherever names are listed and pass it in; the library does not monitor for one. `ClaimOptions` sets the lead time, the window, the spacing, the concurrency and the `TimeSource`. `result.stopReason()` says why the run ended (`CLAIMED`, `WINDOW_ELAPSED`, `TERMINAL_FAILURE`, `CANCELLED`); a `TERMINAL_FAILURE` carries its `failure()`, whose kind says whether it was a rate limit, a refused token or something else. A rate limit ends the run, and cancelling the returned future stops it before the next attempt.

To correct the clock, pass an `NtpTimeSource` (its constructors take the executor its measurements run on), or your own source if you already hold corrected time. `NtpTimeSource.now()` never touches the network, so call its blocking `sync()` before scheduling if the correction has to be in hand; until a measurement lands it is the OS clock. Compiled as `GettingStartedExample.claimAtDrop`.

## Looking a player up

`alts.profileLookup()` resolves names to identities without any account. The lookup is anonymous, so it works before anyone has logged in:

```java
// One name: empty when nobody holds it, which is an answer rather than an error.
alts.profileLookup().byName("DesiredName").ifPresent(player -> render(player.name() + " " + player.uuid()));

try {
    // Many names: sent ten per request. A name nobody holds is simply absent from the result.
    for (PublicProfile player : alts.profileLookup().byNames(names)) {
        render(player.name() + " " + player.uuid());
    }
} catch (AltsException failure) {
    if (failure.kind() != AltsFailure.Kind.RATE_LIMITED) {
        throw failure;
    }
    // Not "those players do not exist": come back after the wait, when the service named one.
    showRetry("Lookup rate limited"
            + failure.failure().retryAfter().map(wait -> " for " + wait).orElse(""));
}
```

`byUuid` takes a dashed or undashed UUID. A value no player could hold (an empty name, one longer than 16 characters, a character outside letters, digits and underscore, or something that is not a UUID) is answered empty without a request. A rate limit part-way through a list fails the whole call; it does not return a partial list. A long list is yours to pace. Compiled as `GettingStartedExample.lookUpPlayers`.

## Logging in from a cookie file

Cookie exports arrive as files more often than as pasted text, and the Netscape format is line-oriented, so pasting one through a single-line input mangles it. Hand the library the path:

```java
alts.loginService().loginCookieFile(chosen, LoginMode.ADD).thenAccept(result -> {
    if (result.success()) {
        render(result.account().username());
    } else {
        showError(result.message());
    }
});
```

The read runs off the calling thread, so this is safe to call from a file-picker callback on your main thread. A file that is missing, is not a file, is larger than `CookieFile.MAX_BYTES`, or holds nothing comes back as a failed result of kind `UNAUTHORIZED` and not as a thrown exception. A failure during the sign-in itself is classified like any other route (`NETWORK`, `RATE_LIMITED`, `XBOX_DENIED`, ...). Failure messages name the file but never the path to it.

Three export shapes are recognised: the tab-separated **Netscape** format (including its `#HttpOnly_` lines), the **JSON** array the common cookie-editor extensions write (including when it is nested under a wrapper key), and text that has been through a copy-paste and lost its structure. Decoding honours a byte-order mark.

Only cookies whose domain is `live.com` or a subdomain are used; everything else in a whole-browser export is dropped. They are sent only to HTTPS hosts their domain covers, and the chain stops on any hop that is not HTTPS. This route follows a browser redirect chain that the services can change without notice, and it was tested against a scripted server only.

If you collect cookie text some other way, `CookieFile.read(Path)` is public, so you can reuse the size cap and the encoding handling without the login route; it throws `AltsException` of kind `INVALID_INPUT` for a file it cannot use. Compiled as `GettingStartedExample.logInFromCookieFile`.

### The picker is yours

The library never opens a window. All it takes is a `Path`. What it does supply is the filter, so your picker and its parser agree:

```java
CookieFile.EXTENSIONS   // ["txt", "json", "cookies"], no leading dot
```

The extension list is advisory. `read` accepts any path, because a user who renamed their export is not wrong.

## Refresh tokens and silent renewal

A Minecraft access token lasts roughly a day. A Microsoft login also yields an OAuth **refresh token**, which the library stores on the account (`AltAccount.refreshToken()`) and redeems to mint a new session without a browser round.

You do not have to drive this. `loginAccount` handles it:

```java
// Reuses the stored session if it is still live; otherwise renews from the refresh token,
// persists the rotated credential, and installs the session — all without a browser.
alts.loginService().loginAccount(account).thenAccept(result -> {
    if (result.success()) {
        render(result.account().username());
    }
});
```

Renewal runs on two triggers: proactively, when the stored expiry (or the token's own `exp` claim) says the access token is spent, and once reactively, when a token that looked live is refused. It never retries in a loop. Compiled as `GettingStartedExample.logInStoredAccount`.

To import a refresh token you already hold, use the login route directly:

```java
alts.loginService().loginRefreshToken(refreshToken, LoginMode.ADD).thenAccept(result -> {
    if (result.success()) {
        // Always the rotated value; persist it for any account the store does not hold.
        persist(result.account().refreshToken());
    } else if (result.failure().orElseThrow().kind() == AltsFailure.Kind.NOT_CONFIGURED) {
        // Only the routes that talk to Microsoft can report this one.
        showError("Microsoft login is not configured");
    }
});
```

Compiled as `GettingStartedExample.importRefreshToken`.

The token endpoint usually **rotates** the refresh token, issuing a new one and invalidating the old. The rotated value is always on `result.account().refreshToken()`, and who persists it depends on where the account came from:

- **Accounts in the local store** (added with `LoginMode.ADD`, or loaded from disk) are updated and written for you.
- **Every other account** (one handed to `loginAccount` straight from a shared repository, one logged in with `LoginMode.DIRECT`, or any record the store has never seen) is **not** persisted. `alts.store().updateCredentials` deliberately does nothing for a UUID it does not already hold. For those, read `result.account().refreshToken()` after every login and persist it yourself, or the next renewal redeems a token the service has already invalidated.

### Branching on the failure

Every failed `LoginResult` carries an `AltsFailure` as `failure()`, so you can pick the right prompt from its kind without matching on a message string, which survives neither obfuscation nor localization:

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

Compiled as `GettingStartedExample.logInStoredAccountWithBranching`.

`AltsFailure.Kind` is one enum for the whole library: a sign-in, a check or a refresh, an account service, a bulk entry, a store and the vault all report through it. Where you are expected to branch on the outcome (a sign-in, an account's status, a name change, a profile creation, a name claim, a bulk entry) the result carries it as `failure()`; everywhere else it is thrown as an `AltsException`, and a future completes exceptionally only with one (inside a `CompletionException`).

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

`failure.retryable()` says whether an unchanged retry may succeed now: `NETWORK` is, `RATE_LIMITED` is once its stated wait has passed, and nothing else is. A 5xx or a dropped connection never costs the user their refresh token, while a rejection the service calls permanent clears it. Keep a `default` branch: a later release may add a kind.

## Shared vault

The shared vault lets members share a set of accounts through hosts that store only ciphertext. It speaks AVP 0.5, the current draft of the [Alt Vault Protocol](https://github.com/trqlmao/avp): the owner, whose keys come from a 24-word BIP39 phrase, signs every change to the members, the policy and the hosts; every write is a commit a member signs; and the client verifies all of it itself, from genesis, trusting no host. Read the threat model in [SECURITY.md](../SECURITY.md) before relying on it.

The whole flow is compiled in [`SharedVaultExample`](../examples/SharedVaultExample.java). Each method there blocks on its futures, so run it off your main thread. The owner key and the snapshot go into `alts.secrets()` under keys of your choosing (`OWNER_ENTROPY` and `SNAPSHOT` in the example).

### Creating a repository

The owner generates its identity, keeps it, connects to its home host and creates the repository:

```java
HostSecrets secrets = alts.secrets();
OwnerIdentity owner = OwnerIdentity.generate();
showOnce(owner.phrase()); // the owner writes it down: it is the only way back to the owner key
byte[] entropy = owner.entropy();
try {
    secrets.put(OWNER_ENTROPY, Base64.getEncoder().encodeToString(entropy));
} finally {
    Arrays.fill(entropy, (byte) 0);
}

// A first contact: nobody vouched for this host's key yet, so show it to compare out of band. From
// here on the snapshot and every token carry it, and each later connection pins it.
VaultHost home = alts.vault().connectFirstContact(homeHost).join();
showOnce("Vault host key: " + home.hostKey());
SharedVault vault = SharedVault.create(home, owner).join();
secrets.put(SNAPSHOT, vault.snapshot().toJson());
return vault.locator().text();
```

Compiled as `SharedVaultExample.createRepository`. Things to know:

- **The phrase is the owner.** Whoever holds the phrase or its entropy controls the repository. Show the phrase once and keep only the entropy, encrypted (`HostSecrets` is), or keep nothing and ask for the phrase (`OwnerIdentity.fromPhrase`) when the owner acts. A second owner device is linked with `LinkSession`, after the owner compares a 6-digit code on both devices, without typing the phrase.
- **`alts.vault()` reaches hosts on the runtime's transport**: your proxy provider (purpose `VAULT`), timeouts and executor. A host locator `host[:port]` is reached at `https://<locator>` unless `Builder#vaultHostAddress` maps it elsewhere; the mapping never changes which host is accepted, because a host is matched by its key.
- **`connectFirstContact` is for a first contact only.** It takes whatever key the host names, which is then unverified. Compare it out of band, then use `connect(HostRef)` (persist `home.ref()`), `connect(locator, key)`, `connect(RepoLocator)` or `connect(VaultSnapshot)`, each of which refuses a host that serves another key with `PROTOCOL`. [SECURITY.md](../SECURITY.md) says what a first contact cannot rule out.
- **The snapshot is a secret.** `VaultSnapshot` holds the pin a rollback must not go below, the retained data keys, the clock and the merged accounts; it names the member but does not hold its identity. Persist `toJson()` encrypted, in `HostSecrets` for example, after every operation.

### Inviting and joining

A member joins through two pasted tokens. The joiner, holding its own `VaultIdentity`, reads the repo locator the owner sent and asks the owner's home host to carry the repository for it:

```java
RepoLocator locator = RepoLocator.parse(pastedLocator);
VaultHost home = alts.vault().connect(locator).join(); // matched by the locator's host key
InviteToken token = SharedVault.prepareJoin(home, member, locator).join();
return token.text();
```

The owner checks the invite token's fingerprint against the one the joiner's device shows, and invites:

```java
InviteToken token = InviteToken.parse(pastedInvite);
if (!token.fingerprint().equals(fingerprintTheMemberSees)) {
    return; // not the person the owner meant to invite
}
SharedVault vault = resumeOwner(alts);
vault.invite(token).join();
alts.secrets().put(SNAPSHOT, vault.snapshot().toJson());
```

Then the joiner joins and reads the accounts:

```java
RepoLocator locator = RepoLocator.parse(pastedLocator);
VaultHost home = alts.vault().connect(locator).join();
SharedVault vault = SharedVault.join(home, member, locator).join();
alts.secrets().put(SNAPSHOT, vault.snapshot().toJson());
return vault.accounts();
```

Compiled as `SharedVaultExample.requestInvite`, `invite` and `join`. The owner wraps the data key only to the keys in the invite token, never to keys a host serves, and verifies the acceptance the joiner's home host signed into it. The joiner checks the repository's owner key against the fingerprint in the locator and verifies the chain from genesis. Every token reads pasted text with `parse`, ignoring whitespace anywhere, so a token a chat client wrapped still reads; anything else is `INVALID_INPUT`.

### Writing and syncing

On a later run the owner resumes from the snapshot:

```java
HostSecrets secrets = alts.secrets();
byte[] entropy = Base64.getDecoder().decode(secrets.get(OWNER_ENTROPY));
OwnerIdentity owner;
try {
    owner = OwnerIdentity.fromEntropy(entropy);
} finally {
    Arrays.fill(entropy, (byte) 0);
}
VaultSnapshot snapshot = VaultSnapshot.fromJson(secrets.get(SNAPSHOT));
VaultHost home = alts.vault().connect(snapshot).join(); // the home host, by the key it had
return SharedVault.resume(home, owner, snapshot).join();
```

and shares, edits, syncs and acts on what the sync reports:

```java
SharedVault vault = resumeOwner(alts);
try {
    vault.put(account).join();
    vault.update(
                    renewed.uuid(),
                    held -> held.withTokens(renewed.accessToken(), renewed.refreshToken(), renewed.expiresAt()))
            .join();
    SyncReport report = vault.sync().join();
    if (report.policyTurnedOn()) {
        showOnce("This repository now shares refresh tokens.");
    }
    report.divergedAt().ifPresent(seq -> showOnce("Two owner devices diverged at state " + seq));
    List<VaultMember> leaving = vault.processLeaves().join();
    leaving.forEach(m -> showOnce("Removed " + m.fingerprint() + ", who left"));
} catch (CompletionException e) {
    AltsFailure failure = ((AltsException) e.getCause()).failure();
    if (failure.kind() == AltsFailure.Kind.PROTOCOL) {
        showOnce("The vault host served something that does not verify: " + failure.message());
    }
} finally {
    alts.secrets().put(SNAPSHOT, vault.snapshot().toJson());
}
```

Compiled as `SharedVaultExample.resumeOwner` and `shareAndSync`. A member resumes the same way with its `VaultIdentity`. What to know about writes and syncs:

- **`update(uuid, edit)` is the way to change an account.** The edit runs on the account as the copy holds it when the write runs, and only the fields it changed are written, so a field another member changed meanwhile is never reverted. `put(base, edited)` writes the fields where the two differ, for an edit of an account read earlier. `put(account)` writes the fields that differ from the copy as it stands, so a stale object can revert remote edits. `remove(uuid)` and `markBanned(uuid, serverId, ban)` complete the set, and a write that changes nothing sends no commit.
- **Nothing the vault reads is saved to the `AccountStore`.** Copy an account into the store yourself if the user wants it kept locally.
- **The `SyncReport` says what the owner has to act on:** new states, a diverged owner chain the tie rule settled (`divergedAt`), a policy that turned to sharing (`policyTurnedOn`), heads that could not be read or were discarded, malformed items, and pending leave requests. `openReport()` says the same of the pull that opened the copy.
- **The owner manages the roster.** `roster()` lists the members as `VaultMember`s, `remove(member)` removes one and rotates the data key, `processLeaves()` removes members who asked to leave, and `hosts()` lists the repository's hosts. A member can `leave()`. Members cannot invite.
- **A host that lies fails the whole operation with `PROTOCOL`.** A forged state, a forged commit or a rollback below the pin is refused, and the device's copy stays as it was. Every vault future fails only with an `AltsException`.

### Sharing policy

A refresh token is a durable credential, so it does **not** travel into a shared repository by default. The owner turns sharing on in a new owner-signed state:

```java
// Withholding is the default for a new repository.
render(vault.sharesRefreshTokens() ? "sharing" : "withholding");

// Owner only. What has been shared stays shared: turning it off later stops future sharing only.
vault.setShareRefreshTokens(true).join();
```

Compiled as `GettingStartedExample.shareRefreshTokens`. While the latest verified state withholds them, `refreshToken` and `expiresAt` are neither sent nor read, so a member running a modified build cannot push them in, and a host cannot flip the flag without breaking the owner's signature. **Opting in is effectively permanent** for what was shared: removing a member rotates the data key, but a refresh token that already reached a member's disk is a credential they hold outright. The only real revocation is at the identity provider: revoke the account's sessions and change its password.

### Carrying over a 0.4 repository

1.0 no longer speaks the 0.4 vault. `LegacyVaultReader` is the one read-only path out of it: give it the manifest and envelope JSON as the 0.4 host wrote them (the JSON is parsed strictly; fetch them with your own HTTP client, authenticating with `VaultIdentity.signChallenge`, or export them while you still run 0.12) and the member's identity, unlocked from its `WrappedIdentity` with the passphrase or the recovery code:

```java
try {
    return LegacyVaultReader.read(manifestJson, envelopeJson, identity);
} catch (AltsException e) {
    switch (e.kind()) {
        // The text the host saved is not strict JSON: fetch or export it again.
        case INVALID_INPUT -> showError("That is not a saved 0.4 repository");
        // Not this member's repository, a manifest and envelope that do not belong together, or
        // not a 0.4 document at all.
        case PROTOCOL -> showError("This identity cannot read that repository");
        // The key did not unwrap or the payload did not authenticate: wrong identity, or tampered.
        case CRYPTO -> showError("The repository could not be decrypted");
        default -> showError(e.getMessage());
    }
    return List.of();
}
```

It never writes, never talks to a host and keeps nothing. Nothing in a 0.4 repository is signed and an import has no rollback floor, so review the accounts before the owner writes them into a new AVP 0.5 repository and invites the members again. Compiled as `GettingStartedExample.importLegacyRepository`.

## Game stats (optional)

Stats are server-agnostic: you implement a `GameStatsSource` per server that returns ready-to-render chips, and the library caches them. It never interprets the chips.

```java
public final class ExampleNetGameStatsSource implements GameStatsSource {

    @Override
    public String serverId() {
        return "example.net";
    }

    @Override
    public GameStats fetch(String uuid) {
        // A real implementation would look the player up on example.net here, then format whatever
        // stats matter for the card. The library never interprets these chips.
        List<GameStats.Stat> chips = List.of(
                new GameStats.Stat("rank", "Veteran"),
                new GameStats.Stat("wins", "128"),
                new GameStats.Stat("kdr", "1.74"));
        return new GameStats(serverId(), uuid, chips, System.currentTimeMillis());
    }
}
```

Register it with `.gameStatsSource(new ExampleNetGameStatsSource())` (call it again for more servers), then read it back per server:

```java
GameStats stats = alts.gameStats("example.net").get(playerUuid);
if (stats != null) {
    for (GameStats.Stat chip : stats.stats()) {
        render(chip.label() + " " + chip.value());
    }
}
```

`fetch` runs on the runtime's executor and may block. For tests and demos, the shipped `StaticGameStatsSource` returns fixed chips with no API call. The source above is compiled as [`ExampleNetGameStatsSource`](../examples/ExampleNetGameStatsSource.java) and the read-back as `GettingStartedExample.readGameStats`.

## Avatars

`alts.skinCache().get(uuid)` returns a host texture handle for a player's face, or `null` while a background fetch runs. **Key it on the UUID, not the username**: a rename leaves a username-keyed entry pointing at a name that no longer resolves.

By default the library resolves the skin from Mojang's own session server and crops the 8×8 face (hat composited) locally. A third-party head-render URL would hand that service the identity of every account on every cache miss, and you are already talking to Mojang for sign-in, so sourcing the face there adds no new party.

If you want a head-render service, opt in on the builder:

```java
.avatarUrlTemplate("https://example.net/avatar/{uuid}/{size}.png")
```

That discloses each UUID to the service you name, through your proxy provider with purpose `AVATAR`. `build()` fails when the template has no `{uuid}` placeholder, or when an `avatarSource` is set as well; implement `AvatarSource` yourself for anything else. At most six downloads run at once; the rest queue. A failed fetch is retried after a growing backoff. When you know a skin changed, `skinCache().invalidate(uuid)` drops the entry and returns the old handle so you can free the texture.

## Protecting the stored file

Accounts are stored in one file in your `VaultDirectoryProvider` directory, encrypted with AES-256-GCM, and the host secrets in a second. By default the key is derived from machine properties plus the key-binding constant. That keeps credentials out of plaintext and stops a copied file opening as it is elsewhere, but the inputs are not secret: it is obfuscation.

A host that can hold a real secret seals the stores under it:

```java
// The same bytes every time, and at least StoreKeyProvider.MIN_LENGTH of them. A provider that
// throws leaves the stores unreadable and unwritable rather than falling back to the weaker key.
StoreKeyProvider storeKey = () -> keystore.loadOrCreate("alts-store-key", 32);

return new AltsRuntime.Builder<MyHandle>()
        .sessionInjector(GettingStartedExample::installSession)
        .vaultDirectory(() -> dataDir)
        .mainThread(Runnable::run)
        .toastSink((level, title, description, durationMs) -> show(level, title, description))
        .storeKeyProvider(storeKey)
        // Off by default, and on for the upgrade launch only: it lets files written before the
        // provider was installed load once and be resealed under it. Left on, it would keep
        // accepting the machine-derived key, which is the key the provider exists to replace.
        .migrateFromMachineKey(upgradeLaunch)
        .build();
```

`keystore` stands for wherever you keep the secret: an operating-system keystore entry, a hardware-backed key, a key derived from a passphrase. Compiled as `GettingStartedExample.buildRuntimeWithHostKey`.

The rules:

- **With a provider, a file opens under your key or not at all.** A store written before you installed the provider does not load, and is reported on `alts.store().loadError()`, unless `migrateFromMachineKey(true)` is set for that launch.
- **Migration is a one-launch opt-in.** Decide `upgradeLaunch` yourself, for example from a flag you persist once the migration has run. That launch loads the old store, rewrites it under your key, and reseals or removes the backup and every unreadable copy. Leave it off afterwards: while it is on, anyone who can write the directory can plant a file sealed under the guessable key.
- **A file that did not open is never written over.** Whatever the reason (the provider threw, or returned `null` or fewer than 16 bytes; the file is sealed under another key; it is damaged), every write is refused until `alts.store().load()` and `alts.secrets().load()` have been called again and succeeded, or you call `discardUnreadable()` on purpose. `saveError()` says so in the meantime.
- **The provider belongs to its runtime.** It is fixed for the runtime's life, and no other runtime's stores ever see it. A runtime built without it, on the same directory, cannot open the host-keyed files, and does not write over them either.

## Threads and shutdown

- **Executor.** Each runtime runs its blocking work on its own executor: by default one it creates, which starts a virtual thread per task (named `alts-io-<n>`), or the one you pass with `.executor(yourExecutor)` to bound concurrency or propagate your own context. Nothing runs on the common pool. Callbacks you chain with `thenAccept` run on that executor, not on your main thread; marshal yourself when you touch UI state.
- **Store writes.** A runtime gathers store mutations for 100 ms and writes them once on a background thread. `alts.store().save()` and `alts.store().flush()` write at once and return when the data is on disk.
- **Closing.** `AltsRuntime` is `AutoCloseable`. Close it when you are done with it:

```java
try (AltsRuntime<MyHandle> alts = buildRuntime(dataDir, azureClientId)) {
    // Open for as long as the host runs. Whatever still waits on the runtime when it closes (a
    // sign-in, a bulk run, a scheduled claim) ends as a failure.
    runHostUntilExit(alts);
}
// The files are released: another runtime may now open the same directory.
```

`close()` writes both stores' pending changes, releases their locks, closes the proxy tunnels and drops the vault's host tokens, and shuts down the executor if the runtime created it; an executor you passed in is left running. It is idempotent. Afterwards the stores write nothing (a mutator changes memory only and reports "the store is closed" on `saveError()`), every request is refused, and whatever was waiting on the runtime (a bulk run paced between entries, a device-code sign-in between polls, a scheduled name claim, a browser sign-in waiting for its callback) ends as a failure. A sign-in, a check or a refresh started afterwards returns a result whose failure is `CANCELLED`, a bulk run reports its unfinished entries as `CANCELLED`, and an account-service call throws `AltsException` of kind `CANCELLED`. The failures of what was waiting run on the thread that calls `close()`, continuations you attached included, so do not block in one on something only `close()` would release. A host that never closes the runtime loses nothing on a normal exit: a shutdown hook flushes the stores. Call `flush()` on both stores yourself before exiting by a route that skips shutdown hooks. Compiled as `GettingStartedExample.runUntilShutdown`.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the internals and [SECURITY.md](../SECURITY.md) for the threat model.

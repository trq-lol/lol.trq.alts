# Accounts

Nothing on this page changes the live session.

## Check and refresh

- **`check(account)`** asks whether the token still works and changes nothing.
- **`refresh(account)`** also renews it, and saves the new token.

```java
// check() only looks: no refresh token is redeemed, so nothing rotates. For more than a handful of
// accounts, alts.bulk().checkAll(...) runs the same check paced, with progress and a cancel handle.
for (AltAccount account : alts.store().accounts()) {
    alts.accountService().check(account).thenAccept(status -> {
        switch (status.state()) {
            // Nothing to do; the account is good as it is.
            case VALID -> render(status.account().username());
            // The stored token is spent but a refresh token is held: refresh(account) renews it,
            // when the host decides to.
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

Use `check` when you only want to look: each refresh replaces the refresh token. `NOT_ENTITLED` also covers an account
that Xbox Live refused (kind `XBOX_DENIED`).

## Bulk runs

`alts.bulk()` adds pacing, retries, progress and cancelling.

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

| Method | What it does |
|---|---|
| `checkAll` | asks whether each stored token still works; renews nothing |
| `refreshAll` | that, and renews the spent ones, persisting each rotation |
| `entitlementsAll` | reads what each account owns; the product set is on `BulkEntryResult.entitlements()` |
| `importCredentials` | resolves a pasted list into accounts, storing them with `LoginMode.ADD` |

The defaults are four at a time, a quarter second apart, with two retries.

- **A rate limit ends the run**, and `report.stoppedEarly()` says so. With `withoutStoppingOnRateLimit()` the run waits
  and continues.
- **Only network failures are retried.**
- **Cancelling** stops new entries. Those in flight finish.
- **Every entry is in the report**; a run cut short marks the rest `CANCELLED`.
- **`entitlementsAll` does not renew.** An expired token fails with `UNAUTHORIZED`, so run `refreshAll` first.
- Spacing is for the whole run, not per proxy.

Import a pasted list:

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

A label is a username or `entry 4`, never the line itself. `CredentialKind.detect(line)` shows what a line will be
imported as. A line it cannot place fails with `INVALID_INPUT`.

## Manage an account

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

Reads throw `AltsException`; switch on `e.kind()`. A name change returns a `NameChangeResult` and a profile creation a
`ProfileCreationResult`, because a refusal there is normal. These calls block, so keep them off your main thread.

A skin must be a PNG of 64x64 or 64x32 pixels, at most `SkinService.MAX_SKIN_BYTES`. `skin().validate(bytes)` says why
a file would be refused, without sending it.

### Bans and permissions

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

These are the platform's bans, not those of a single server.

### Claim a name

`claimAt` makes a bounded burst of attempts around a known time and stops at the first success.

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

You supply the time. A rate limit ends the run, and cancelling the future stops it. To correct the clock, pass an
`NtpTimeSource` in `ClaimOptions` and call its blocking `sync()` first.

## Look up players

No account needed.

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

`byUuid` takes a UUID with or without dashes. An impossible name returns empty without a request. A rate limit fails the
whole list.

## Avatars

`alts.skinCache().get(uuid)` returns your texture handle, or `null` while it loads. Key it on the UUID, because names
change. `invalidate(uuid)` drops an entry and returns the old handle so you can free it.

Faces come from Mojang by default, so no third party sees your account list. To use a render service instead, set:

```java
.avatarUrlTemplate("https://example.net/avatar/{uuid}/{size}.png")
```

That sends each UUID to the service. A template without `{uuid}`, or one combined with an `avatarSource`, fails
`build()`.

## Game stats

Implement one source per server. The library caches the result and does not interpret it.

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

Register it with `.gameStatsSource(...)`, then read it back:

```java
GameStats stats = alts.gameStats("example.net").get(playerUuid);
if (stats != null) {
    for (GameStats.Stat chip : stats.stats()) {
        render(chip.label() + " " + chip.value());
    }
}
```

`fetch` may block. `StaticGameStatsSource` returns fixed values for tests.

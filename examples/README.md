# Examples

Illustrative, dependency-free samples. They are compiled by the `examples` Gradle source set (so they
cannot drift from the library API) but are not part of the published jar.

## `GettingStartedExample`

The compiled companion to the guides in [`../docs/`](../docs/GETTING_STARTED.md). The snippets they show
are methods here:

- `buildRuntime`, `warnIfTheStoreDidNotLoad`, `startOverWithoutTheOldFile`: wiring the seams, reporting a
  store that could not be read, and giving up on it with `discardUnreadable()` once the user says so.
- `buildRuntimeWithHostKey`: sealing the stores under a host-supplied key, with the one-launch migration opt-in.
- `runUntilShutdown`: closing the runtime with try-with-resources, which releases its store files.
- `logInAndRead`, `logInWithDeviceCode`, `logInFromCookieFile`: browser, device-code and cookie-file sign-in.
- `logInStoredAccount`, `importRefreshToken`, `logInStoredAccountWithBranching`: silent renewal, refresh-token
  import, and branching on the failure's kind, rate limits included.
- `proxyPerAccount`: one proxy route per account.
- `sweepStoredAccounts`, `refreshEverything`, `importPastedCredentials`: checking and renewing accounts
  without logging in, singly and in bulk.
- `manageAccount`, `readAttributes`, `claimAtDrop`: profile, entitlements, name change, player attributes
  and bans, and a scheduled name claim.
- `lookUpPlayers`: anonymous lookup by name and by list, with the rate-limit branch.
- `importLegacyRepository`, `shareRefreshTokens`: reading the accounts of a 0.4 repository with the
  read-only importer, and turning refresh-token sharing on for an AVP 0.5 repository.
- `readGameStats`: reading one server's stat chips.

The file is compiled with `-Xlint:deprecation -Werror`, so it cannot use deprecated API.

## `SharedVaultExample`

The AVP 0.5 shared vault end to end: `createRepository` (a first contact whose host key the user
confirms out of band before anything is created, the owner key kept as its entropy, the snapshot in the
host secrets), `requestInvite` and `join` on the joiner's side, `invite` on the owner's after comparing
fingerprints, `resumeOwner` (the owner key and the snapshot back out of the host secrets), and
`shareAndSync`, which resumes from the snapshot, shares an account, renews another with `update` (which
never reverts a field another member changed), syncs and acts on the report. Compiled the same way, and
inlined into the [vault guide](../docs/VAULT.md).

Both files are the authoritative copy; the guides inline from them. Change the library API and the
build breaks here, which is the point: markdown alone rots silently. Keep the two in step when either
moves. Spotless formats this directory too, so a snippet pasted into the guide is already house-styled.

## `ExampleNetGameStatsSource`

A minimal [`GameStatsSource`](https://github.com/trq-lol/lol.trq.alts/blob/main/src/main/java/lol/trq/alts/spi/GameStatsSource.java) for a fictional
`example.net` server. It shows the whole shape of the feature: a source reports a `serverId` and returns
ready-to-render `GameStats.Stat` chips; the library only caches them.

Wire it and read it back:

```java
AltsRuntime<MyHandle> alts = new AltsRuntime.Builder<MyHandle>()
        .sessionInjector(...)
        .vaultDirectory(...)
        .mainThread(...)
        .toastSink(...)
        .gameStatsSource(new ExampleNetGameStatsSource())   // one per server; call again for more
        .build();

// uuid -> stats for example.net (null on the first call while the background fetch runs,
// then the chips on a later call; unknown server ids return null forever).
GameStats stats = alts.gameStats("example.net").get(playerUuid);
if (stats != null) {
    for (GameStats.Stat chip : stats.stats()) {
        render(chip.label(), chip.value());   // e.g. "rank Veteran", "wins 128"
    }
}
```

For a static, in-memory source (handy for tests and demos), use the shipped
[`StaticGameStatsSource`](https://github.com/trq-lol/lol.trq.alts/blob/main/src/main/java/lol/trq/alts/spi/StaticGameStatsSource.java):

```java
var source = new StaticGameStatsSource(
        "example.net",
        Map.of(playerUuid, List.of(new GameStats.Stat("rank", "Veteran"))));
```

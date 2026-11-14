# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Migrating from 0.12

1.0.0 freezes the API, and it does so in one release: every form it replaces is removed outright, with
no deprecated bridge and no transitional release in which both work. This section is the whole route
from 0.12.0, name by name; the sections after it give the detail of each change.

**The runtime owns its state.** Nothing is process-wide any more: each `AltsRuntime` builds its own
stores, transport and executor.

| 0.12 | 1.0 |
| --- | --- |
| `AltStore.accounts()`, `AltStore.addAccount(a)`, and every other `AltStore` call | the same call on `alts.store()` (an `AccountStore`) |
| every `SecretStore` call | the same call on `alts.secrets()` (a `HostSecrets`) |
| `AltStore.bind`, `configure`, `keyProvider`, `writeDelay`, and the same on `SecretStore` | none: the builder sets the directory, file names, key bindings and key provider, and a runtime always coalesces writes (100 ms) |
| `AltStore.DEFAULT_WRITE_DELAY` | none |
| `HttpUtil` (and `bind`), `IoExecutor` | none: set `proxyProvider` and `executor` on the builder |
| `AltsToasts.success`, `failure`, `info`, `removed` | `alts.toasts().toast(level, title, description, durationMs)` (see Removed for each mapping) |
| `AccountServices.of(...)` | `alts.accountServices(account)` or `alts.accountServices(token, uuid)` |
| `ProfileLookupService.create(...)` | `alts.profileLookup()`; another base with `Builder#accountEndpoints` |
| `new SkinAvatarCache<>(...)` | `alts.skinCache()` |
| `new UrlTemplateAvatarSource(t)` passed to `avatarSource` | `Builder#avatarUrlTemplate(t)` |
| `new MojangAvatarSource(...)` | nothing: it is the default |
| `new AsyncCache<>(loader, ...)` | `new AsyncCache<>(executor, loader, ...)` |
| `new NtpTimeSource(...)` | `new NtpTimeSource(executor, ...)` |
| a runtime left open for the process | close it (`try (AltsRuntime<H> alts = ...)` or `alts.close()`); a shutdown hook still flushes if you do not |

**One error model.** Every failure is an `AltsFailure`, thrown as an `AltsException` where it is not
part of a result. The [Error kinds](#error-kinds) table below maps every former constant to its kind.

| 0.12 | 1.0 |
| --- | --- |
| `AltLoginCallback.LoginResult` | `auth.LoginResult(account, failure)` |
| `AltLoginCallback`, `AltLoginCallback.FailureReason` | none; `result.reason()` becomes `result.failure().map(AltsFailure::kind)` |
| `LoginResult.retryAfter()`, `xstsError()` | `failure().flatMap(AltsFailure::retryAfter)`, `failure().flatMap(AltsFailure::xstsError)` |
| `LoginResult.failure(String)`, `failure(String, FailureReason, ...)`, `rateLimited()` | `LoginResult.failure(AltsFailure)`, `LoginResult.failure(Kind, String)` |
| `AccountStatus.reason()`, `rateLimited()`, `retryAfter()` | `AccountStatus.failure()`; `state()` is unchanged |
| `catch (AccountException e)` and `e.status()`, `tokenRefused()`, `rateLimited()`, `notFound()`, `retryAfter()` | `catch (AltsException e)` and `e.kind()`, `e.failure().retryAfter()` |
| `SkinValidationException` and its `Reason` | `SkinService.validate(bytes)` returning a `SkinProblem` (same constants); an upload throws `AltsException` of kind `INVALID_INPUT` |
| `CryptoException`, `VaultException` | `AltsException` of kind `CRYPTO`, `INVALID_INPUT` or `PROTOCOL` |
| `CookieFile.read`'s `IOException` | `AltsException` of kind `INVALID_INPUT` |
| `PlayerCertificate.privateKey()`, `publicKey()` throwing `GeneralSecurityException` | the same calls, throwing `AltsException`: `INVALID_INPUT` for an absent or non-Base64 PEM, `CRYPTO` for one that decodes to no RSA key; drop the `catch (GeneralSecurityException e)` |
| `NameChangeResult` and `ProfileCreationResult` outcomes `NOT_ENTITLED`, `UNAUTHORIZED`, `RATE_LIMITED` | `FAILED`, with the kind on `failure()` |
| `ClaimResult.StopReason.RATE_LIMITED`, `UNKNOWN`; `ClaimResult.rateLimited()` | `TERMINAL_FAILURE`, with the kind on `failure()` |
| `new ClaimResult(claimed, attempts, finalResult)`, `new ClaimResult(claimed, attempts, finalResult, stopReason)` | `new ClaimResult(claimed, attempts, finalResult, stopReason, failure)` |
| `BulkEntryResult.reason()` | `BulkEntryResult.failure()` |
| `BulkEntryResult.failure(index, label, FailureReason, message, attempts)` | `BulkEntryResult.failure(index, label, AltsFailure, attempts)` |
| store `loadError()`, `saveError()`, `loadWarning()` strings | `Optional<AltsFailure>` of kind `STORAGE` |

**Value types that may grow are classes.** Six records of 0.12 are final classes (and the new
`AltsFailure` is one too), so a later field is an addition and not a break. Accessors,
`equals`/`hashCode` over the same fields, the redacted `toString` where there was one, and every `withX`
method are unchanged; the public canonical constructors are gone, and so are deconstruction patterns
over them.

| 0.12 | 1.0 |
| --- | --- |
| `new AltAccount(uuid, username, accessToken, type, lastUsed, lastUsedBy, bans, sourceClient, sourceUser, refreshToken, expiresAt)` | `AltAccount.builder(uuid, username, accessToken, type).lastUsed(..).lastUsedBy(..).bans(..).sourceClient(..).sourceUser(..).refreshToken(..).expiresAt(..).build()` (each setter optional), or `account.toBuilder()` to change several fields; the store file format is unchanged |
| `new MicrosoftAuthConfig(...)` (thirteen or eleven arguments) | `MicrosoftAuthConfig.of(clientId)` or `legacyMsa(clientId)`, then `withScope`, `withRedirectPath`, `withEndpoints`, `withDeviceCodeEndpoints`, and the new `withRedirectUri` and `withRpsTicketPrefix` |
| `new NetworkScope(purpose, uuid, username)`, `new NetworkScope(purpose, uuid, username, routeTag)` | `NetworkScope.of(purpose)` or `NetworkScope.forAccount(purpose, uuid, username)`, then `withRouteTag(tag)` |
| `new BulkOptions(concurrency, minSpacing, maxRetries, retryBaseDelay, stopOnRateLimit)` | `BulkOptions.of(concurrency, minSpacing, maxRetries, retryBaseDelay, stopOnRateLimit)`, or `BulkOptions.defaults()` and the `withX` methods; a route tag with `withRouteTag(tag)` |
| `new ClaimOptions(leadTime, window, attemptSpacing, concurrency, timeSource)` | `ClaimOptions.of(leadTime, window, attemptSpacing, concurrency, timeSource)`, or `ClaimOptions.defaults()` and `withTimeSource` |
| `new BulkEntryResult(...)` | `BulkEntryResult.success(index, account, message, attempts)`, `success(index, account, entitlements, message, attempts)` or `failure(index, label, failure, attempts)` |

**The shared vault: 0.4 to AVP 0.5.** 1.0 writes AVP 0.5 only, which is not wire compatible with 0.4
and specifies no upgrade. A repository moves in five steps:

1. Get the repository's manifest and envelope JSON: export them while the host still runs 0.12, or
   fetch them from the 0.4 server with your own HTTP client, authenticating with
   `VaultIdentity.signChallenge`.
2. Read them with `LegacyVaultReader.read(manifestJson, envelopeJson, identity)`, which returns the
   accounts and writes nothing. Review them: 0.4 signed nothing, and the import has no rollback floor.
3. The owner creates a new repository: `OwnerIdentity.generate()` (keep its entropy in
   `HostSecrets`, or have the owner write the phrase down), `alts.vault().connectFirstContact(host)`
   and then `SharedVault.create(host, owner)`, and `put`s the accounts they choose.
4. Each member joins again: the joiner calls `SharedVault.prepareJoin` with the repo locator the
   owner sent and returns the invite token, the owner calls `invite`, and the joiner calls `join`.
5. Persist each copy's `VaultSnapshot` (`toJson()`, encrypted, for example in `HostSecrets`) and
   resume with `SharedVault.resume` on the next run.

| 0.12 | 1.0 |
| --- | --- |
| `SharedVault`'s 0.4 constructors and `createRepo`, `openRepo`, `addMember`, `encryptPayload`, `decryptPayload`, `rotateKey`, `removeMember` | `SharedVault.create`, `open`, `prepareJoin`, `join`, `resume`, then `accounts`, `update`, `put`, `removeAccount`, `invite`, `removeMember`, `sync` and the rest |
| `KeyBindingVerifier`, `IssuerSignedKeyBindingVerifier` | none: the owner-signed chain and invite tokens replace key binding |
| `RepoPin`, `RepoContext` | the pin lives in `VaultSnapshot` |
| `MemberPublicKey` (a prospective member's two public keys, passed to `addMember`, `rotateKey`, `removeMember`) | none: a joiner's keys reach the owner inside the `InviteToken` it returns from `SharedVault.prepareJoin`, and the roster lists members as `VaultMember`s (`roster()`, `removeMember(member)`) |
| `VaultTransport` and the `vault.transport` DTOs | none: `alts.vault()` speaks AVP 0.5 over the runtime's transport |
| `vault.federation.RepoAddress`, `InviteRequest`, `RepoLocator` | `vault.RepoLocator`, `vault.InviteToken` |
| `VaultTransportResolver`, `Builder#vaultTransportResolver`, `AltsRuntime.vaultTransportResolver()` | `alts.vault()`, and `Builder#vaultHostAddress` to map a host locator to a URL |
| `crypto.VaultIdentity`, `crypto.WrappedIdentity`, `crypto.RecoveryCode` | the same types in `lol.trq.alts.vault` (change the import; a stored identity still opens) |
| `VaultIdentity.keyAgreementPrivateKey()`, `RecoveryCode.deriveKey` | none: the library unwraps inside itself |
| `crypto.KeyWrapScheme`, `X25519HkdfAesGcmKeyWrap`, `RepoDataKey`, `WrappedKey`, `Hkdf` | none |

**Moved or removed packages.** The `crypto` package is gone: its primitives are internal, and the
identity types are in `vault` (above). The `format` package and `AltManagerFormatting` are removed (the
code to copy is under Removed). The implementation (`HttpUtil`'s successor `HttpTransport`,
`FailureText`, `MicrosoftAuthUtil`, `CookieAuthUtil`, `AccountNetworkUtil`, `TokenExpiry`,
`MinecraftProfile`, the `*Impl` classes, `EncryptionUtil`, `MicrosoftCallbackServer`, ...) is under
`lol.trq.alts.internal`, outside the API; the table under Removed says what a host uses instead of each.

**The build and the module.**

- Gson is an ordinary `api` dependency now and arrives transitively; a host no longer has to put it on
  its runtime class path. One that ships its own Gson resolves the version as for any dependency.
- The jar is the named module `lol.trq.alts`, with a `module-info.java` in place of the
  `Automatic-Module-Name` (the name is unchanged). A consumer module says `requires lol.trq.alts;` and
  reads Gson through it. Only the API packages are exported.
- The jar is sealed: on the class path, a class of yours placed in a `lol.trq.alts` package no longer
  loads beside the library's.

**Behaviour a host should know about.**

- **The store fails closed after any failed load.** A file that exists and did not open, for whatever
  reason, refuses every write until a load succeeds or the host calls `discardUnreadable()`; before,
  only a missing key held writes back. The copy aside is made when the load fails.
- **A store file has one owner.** Each store holds a lock on `<file>.lock`, so two runtimes on one
  directory, in one process or two, can no longer both build; the second fails with `CONFLICT`, and a
  directory that cannot be created or locked fails `build()` with `STORAGE`. The lock is new in 1.0.
- **Everything is per runtime.** A runtime built without a proxy provider connects directly, whatever
  another runtime was given; its store key provider and executor reach its own stores and tasks only.
- **Route tags.** `NetworkScope` and `BulkOptions` gain `routeTag()` (both are classes now, see
  above). `AltLoginService.routed(tag)` is new and abstract, so a host's own implementation of the
  interface must add it.
- **`close()` ends what waits.** A paced bulk run, a device-code poll, a scheduled claim and a browser
  sign-in still waiting for its callback fail when the runtime closes; anything started afterwards
  returns or throws `CANCELLED`.
- **Messages are the library's own.** A service's error text and what the host's session injector threw
  are no longer repeated in a failure message. Branch on the kind.
- **Headers.** A caller-supplied `Proxy-Authorization` header is refused before anything is sent.
- **`VaultIdentity.signChallenge`** refuses input that begins with `avp/` or is shorter than 16 or
  longer than 1024 bytes.
- **The default loopback redirect path is new.** `MicrosoftAuthConfig.DEFAULT_REDIRECT_PATH` names no
  product. A host whose Azure app registration lists the 0.12 default path, and relied on the default,
  passes that path explicitly with `withRedirectPath(path)` (read it from the registration's redirect
  URIs), or adds the new default to the registration.

### Error kinds

Every former reason, outcome and exception case, and the kind it becomes. *kept* means the constant is
still there and carries no failure of its own (`FAILED` and `TERMINAL_FAILURE` carry the failure that
says the kind); *none* means success, so `failure()` is empty.

| Former | Kind | Notes |
| --- | --- | --- |
| `FailureReason.NONE` | none | |
| `FailureReason.UNKNOWN` | `UNKNOWN` | |
| `FailureReason.REAUTH_REQUIRED` | `REAUTH_REQUIRED` | The credential is spent and was discarded. |
| `FailureReason.INVALID_TOKEN` | `UNAUTHORIZED` | Empty, malformed or refused; a refresh token may still renew. Where nothing was sent because the input is no credential at all (an offline name that is not a name, a bulk line of no known form), `INVALID_INPUT`. A `403` from the Minecraft services Xbox login, which refuses the host's client registration, is `NOT_CONFIGURED`. |
| `FailureReason.NETWORK` | `NETWORK` | |
| `FailureReason.NOT_CONFIGURED` | `NOT_CONFIGURED` | A missing `DeviceCodePrompt` argument is `INVALID_INPUT`. |
| `FailureReason.NOT_ENTITLED` | `NOT_ENTITLED` | |
| `FailureReason.RATE_LIMITED` | `RATE_LIMITED` | The wait is `failure().retryAfter()`. |
| `FailureReason.XBOX_DENIED` | `XBOX_DENIED` | The reason is `failure().xstsError()`. |
| `FailureReason.DECLINED` | `DECLINED` | |
| `FailureReason.TIMED_OUT` | `TIMED_OUT` | |
| `AccountException.tokenRefused()` | `UNAUTHORIZED` | Status 401 or 403. |
| `AccountException.notFound()` | `NOT_FOUND` | Status 404 on any call but the profile read. |
| `AccountException.notFound()` from `ProfileService.fetch` | `NOT_ENTITLED` | No Minecraft profile, as sign-in and check say; `fetchIfPresent()` is still empty. |
| `AccountException.rateLimited()` | `RATE_LIMITED` | Status 429, with its wait. |
| `AccountException` status 5xx or 408 | `NETWORK` | |
| `AccountException` status 400 or 422 | `INVALID_INPUT` | |
| `AccountException` status 409 | `CONFLICT` | |
| `AccountException` another status | `UNKNOWN` | |
| `AccountException` status 0, unreachable | `NETWORK` | `CANCELLED` once the runtime is closed. |
| `AccountException` status 0, unreadable answer | `PROTOCOL` | |
| `XstsAuthException` | `XBOX_DENIED` | |
| `RefreshRejectedException.permanent()` | `REAUTH_REQUIRED` | A stated `invalid_grant` only. |
| `RefreshRejectedException.rateLimited()` | `RATE_LIMITED` | |
| `RefreshRejectedException`, an outage | `NETWORK` | Status 5xx or 408, or unreachable. |
| `RefreshRejectedException`, another refusal | `UNAUTHORIZED` | Was `NETWORK`; the stored token is kept. |
| `RefreshRejectedException`, `invalid_client` or `unauthorized_client` | `NOT_CONFIGURED` | The host's client registration was refused; the token is kept. |
| `SkinValidationException.Reason.UNREADABLE` | `INVALID_INPUT` | `SkinProblem.UNREADABLE` |
| `SkinValidationException.Reason.EMPTY` | `INVALID_INPUT` | `SkinProblem.EMPTY` |
| `SkinValidationException.Reason.TOO_LARGE` | `INVALID_INPUT` | `SkinProblem.TOO_LARGE` |
| `SkinValidationException.Reason.NOT_PNG` | `INVALID_INPUT` | `SkinProblem.NOT_PNG` |
| `SkinValidationException.Reason.WRONG_DIMENSIONS` | `INVALID_INPUT` | `SkinProblem.WRONG_DIMENSIONS` |
| `NameChangeResult.Outcome.CHANGED` | kept | |
| `NameChangeResult.Outcome.INVALID_NAME` | kept | |
| `NameChangeResult.Outcome.UNAVAILABLE` | kept | |
| `NameChangeResult.Outcome.NOT_ENTITLED` | `NOT_ENTITLED` | Now `FAILED`. |
| `NameChangeResult.Outcome.UNAUTHORIZED` | `UNAUTHORIZED` | Now `FAILED`. |
| `NameChangeResult.Outcome.RATE_LIMITED` | `RATE_LIMITED` | Now `FAILED`, with its wait. |
| `NameChangeResult.Outcome.FAILED` | kept | Its failure carries the kind. |
| `ProfileCreationResult.Outcome.CREATED` | kept | |
| `ProfileCreationResult.Outcome.INVALID_NAME` | kept | |
| `ProfileCreationResult.Outcome.DUPLICATE` | kept | |
| `ProfileCreationResult.Outcome.NOT_ALLOWED` | kept | |
| `ProfileCreationResult.Outcome.NOT_ENTITLED` | `NOT_ENTITLED` | Now `FAILED`. |
| `ProfileCreationResult.Outcome.UNAUTHORIZED` | `UNAUTHORIZED` | Now `FAILED`. |
| `ProfileCreationResult.Outcome.RATE_LIMITED` | `RATE_LIMITED` | Now `FAILED`, with its wait. |
| `ProfileCreationResult.Outcome.FAILED` | kept | Its failure carries the kind. |
| `ClaimResult.StopReason.CLAIMED` | kept | |
| `ClaimResult.StopReason.WINDOW_ELAPSED` | kept | |
| `ClaimResult.StopReason.RATE_LIMITED` | `RATE_LIMITED` | Now `TERMINAL_FAILURE`, with its wait. |
| `ClaimResult.StopReason.TERMINAL_FAILURE` | kept | Its failure carries the kind. |
| `ClaimResult.StopReason.CANCELLED` | kept | |
| `ClaimResult.StopReason.UNKNOWN` | `UNKNOWN` | Now `TERMINAL_FAILURE`. |
| Store `loadError()`, `saveError()`, `loadWarning()` strings | `STORAGE` | |
| `CookieFile.read`'s `IOException` | `INVALID_INPUT` | A sign-in from the file still reports `UNAUTHORIZED`. |
| `CryptoException`, a wrong passphrase or recovery code | `CRYPTO` | From `VaultIdentity.unlock` and `unlockWithRecovery`; also a tampered sealing, or stored public keys that do not match the private material. |
| `CryptoException`, a malformed stored identity | `INVALID_INPUT` | A missing or non-Base64 field, a key or sealing of the wrong length, an iteration count out of range, a missing passphrase, no recovery sealing. `WrappedIdentity`'s constructor reports a missing field the same way, where it threw `NullPointerException`. |
| `CryptoException`, another failed key operation | `CRYPTO` | Key generation, sealing, signing. A 0.4 data key that does not unwrap or a payload that does not authenticate, now from `LegacyVaultReader`. |
| `VaultException` | `PROTOCOL` | Only the 0.4 vault threw it; `LegacyVaultReader` makes the same checks and reports them as `PROTOCOL`. |

An `AuthFlowException` becomes the kind of the `FailureReason` it carried, as in the rows above.

### Added

- **One error model.** `lol.trq.alts.AltsFailure` is the one value that describes a failure anywhere in
  the library (a final class, built by `of`, `rateLimited` and `xboxDenied`, so it can gain a field in a
  1.x release): a `kind()` to branch on, a `message()` the library builds (never a transport exception's
  text, a token or a path), an `Optional<Duration> retryAfter()`, an `Optional<XstsError> xstsError()`
  (present only on `XBOX_DENIED`), and `Optional<Instant> retryAt()`, the instant a stated wait ends
  (present exactly when `retryAfter` is). `retryable()` honours a stated wait for every retryable kind:
  with `retryAt` present, `NETWORK` and `RATE_LIMITED` are retryable once it has passed; without one,
  `NETWORK` is retryable and `RATE_LIMITED` is not; no other kind is retryable. A failure with no stated
  wait records no time, so equality does not depend on when it was made. `AltsFailure.Kind` is one enum
  for the whole library: `NETWORK`, `RATE_LIMITED`, `UNAUTHORIZED`, `REAUTH_REQUIRED`, `NOT_ENTITLED`,
  `NOT_FOUND`, `XBOX_DENIED`, `DECLINED`, `TIMED_OUT`, `CANCELLED`, `INVALID_INPUT`, `CONFLICT`,
  `NOT_CONFIGURED`, `STORAGE`, `CRYPTO`, `PROTOCOL`, `UNKNOWN`. `lol.trq.alts.AltsException` (unchecked)
  carries one in `failure()`, and is the only exception a library future completes with exceptionally.
- `account.SkinProblem` (`UNREADABLE`, `EMPTY`, `TOO_LARGE`, `NOT_PNG`, `WRONG_DIMENSIONS`) and
  `SkinService.validate(byte[])`, which says why bytes are not an uploadable skin without sending
  anything.
- **The shared vault speaks AVP 0.5** (the "0.5 (draft)" specification of the Alt Vault Protocol), in
  `lol.trq.alts.vault`. A repository has an owner, whose keys come from a 24-word BIP39 phrase
  (`OwnerIdentity`: `generate`, `fromPhrase`, `fromEntropy`, `phrase`, `entropy`); every change to the
  members, the refresh-token policy or the hosts is a state the owner signs, and every write is a
  commit a member signs. The client verifies all of it itself, from genesis, and trusts no host:
  - `alts.vault()` returns `VaultHosts`, which connects to a host on the runtime's transport (its proxy,
    timeouts and executor) by the host's key. `connect` takes a `RepoLocator`, a `HostRef`, a
    `VaultSnapshot` or a locator and key, and refuses a host that serves another key with `PROTOCOL`;
    `connectFirstContact(locator)` takes whatever key the host serves, which is then unverified: compare
    it out of band, persist `VaultHost.ref()` and reconnect with `connect(HostRef)`. A locator is
    reached at `https://<locator>` unless `Builder#vaultHostAddress` maps it elsewhere. Each runtime
    keeps its own host tokens, and `close()` drops them.
  - `SharedVault.create`, `open`, `prepareJoin`, `join` and `resume` give one member device's copy.
    `sync()` returns a `SyncReport`: the new states, a diverged owner chain the tie rule settled
    (`divergedAt`), a policy that turned to sharing (`policyTurnedOn`), the unreadable and discarded
    heads, and the pending leave requests. `openReport()` says the same of the pull that opened the copy.
  - The accounts are `AltAccount`s with `BanInfo` per server id: `accounts()`, `account(uuid)`,
    `update(uuid, edit)`, `put(base, edited)`, `put(account)`, `removeAccount(uuid)`, `markBanned`.
    `update` is the way to change an account: it edits the account as the copy holds it when the write runs and
    stamps only the fields the edit changed, so a field another member changed is never reverted.
    `put(base, edited)` stamps only the fields where the two differ, for an edit of an account read
    earlier. `put(account)` stamps the fields that differ from the copy as it stands when the write
    runs, so a stale object can revert remote edits; use `update`. A removed account put again is
    written whole, and drops the bans it held before its removal that it does not carry now. A write
    that changes nothing sends no commit. While the repository withholds refresh tokens,
    `refreshToken` and `expiresAt` are neither sent nor read. Nothing the vault reads is saved to the
    `AccountStore`.
  - The owner invites from a pasted `InviteToken`, removes a `VaultMember` from `roster()` with
    `removeMember` (the data key rotates), sets the policy with `setShareRefreshTokens`, and removes
    leaving members with `processLeaves()`; a member can `leave()`. `hosts()` lists the repository's hosts.
  - `LinkSession` adds a second owner device without typing the phrase, after the owner confirms a
    6-digit code on both devices.
  - `RepoLocator`, `InviteToken`, `LinkRequest` and `LinkGrant` read pasted text, whitespace anywhere
    ignored, and refuse anything else with `INVALID_INPUT`.
  - `VaultSnapshot` is what a host persists between runs, as JSON, encrypted (for example in
    `HostSecrets`): the pin a rollback must not go below, the retained data keys, the clock and the
    merged accounts. Its `toString` shows no key and no account.
  - A host that serves a forged state or rolls the repository back fails the whole operation with
    `PROTOCOL`, and the pull that met it adopts nothing of what the host served (the reference client
    keeps the valid prefix instead). Every vault
    future fails only with an `AltsException`. No request carries the phrase, its entropy or seed, a
    private key, a data key or a plaintext account field.
  - A member that signs a stamp at the largest value there is (`at` and `n` both `Long.MAX_VALUE`)
    leaves no greater stamp to write: every account write of a member that merged it fails with
    `PROTOCOL`, and the message says that the protocol cannot undo it and that the only way out is a
    new repository (SECURITY.md).
  - Two registers with equal stamps and different values, which no conformant writer produces and
    whose merge SPEC 5 leaves implementation-defined, merge to the one whose value has the greater
    compact JSON encoding, compared as unsigned bytes, so the merge gives the same result in any order.
  - A host that answers `422 missing_parents` (it is still fetching from its peers) is asked again,
    up to 40 times, 100 ms apart. The pause is a wait on the runtime, so a `close()` during it ends the
    operation at once with `CANCELLED` instead of leaving it to run out its retries.
- `VaultIdentity.fingerprint()`, the member fingerprint an owner compares with an invite token's.
- `vault.LegacyVaultReader`, the one way to read a repository of the 0.4 vault, which 1.0 no longer
  speaks: `read(manifestJson, envelopeJson, identity)` takes the manifest and envelope as the 0.4 host
  wrote them (the JSON is parsed strictly) and the member's `VaultIdentity`, and returns the accounts.
  It never writes, never talks to a host and keeps nothing; it accepts what a 0.12 member could read
  (the `X25519-HKDF-SHA256-AESGCM-v1` wrap, the member listed at the manifest's key epoch, an envelope
  of the same repository and epoch, no older than the manifest, authenticated under the 0.4 AAD) and
  strips `refreshToken` and `expiresAt` while the manifest withholds them. It has no rollback floor:
  an import is one read, with no earlier state to compare, so it proves nothing a 0.4 host could not
  have forged. Text that is not strict JSON is `INVALID_INPUT`, a document that is not the 0.4 shape
  or a member not listed is `PROTOCOL`, a key that does not unwrap or a payload that does not
  authenticate is `CRYPTO`, and every message starts "Vault 0.4 import: ". The owner then creates an
  AVP 0.5 repository with the accounts they choose.
- **A module descriptor.** The jar is the named module `lol.trq.alts`. It exports `lol.trq.alts` and its
  `account`, `auth`, `bulk`, `cache`, `model`, `net`, `skin`, `spi`, `store`, `time` and `vault`
  packages, and nothing under `lol.trq.alts.internal`; it `requires transitive com.google.gson`, and
  requires `java.desktop` and `jdk.httpserver`, which the browser sign-in and the default avatar source
  already used. The descriptor records the release (`lol.trq.alts@1.0.0`). On the module path a host
  reads only the exported packages. On the class path nothing changes for a host that kept to the API.
- **A compatibility gate.** `api/lol.trq.alts.api` is the committed dump of the exported API, and the
  build's `apiCheck` fails a change that removes or alters any of it outside a new major version, so the
  1.x surface stays what 1.0.0 promises. Internal packages are outside it.
- **Three more Xbox Live refusals decoded.** `XstsError` gains `ACCOUNT_BANNED` (`XErr` 2148916227),
  `ACCOUNT_RESTRICTED` (2148916229) and `TERMS_NOT_ACCEPTED` (2148916234), named for what each code
  is commonly observed to mean (Xbox Live does not guarantee it). Each still arrives as
  `XBOX_DENIED`; before, they were `XstsError.UNKNOWN`. A host switching over `XstsError` without a
  `default` places them.
- **`HostSecrets.find(key)`** returns the secret as an `Optional<String>`, empty when there is none.
  `get(key)` still returns it or `null`.

### Changed

- **Breaking: `AltAccount` is a final class.** It was a record; its accessors, value equality, redacted
  `toString` and copy methods are kept, and `builder(...)`, `toBuilder()` and `AltAccount.Builder` replace
  the canonical constructor. The stores read and write it through an internal record with the same
  components under the same names and in the same order, so an account file written by 0.12 loads and is
  written back byte for byte (pinned by a fixture captured from 0.12.0). No final field is set by
  reflection, and `lol.trq.alts.model` is not opened to Gson. A host's own Gson therefore cannot read or
  write an `AltAccount` on the module path, and on the class path only by setting final fields through
  reflection: a host that persists accounts itself goes through the accessors and the builder.
- **Breaking: the default loopback redirect path changed.** `MicrosoftAuthConfig.DEFAULT_REDIRECT_PATH`
  is now `/lol_trq_alts_loopback_redirect_long_enough_to_avoid_accidental_leaks_on_screenshare`, a neutral
  path, still long to reduce accidental exposure on a shared screen. The
  browser sign-in listens on it unless `withRedirectPath` says otherwise; see Migrating from 0.12.
- **Breaking: each runtime owns its stores.** `AltsRuntime` now constructs and owns an
  `AccountStore` (`alts.store()`) and a `HostSecrets` (`alts.secrets()`) of its own, instead of binding
  process-wide statics. Every operation keeps its name and its rules: `AltStore.accounts()` becomes
  `alts.store().accounts()`, `AltStore.addAccount(a)` becomes `alts.store().addAccount(a)`, and each
  `SecretStore` call becomes the same call on `alts.secrets()`. `loadError()`, `loadWarning()` and
  `saveError()` return `Optional<AltsFailure>` (see the error model below). Two runtimes in one
  process, on two directories, no longer share accounts, secrets, a store key or a write delay.
- **Breaking: `AltsRuntime` is `AutoCloseable`.** `close()` writes what the stores still hold, releases
  their files, stops their background writers and removes their shutdown hooks; it is idempotent. After
  it the stores write nothing: a mutator changes memory only and reports "the store is closed" on
  `saveError()`. A host that never calls it still loses nothing on a normal exit.
- **Breaking: a store file has one owner.** Each store holds an exclusive lock on a sidecar
  `<file>.lock` (for example `accounts.dat.lock`) beside its file for its lifetime, which also covers two
  processes sharing a directory. A second runtime on the same directory fails in `build()` with an
  `AltsException` of kind `CONFLICT` saying the store file is in use (the message names the file, never
  the path), and a build that fails holds no lock. `build()` also fails, with kind `STORAGE`, when the
  store directory cannot be created or locked, where it used to build and report the failure on
  `loadError()`.
- **Breaking: a store file that could not be read is never written over.** Before, only a load that
  failed for want of the store key refused writes; any other unreadable file (the wrong key, a damaged
  file, a read error) was copied aside and replaced by the next write, so a runtime without the host's
  key wrote a fresh machine-keyed store over a host-keyed one. Now every failed load of a file that
  exists refuses every write, reported on `saveError()`, until a later `load()` succeeds, the file is
  gone, or the host calls the new `discardUnreadable()` on `AccountStore` or `HostSecrets`. That is the
  route for a renamed OS user, a moved home directory or a rotated key: the file is copied aside and the
  next write starts a new store. The copy aside to `<name>.unreadable.<time>` is now made when the load
  fails (newest five kept), not when a write replaces the file; a file unread only because the key was
  unavailable is copied when it is discarded.
- The `VaultDirectoryProvider` is asked once, in `build()`; the stores keep that directory for the
  runtime's lifetime. The store key provider applies to the runtime that was given it and nothing else.
- **Breaking: the caches and the clock take the executor they run on.** `AsyncCache`'s public
  constructors take a `java.util.concurrent.Executor` first (`new AsyncCache<>(executor, loader)`,
  `(executor, loader, ttlMillis)`, `(executor, loader, ttlMillis, maxEntries)`), and so do
  `NtpTimeSource`'s (`new NtpTimeSource(executor)`, `(executor, server, interval)`,
  `(executor, server, port, interval)`). Nothing in the library reaches for a process-wide executor to
  run a cache load or a clock measurement.
- **Breaking: `SkinAvatarCache` has no public constructor.** `alts.skinCache()` is the only route; the
  runtime builds it over its own avatar source and executor.
- **Breaking: each runtime owns its transport and its executor.** The proxy provider, the proxy tunnel
  connections and the executor were process-wide statics that every runtime rebound; now each runtime
  builds its own transport and hands it to every service through its constructor. A runtime's requests
  are routed by its own `ProxyProvider` only, and a runtime built without one connects directly
  whatever another runtime was given (before, a second runtime without a provider silently kept the
  first one's). Its blocking work runs on its own executor: the host's from `Builder#executor`, which
  the runtime never shuts down, or one the runtime creates (a virtual thread per task, named
  `alts-io-<n>`) and shuts down in `close()`. Proxy semantics are unchanged: a provider that throws or
  returns null fails the request, no provider means direct, the credential rides the `CONNECT` only,
  and tunnels are kept apart per proxy identity, now also per runtime.
- **Breaking: `AltsRuntime.close()` closes the transport.** It closes the pooled proxy tunnels, refuses
  every request made afterwards, and shuts down a library-created executor, after flushing the stores
  as before. Whatever was waiting on the runtime ends with it, as a failure: a bulk run paced between
  entries (its report completes), a device-code sign-in between polls, a scheduled name claim, and a
  browser sign-in still waiting for its callback, whose loopback port is released.
- Internal, now under `lol.trq.alts.internal` and outside the API: `AltLoginServiceImpl`,
  `AltAccountServiceImpl`, `BulkOperationsImpl`, `MicrosoftCallbackServer`, `MicrosoftAuthUtil`,
  `CookieAuthUtil` and `AccountNetworkUtil` take the runtime's `AccountStore`, transport or executor
  through their constructors, the auth chain's request methods are instance methods, and
  `BulkOperationsImpl` loses the three-argument constructor that read entitlements from the public
  Minecraft services (the runtime passes its own account services).
- **Breaking: `NetworkScope` is a final class and carries a route tag.** It was a record; its accessors,
  value equality and description are kept, `of` and `forAccount` build it with an empty tag, and the new
  `withRouteTag(tag)` and `routeTag()` add and read one. Its public constructors are gone. New
  `AltLoginService.routed(String tag)` returns a view of the login service
  whose every request, on every hop of every route (the renewal behind `loginAccount` included),
  reaches the `ProxyProvider` with that tag, and new `BulkOptions.withRouteTag(tag)` does the same for
  `importCredentials`. A host that pins accounts to proxies can now route a new account's first
  sign-in before any UUID exists. `routed` is abstract, so a host's own `AltLoginService`
  implementation has to add it. `BulkOptions` is a final class too, with `routeTag()`, and the new
  `BulkOptions.of(...)` with the five pacing settings replaces its constructors. A blank tag is refused
  with `IllegalArgumentException` wherever
  it is given: by `routed` or by `withRouteTag`.
- **Request headers.** Besides a header holding a control character (0.12.0), `HttpTransport`'s
  header-taking methods now refuse a caller-supplied `Proxy-Authorization`, in any capitalisation, with
  an `IllegalArgumentException` whose message quotes nothing, before anything is sent. The proxy
  credential is placed only by the route: on the `CONNECT` of a tunnel, or on a plain request to the
  proxy itself, never on a connection the JDK would send to the origin.
- **Breaking: a failure is an `AltsFailure` everywhere.** An outcome a caller branches on is a result
  carrying `Optional<AltsFailure> failure()`; everything else throws `AltsException`. Sign-in returns
  `auth.LoginResult(account, failure)` (`success()` and `message()` remain as methods); `AccountStatus`
  is `(account, state, failure)` and keeps its `State`, whose exhaustive mapping from the kind is
  unchanged (`RATE_LIMITED` and `NETWORK` are `UNREACHABLE`, `XBOX_DENIED` is `NOT_ENTITLED`);
  `BulkEntryResult` carries `failure()` in place of the success flag and reason, with `success()` a
  method. `NameChangeResult` and `ProfileCreationResult` keep the outcomes a host shows
  (a name changed, invalid, unavailable, taken, blocked) and fold every failure into `FAILED`, which
  carries the failure and its wait; an unreachable service is a `FAILED` result, no longer an
  exception. `ClaimResult` gains `failure()`, present exactly on `TERMINAL_FAILURE`, which now also
  ends a run that met a rate limit or a closed runtime. The account services, `ProfileLookupService`
  and `SkinService` throw `AltsException` and declare no checked exception, and so do
  `PlayerCertificate.privateKey()` and `publicKey()`, which threw the checked
  `GeneralSecurityException`. The stores report
  `loadError()`, `saveError()` and `loadWarning()` as `Optional<AltsFailure>` of kind `STORAGE`. Read
  `failure().map(AltsFailure::kind)` where you read a reason, `failure().flatMap(AltsFailure::retryAfter)`
  where you read `retryAfter()`, and `failure().flatMap(AltsFailure::xstsError)` where you read
  `xstsError()`. The [Error kinds](#error-kinds) table above maps every former constant to its kind.
- **Breaking: a failure message is the library's own.** A failed account-service call says which
  request failed and with what status; the service's `errorMessage` is no longer repeated, since a
  service may echo what it was sent. A sign-in no longer repeats what the host's session injector
  threw.
- **Breaking: `CookieFile.read(Path)` throws `AltsException` of kind `INVALID_INPUT`** in place of a
  checked `IOException` for a file that is missing, not a file, empty, too large or unreadable; the
  message still names the file only, and no exception carrying the path rides along as its cause.
- **Breaking: nothing a closed runtime starts throws at the caller.** A sign-in route, a check or a
  refresh started after `close()`, or refused by its executor, returns a result whose failure is
  `CANCELLED` (it used to throw `RejectedExecutionException` on a runtime-created executor); a browser
  sign-in no longer binds a port or opens a browser once the runtime is closed. A scheduled name claim
  that the closing runtime ends completes with a `TERMINAL_FAILURE` result of kind `CANCELLED` instead
  of an exception. A bulk run cut short (the runtime closed under a wait, or its executor refused a
  task) reports every entry it did not finish as a failure of kind `CANCELLED`, so its report holds
  every entry; a `BulkProgress.started` that throws fails that entry with kind `UNKNOWN`, unattempted,
  and the run goes on. A `BulkProgress.completed` or `finished` that throws a `RuntimeException` is
  ignored: the entry stays recorded and the run is not cut short. An `Error` from a callback does cut it
  short: the entry being reported keeps its result and every remaining entry is reported as
  `CANCELLED`. An account-service call on a closed runtime throws `AltsException` of kind `CANCELLED`.
- **Breaking: `VaultIdentity.signChallenge` refuses an AVP structure.** It signs nothing and throws
  `AltsException` of kind `INVALID_INPUT` for an input that begins with the ASCII bytes `avp/`, or is
  shorter than `VaultIdentity.MIN_CHALLENGE_BYTES` (16) or longer than `MAX_CHALLENGE_BYTES` (1024), so a
  server cannot have the key sign an AVP 0.5 leave request or commit signature passed off as a nonce. It
  stays the raw-nonce signature a host uses to authenticate to a 0.4 server; AVP 0.5 authentication signs
  a domain-separated challenge transcript instead.
- **Breaking: the vault identity throws `AltsException`.** `VaultIdentity.create`, `unlock`,
  `unlockWithRecovery`, `withRecovery`, `identityId` and `signChallenge` declare no checked exception:
  a wrong passphrase or recovery code, or a tampered record, is kind `CRYPTO`, and a malformed stored
  record (a missing or non-Base64 field, a key of the wrong length, an iteration count out of range, no
  recovery sealing, a null passphrase) is kind `INVALID_INPUT`. `WrappedIdentity`'s constructor refuses
  a missing required field with `INVALID_INPUT` instead of `NullPointerException`.
  `RecoveryCode.deriveKey` is no longer public; `RecoveryCode.newCode()` and
  `VaultIdentity.unlockWithRecovery` are the recovery route.
- **Breaking: the identity types moved to `lol.trq.alts.vault`.** `VaultIdentity`, `WrappedIdentity` and
  `RecoveryCode` were in `lol.trq.alts.crypto`; change the import. The JSON form of `WrappedIdentity` is
  unchanged, so a stored identity still opens. `VaultIdentity` is also the AVP 0.5 member identity: its
  Ed25519 key is the member key and its X25519 key the one data keys are wrapped to.
- **Breaking: Gson is an ordinary dependency.** The library declared Gson `compileOnlyApi`, so a host had
  to put Gson on its runtime class path itself. It is now an `api` dependency: the Gradle metadata and the
  POM both carry `com.google.code.gson:gson:2.14.0` at compile scope, and a host receives it
  transitively. A host that ships its own Gson resolves the version in its build as for any other
  dependency.
- **Breaking: the jar is sealed.** Its manifest says `Sealed: true`, so on the class path a class from
  another jar cannot join one of the library's packages. It no longer carries `Automatic-Module-Name`;
  the module descriptor names the module, still `lol.trq.alts`.
- The `@since` tags name the release each type and member first shipped in (about seventy said 1.0.0
  for API that shipped in 0.11.0 or earlier), and every exported declaration now has one.

### Removed

- **Breaking:** `AltLoginCallback` and `AltLoginCallback.FailureReason`: every route returns a future,
  and the reason is `AltsFailure.Kind`. `AltLoginCallback.LoginResult` is now `auth.LoginResult`; its
  constructors with four to six arguments, `failure(String)`, `failure(String, FailureReason, ...)`
  and `rateLimited()` go, replaced by `LoginResult.failure(AltsFailure)` and
  `LoginResult.failure(Kind, String)`.
- **Breaking:** `crypto.CryptoException` and `vault.VaultException`; every failure is an
  `AltsException` (the [Error kinds](#error-kinds) table above maps them).
- **Breaking: the `lol.trq.alts.crypto` package.** Its primitives (`Ed25519`, `X25519`, `Pbkdf2` and
  `PayloadCipher`, which loses the 0.4 `aad` builder) are internal, under
  `lol.trq.alts.internal.crypto`, and no public type takes or returns one. A host needs none of them:
  `VaultIdentity`, `WrappedIdentity` and `RecoveryCode` (already in `vault`) are the identity API, and
  the AVP 0.5 constructions live under `lol.trq.alts.internal.avp`.
- **Breaking:** `AccountException` and `SkinValidationException` (with `SkinValidationException.Reason`,
  replaced by `SkinProblem` constant for constant). Their `status()`, `tokenRefused()`, `rateLimited()`,
  `notFound()` and `retryAfter()` become `failure().kind()` and `failure().retryAfter()`.
- **Breaking:** `AccountStatus.rateLimited()`, `AccountStatus.retryAfter()`, `AccountStatus.reason()`,
  the `AccountStatus.failure` overloads taking a reason and a message, `ClaimResult.rateLimited()`,
  `ClaimResult`'s three-argument constructor and its stop-reason inference, its four-argument canonical
  constructor (the canonical one now takes the failure as a fifth argument), the
  `BulkEntryResult.failure(int, String, FailureReason, String, int)` factory (now
  `failure(int, String, AltsFailure, int)`), and the result records' `retryAfter` components.
- Internal: `MicrosoftAuthUtil.AuthFlowException`, `MicrosoftAuthUtil.XstsAuthException` and
  `MicrosoftAuthUtil.RefreshRejectedException`; the sign-in chain fails with `AltsException`.
- **Breaking:** `AltStore` and `SecretStore`, with no deprecation bridge. Their static `bind`,
  `configure`, `keyProvider` and `writeDelay` have no replacement call: the builder sets the directory,
  file names, key bindings and key provider, and a runtime always coalesces writes (100 ms).
  `AltStore.DEFAULT_WRITE_DELAY` has no public replacement. A store is reached only through its runtime:
  `AccountStore` and `HostSecrets` have no public factory and no public `close()`, so a store cannot be
  closed under a runtime that is still open; closing the runtime closes both.
- **Breaking:** `AltsToasts`, with no deprecation bridge. `alts.toasts()` is the only route to the
  host's `ToastSink`. Each helper becomes one `toast(level, title, description, durationMs)` call:
  `success(name)` is `toast(SUCCESS, "Logged In", "Logged in as " + name, 3000)`, `failure(message)` is
  `toast(ERROR, "Login Failed", message, 4000)`, `info(title, description)` is
  `toast(INFO, title, description, 2500)`, and `removed(name)` is
  `toast(INFO, "Account Removed", "Removed " + name, 2500)`.
- The store test seam (`StoreTestHooks.reset()` and the package-private `resetForTests()` behind it);
  a test that owns its runtime or store needs no process-wide reset.
- **Breaking:** `AccountServices.of(...)` and `ProfileLookupService.create(...)`. The routes are
  `alts.accountServices(account)` (or `alts.accountServices(token, uuid)`) and `alts.profileLookup()`;
  the new `Builder#accountEndpoints(AccountEndpoints)` points both at another base, which by default is
  the origin of the configured Minecraft profile URL.
- **Breaking:** `MojangAvatarSource` and `UrlTemplateAvatarSource` are no longer public. The runtime uses
  the Mojang source when no `AvatarSource` is set; `.avatarSource(new UrlTemplateAvatarSource(t))`
  becomes the new `Builder#avatarUrlTemplate(t)`. Setting both an avatar source and a template, or a
  template without a `{uuid}` placeholder, fails `build()`. The `AvatarSource` seam stays.
- **Breaking:** `HttpUtil` (now the internal, per-runtime `HttpTransport`) and `IoExecutor`, with their
  static `bind` methods. A host sets the provider and the executor on the builder, as before, and
  nothing else: there is no process-wide transport or executor left to reach.
- `AccountNetworkUtil.lookupUsername`, which nothing used; `ProfileLookupService.byUuid` does the job.
- Internal, now under `lol.trq.alts.internal`: `CookieAuthUtil.authenticate(String)` (the overload
  against the default endpoints), the `MicrosoftCallbackServer(state, config)`
  constructor that sent no PKCE challenge, and the static request methods of `MicrosoftAuthUtil`,
  `CookieAuthUtil` and `AccountNetworkUtil`, now instance methods over the runtime's transport.
- The `lol.trq.alts.testSeams` system property and the test hooks it guarded (`HttpUtil.resetForTests`,
  `IoExecutor.resetForTests`, `NetTestHooks`): a test builds its own runtime or transport and needs no
  process-wide reset.
- **Breaking: the 0.4 shared vault**, with no deprecation bridge; 1.0 writes AVP 0.5 only, and
  `LegacyVaultReader` reads a 0.4 repository once so its accounts can move to a new one. Gone: the 0.4
  half of `SharedVault` (both constructors, `createRepo`, `openRepo`, `addMember`, `encryptPayload`,
  `decryptPayload`, `rotateKey`, `removeMember`, `SharedVault.CreatedRepo`,
  `SharedVault.RotationResult`, and the `IllegalStateException` a 0.5 copy threw from them); every type
  in `vault.transport` (`VaultTransport`, `KeyBindingVerifier`, `IssuerSignedKeyBindingVerifier` and the
  wire DTOs: `VaultManifest`, `MemberEntry`, `EncryptedEnvelope`, `AuthChallenge`, `AuthToken`,
  `ChallengeRequest`, `TokenRequest`, `CreateRepoRequest`, `PullRequest`, `PullResponse`,
  `PushRequest`, `PushResponse`, `MemberAddRequest`, `MemberRemoveRequest`); every type in
  `vault.federation` (`RepoAddress`, `InviteRequest`, and the 0.4 `RepoLocator`, which the 0.5
  `vault.RepoLocator` replaces); `vault.RepoPin`, `vault.RepoContext` and `vault.MemberPublicKey`;
  `spi.VaultTransportResolver`, `Builder#vaultTransportResolver` and
  `AltsRuntime.vaultTransportResolver()` (a 0.5 host is reached by locator and matched by key over the
  runtime's transport, `alts.vault()`); and
  the 0.4 wrap types in `crypto`: `KeyWrapScheme`, `X25519HkdfAesGcmKeyWrap`, `RepoDataKey`, `WrappedKey`
  and `Hkdf`. The wrap scheme itself is unchanged in AVP 0.5, and the importer reads 0.4 wraps with it.
- **Breaking: the implementation moved under `lol.trq.alts.internal`**, which the module does not export,
  the Javadoc does not document and the compatibility gate does not cover. Each type and what a host
  uses instead:

  | Type (0.12) | Now | Use instead |
  | --- | --- | --- |
  | `net.HttpUtil` / `HttpTransport` and its `HttpResponse`, `JsonResponse`, `BytesResponse`, `HeaderResponse` | `internal.net` | no public replacement: the runtime owns its transport; set `proxyProvider` and `executor` on the builder |
  | `net.Multipart`, `net.Backoff` | `internal.net` | no public replacement |
  | `net.FailureText` | `internal.net` | `AltsFailure.message()` |
  | `net.MicrosoftCallbackServer` | `internal.net` | `loginService().loginMicrosoft(...)` |
  | `ProxyRoute.toProxy()`, `ProxyRoute.authorizationHeader()` | `internal.net.ProxyRoutes` | no public replacement: the transport builds the proxy and the header |
  | `auth.MicrosoftAuthUtil` | `internal.auth` | the `loginService()` routes |
  | `auth.CookieAuthUtil` | `internal.auth` | `loginService().loginCookie(...)` and `loginCookieFile(...)` |
  | `auth.AccountNetworkUtil` (and `ProfileLookup`) | `internal.auth` | `accountServices(account).profile()`, or `profileLookup()` |
  | `auth.TokenExpiry` | `internal.auth` | `AltAccount.expiresAt()`; `accountService().check(account)` for validity |
  | `auth.MinecraftProfile` | `internal.auth` | `LoginResult` and `PlayerProfile` |
  | `auth.AltLoginServiceImpl`, `auth.AltAccountServiceImpl` | `internal.auth` | `alts.loginService()`, `alts.accountService()` |
  | `bulk.BulkOperationsImpl` | `internal.bulk` | `alts.bulk()` |
  | `store.EncryptionUtil` | `internal.store` | no public replacement: the stores encrypt their files; key them with a `StoreKeyProvider` |
  | `VaultIdentity.keyAgreementPrivateKey()` | removed | no public replacement: the vault unwraps inside the library |

- **Breaking:** `format.AltManagerFormatting` and the `format` package. Nothing in the library used it,
  and its English labels are presentation a host should localize. To keep them, copy:

  ```java
  static String prettyType(AccountType type) {
      return switch (type) {
          case MICROSOFT -> "Microsoft";
          case COOKIE -> "Cookie";
          case SESSION -> "Session";
          case OFFLINE -> "Offline";
      };
  }

  static String relativeTime(long epochMillis) {
      long delta = System.currentTimeMillis() - epochMillis;
      if (epochMillis <= 0 || delta < 0) return "";
      long minutes = delta / 60_000, hours = minutes / 60, days = hours / 24;
      if (minutes < 1) return "just now";
      if (hours < 1) return minutes + "m ago";
      if (days < 1) return hours + "h ago";
      if (days < 7) return days + "d ago";
      if (days < 30) return (days / 7) + "w ago";
      if (days < 365) return (days / 30) + "mo ago";
      return (days / 365) + "y ago";
  }

  static int hsvToRgb(int hueDeg, float s, float v) {
      float h = (hueDeg % 360) / 60f;
      int i = (int) Math.floor(h);
      float f = h - i;
      float p = v * (1 - s), q = v * (1 - s * f), t = v * (1 - s * (1 - f));
      float[] rgb = switch (i % 6) {
          case 0 -> new float[] {v, t, p};
          case 1 -> new float[] {q, v, p};
          case 2 -> new float[] {p, v, t};
          case 3 -> new float[] {p, q, v};
          case 4 -> new float[] {t, p, v};
          default -> new float[] {v, p, q};
      };
      return 0xff000000 | ((int) (rgb[0] * 255) & 0xff) << 16 | ((int) (rgb[1] * 255) & 0xff) << 8
              | ((int) (rgb[2] * 255) & 0xff);
  }
  ```

### Fixed

- A bulk run's report completed before its `BulkProgress.finished` callback ran, so a caller woken by
  the report could miss it. The report now completes after `finished` has returned (or thrown).
- A stated `Retry-After` is held to one day. A service naming an absurd wait (`100000000000000000`
  seconds, or a date in the year 9999) overflowed the millisecond conversions downstream: a failure
  could not be built, and a paced bulk run was cut short instead of waiting. `AltsFailure.retryAt()`
  is held to `Instant.MAX`, and every wait saturates, as a backstop for a wait a host builds itself.
- A renewal, a check and a username correction wrote the caller's whole copy of the account back to
  the store. A copy older than the store undid what had changed since: a ban marked while a paced
  `refreshAll` worked through its list was lost, and a stale copy put a refresh token the service had
  rotated past back on disk. Each now writes only what it changed (the tokens and expiry, or the
  name) onto the record the store holds, under the store's lock, and the renewed account it returns
  is that record. A stated `invalid_grant` discards the stored refresh token only when it is the one
  that was refused. An account the store does not hold is still never persisted.
- A renewal whose token redemption succeeded but whose later hop failed (a throttled Minecraft
  services login, an Xbox Live refusal, an outage) kept the redeemed refresh token and dropped the
  rotated one, so the next renewal replayed a token the service may already have retired. The rotated
  token is now written to the stored account as soon as the token endpoint issues it, and the failed
  status carries it too.
- A `403` from the Minecraft services Xbox login (`login_with_xbox`) was reported as `UNAUTHORIZED`,
  which sends the user through a fresh sign-in that fails the same way. Minecraft services answers
  every account so while the host's client registration is not approved for it, so it is now
  `NOT_CONFIGURED`, on sign-in and on renewal alike.
- Library connections used the JVM's URL-connection caches, so a host that installed a process-wide
  `ResponseCache` was offered every response, a token-bearing sign-in answer included. Caches are now
  off for every library connection. SECURITY.md states the limit that remains: a host-installed
  default `CookieHandler` still sees library requests, which `HttpURLConnection` gives no way to stop.
- A bulk import made each resolved account the store's current one and, when the run ended, put back
  whatever was current when it started, so a sign-in the user made while the import ran was undone.
  It also stamped every imported account as used. An import now never touches the current account
  and leaves a stored account's `lastUsed` as it was.
- A successful answer that carried nothing usable was misreported: an XSTS `2xx` with no readable
  body came back as `XBOX_DENIED` (with `XstsError.UNKNOWN`), and a profile naming a JSON `null` for
  its name or id escaped the profile hop unclassified. Both are now `PROTOCOL`.
- The cookie route dropped a stated wait: a `429` with `Retry-After` on one of its redirect hops, or on
  its profile hop, was `RATE_LIMITED` with no `retryAfter()`. It now carries the wait, as every other
  route does.
- A saving (`ADD`) Microsoft sign-in (browser, device code, refresh token) stored the account before
  installing its session, so one whose session the host's injector refused was saved anyway. It now
  installs first and saves only on success, as the other routes always did.
- `AccountStore.load()` and `HostSecrets.load()` cleared memory and then refilled it, so a host reading
  `accounts()` or `get(key)` from another thread could see an empty store mid-load. Each now replaces
  the whole contents in one step. A store file whose plaintext is empty used to leave memory as it was;
  it now loads as the empty store it is.
- `AltAccount` kept the `bans` map it was built with, and `GameStats` its `stats` list, so whoever still
  held that map or list could change a record the store shares between threads, and so could a caller
  of `bans()` or `stats()`. Each now takes an unmodifiable copy; `null` stays `null`.

## [0.12.0] - 2026-11-12

Device-code login, a wider account surface, a host-supplied store key, and a hardening pass over the
transport, the stores, the sign-in routes and the shared vault. Several defaults changed on the way, so
read the upgrade notes first.

### Upgrading

Every item here is a break or a change in behaviour that a host has to act on or at least know about.

- **Dependency coordinate.** The repository moved to the `trq-lol` organisation and JitPack coordinates
  follow the repository owner, so the dependency is now `com.github.trq-lol:lol.trq.alts`, with the
  release tag as the version. The previous coordinate serves releases up to 0.11.1 only.
- **Removed API.** `AccountNetworkUtil.fetchProfileFromToken(String)` and
  `fetchProfileFromToken(String, String)`, deprecated since 0.8.0, are removed. Use
  `fetchProfile(token, profileUrl, scope)`, which returns the status alongside the identity.
- **Records that gained components.** `LoginResult` (`xstsError`, `retryAfter`), `MicrosoftAuthConfig`
  (`deviceCodeUrl`, `deviceTokenUrl`), `ClaimResult` (`stopReason`), `NameEligibility` (`changedAt`) and
  `BulkEntryResult` (`entitlements`). Each keeps a constructor with its previous arity, so
  `new LoginResult(...)` and the like still compile. A record deconstruction pattern does not: add the
  new components to it.
- **New `FailureReason` constants.** `RATE_LIMITED`, `XBOX_DENIED`, `DECLINED` and `TIMED_OUT`. A switch
  expression over the enum with no `default` stops compiling until it handles them; a switch statement
  compiles and silently skips them. `AccountStatus.State.NOT_ENTITLED` now also covers `XBOX_DENIED`.
- **A rate limit is `RATE_LIMITED`, not `NETWORK`.** A `429` from any step of a login, check, refresh or
  import used to be reported as `NETWORK`. Code that retries on `NETWORK` no longer retries a throttle,
  and should wait for `LoginResult.retryAfter()` or `AccountStatus.retryAfter()` when one is stated.
  `AccountStatus.state()` is still `UNREACHABLE` for it, and `rateLimited()` is true with or without a
  stated wait. In `bulk()`, `stopOnRateLimit` now also stops on a `429` that names no wait.
- **Sign-in failures are classified.** `loginMicrosoft` used to report every failure as `UNKNOWN` and
  `loginCookieFile` every failure as `INVALID_TOKEN`. Both now report `NETWORK`, `RATE_LIMITED`,
  `INVALID_TOKEN`, `NOT_ENTITLED`, `XBOX_DENIED`, `DECLINED` or `TIMED_OUT` as the case is. A handler
  that treated `UNKNOWN` as "the Microsoft login failed" needs a `default` branch.
- **Store key provider.** `Builder.storeKeyProvider(...)` is optional. Once one is installed, a store
  file opens under the host's key or is reported unreadable. A store written under the machine-derived
  default does not load under a provider unless `Builder.migrateFromMachineKey(true)` is set. Set it on
  the one launch that first installs the provider over existing files: that launch loads the old store,
  rewrites it under the host's key, and reseals or removes the rolling backup and every unreadable copy.
  Leave it off afterwards, because while it is on the machine-derived key is still accepted. When the
  provider throws, or returns `null` or fewer than `StoreKeyProvider.MIN_LENGTH` (16) bytes, the store
  is unreadable and every write is refused until a later `AltStore.load()` / `SecretStore.load()`
  succeeds; `saveError()` says so. `AltStore.keyProvider(null)`, `SecretStore.keyProvider(null)` and a
  second runtime built without a provider never remove an installed one.
- **Unreadable copies are named differently.** A store file that could not be read is copied to
  `<name>.unreadable.<time>` (epoch milliseconds) before a write replaces it, one copy per distinct
  file, newest five kept. It used to be a single `<name>.unreadable`, made once. A host or a support
  script that looks for the old name should match the prefix.
- **`HttpUtil.bind(null)` no longer clears a proxy provider.** Neither does building a second runtime
  with no `proxyProvider`. There is no public call that removes an installed provider.
- **Blocking work left the common pool.** Every request, and everything that waits on one, now runs on
  the library executor (`IoExecutor.executor()`): one virtual thread per task by default, or the
  executor passed to `Builder.executor(...)`. Continuations a host chains without an executor,
  `AsyncCache` loaders, `GameStatsSource.fetch`, `AvatarSource` and `DeviceCodePrompt.show` run there
  rather than on `ForkJoinPool.commonPool()`. A host that relied on common-pool threads, their names or
  their thread-locals should supply its own executor.
- **Store writes are coalesced.** A runtime built through `AltsRuntime.Builder` writes each store on a
  background daemon thread 100 ms (`AltStore.DEFAULT_WRITE_DELAY`) after a mutation, so a mutation is
  not yet on disk when the call returns. `AltStore.save()`, `AltStore.flush()` and
  `SecretStore.flush()` write at once, and a shutdown hook flushes on a normal exit. Call `flush()`
  before leaving by a route that skips shutdown hooks. `AltStore.writeDelay(Duration.ZERO)` after
  `build()` restores synchronous writes; a store bound directly, without the builder, stays synchronous.
- **Deprecated `SharedVault` entry points.** The one-argument constructor `SharedVault(KeyWrapScheme)`
  is deprecated because it installs `KeyBindingVerifier.trustTransport()` without being asked; use
  `SharedVault(KeyWrapScheme, KeyBindingVerifier)` and choose the verifier. `addMember(ctx, member)`,
  `rotateKey(ctx, alts, List<MemberPublicKey>)` and `removeMember(ctx, alts, List<MemberPublicKey>)`
  are deprecated in favour of `addMember(ctx, member, keyBindingSig)`,
  `rotateKey(ctx, alts, manifest)` and `removeMember(ctx, alts, manifest, removedMemberId)`. The
  deprecated forms run the verifier with no signature, so they fail under a verifier that requires one.
  The new forms throw the checked `VaultException`.
- **`SharedVault` refuses more.** `openRepo` rejects a manifest whose scheme id is not the configured
  scheme or whose member entry names a different key epoch, `decryptPayload` rejects an envelope from
  another epoch, and malformed envelopes, payloads and missing transport objects fail with
  `VaultException` instead of an unchecked exception. `RepoAddress` and `RepoLocator.decode` reject
  userinfo, whitespace, and path, query or fragment characters in the host.
- **`AsyncCache` behaviour.** The cache is bounded (`DEFAULT_MAX_ENTRIES`, 4096; entries read longest
  ago go first). A failed fetch is retried after a growing backoff, where it used to stay failed until
  `invalidate`. A failed refresh keeps the stale value. The loader runs on the library executor.
- **`NtpTimeSource.now()` no longer measures inline.** It returns the OS clock plus the last measured
  offset and never touches the network, so before the first measurement lands it is the uncorrected OS
  clock. Call the blocking `sync()` first when the correction has to be in hand. A reply is accepted
  only as a server-mode answer from a synchronised server that echoes the request's nonce.
- **Skin uploads are validated locally.** `SkinService.upload` throws `SkinValidationException` (an
  `AccountException`) before any request for data that is empty, larger than
  `SkinService.MAX_SKIN_BYTES` (1 MiB), not a PNG, or not 64x64 or 64x32.
- **Cookie login uses `live.com` cookies only.** Cookies an export attributes to any other domain are
  dropped, cookies are attached only to HTTPS hosts their domain covers, and the chain stops on a hop
  that is not HTTPS. An export that holds no `live.com` cookies fails the login.
- **Session-token login confirms the identity before storing.** With `LoginMode.ADD` the token always
  goes through the profile lookup, so adding a session token costs a request and can fail as `NETWORK`
  or `RATE_LIMITED`.
- **Request headers.** `HttpUtil` refuses a header name or value holding a control character with an
  `IllegalArgumentException` whose message quotes nothing, and reads at most 1 MiB of a JSON or text
  body. Failure messages no longer repeat a transport exception's own message.

### Added

- **Device-code login.** `AltLoginService.loginDeviceCode(prompt, mode)` runs the OAuth
  device-authorization grant: the host shows a short code and the verification address through the new
  `spi/DeviceCodePrompt` seam, and the library polls until the sign-in is approved, declined or expired.
  It needs no loopback port and no local browser. Polling honours the advertised interval (held to
  between 1 and 60 seconds), adds five seconds on `slow_down`, tolerates a few unanswered polls, and
  stops at the advertised expiry (held to 30 minutes). Cancelling the returned future stops it.
  `MicrosoftAuthConfig` gains `deviceCodeUrl` and `deviceTokenUrl`, defaulting to the consumers tenant,
  and `withDeviceCodeEndpoints(...)`.
- **PKCE on the browser login.** Every `loginMicrosoft` generates a code verifier, sends its S256
  challenge on the authorize URL and the verifier on the token exchange.
- **Typed sign-in failures.** `FailureReason.RATE_LIMITED`, `XBOX_DENIED`, `DECLINED` and `TIMED_OUT`;
  `LoginResult.xstsError()` carrying the decoded Xbox Live refusal; `LoginResult.retryAfter()` and
  `rateLimited()`; and `MicrosoftAuthUtil.AuthFlowException`, the typed failure each step of the chain
  raises.
- **Account services.** On `alts.accountServices(account)`:
  - `attributes()`: `PlayerAttributesService` reads privileges, preferences and platform ban status
    (`PlayerAttributes`), and sets the profanity filter. Unknown fields are ignored and unknown ban
    scopes are kept.
  - `certificates()`: `CertificateService` requests the chat-signing key pair (`PlayerCertificate`),
    which decodes to `java.security` keys, reports expiry, and redacts the private key from `toString`.
    Nothing is persisted.
  - `blocklist()`: `BlocklistService` reads the players the account has blocked.
  - `profile().fetchIfPresent()` returns an entitled account's missing profile as an empty result, and
    `profile().create(name)` creates one, returning a classified `ProfileCreationResult`.
  - `skin().upload(Path, model)`, `skin().resetToDefault()` and `cape().hideActive()`, the last two
    returning the updated profile.
  - `NameEligibility.changedAt()`, with `estimatedNextChange()` and `estimatedWaitAt(now)`. The service
    returns no such date; the estimate is the last change plus the documented 30-day cooldown.
  - `ClaimResult.stopReason()` and `rateLimited()`, stating why a scheduled claim stopped.
- **Public profile lookup.** `alts.profileLookup()` (`ProfileLookupService`) resolves a player by name
  or UUID with no token and no account. `byNames` posts ten names per request to the batch endpoint,
  de-duplicated without regard to case. A rate limit part-way through fails the call rather than
  returning a partial list.
- **Bulk entitlement sweep.** `bulk().entitlementsAll(...)` reads what every account owns through the
  same runner as `checkAll` and `refreshAll`. A successful entry carries the product set on
  `BulkEntryResult.entitlements()`.
- **Store key provider.** `spi/StoreKeyProvider`, `Builder.storeKeyProvider(...)` and
  `Builder.migrateFromMachineKey(boolean)`: the host supplies the key material both encrypted stores
  are sealed under.
- **Store reporting and control.** `AltStore.saveError()`, `AltStore.loadWarning()`,
  `AltStore.flush()`, `AltStore.writeDelay(Duration)`, `AltStore.DEFAULT_WRITE_DELAY`, and the same
  `saveError`, `flush` and `writeDelay` on `SecretStore`.
- **Library executor.** `net/IoExecutor` and `Builder.executor(...)`.
- **Rollback floor for shared repositories.** `vault/RepoPin`, `SharedVault.openRepo(manifest, identity,
  pin)` and `RepoContext.pin()`. A host that persists the pin gets a floor on key epoch and payload
  version.
- **Verified wraps.** `SharedVault(KeyWrapScheme, KeyBindingVerifier)` runs the verifier before every
  wrap to another member's keys, through the new `KeyBindingVerifier.verify(repoId, claimed,
  keyBindingSig)`, with `addMember`, `rotateKey` and `removeMember` overloads that carry what it needs.
- **Transport additions.** `HttpUtil.postJsonForElement` (for a top-level JSON array),
  `getBytesForStatus` (with an optional per-hop redirect predicate), `postJsonForStatus` with a scope,
  `HeaderResponse.rateLimited()`, `BytesResponse`, `JsonResponse`, and `net/FailureText`, which
  describes a failure by its kind without repeating its message.
- `AccountException.retryAfter()` and `notFound()`. The class is no longer final, so a typed failure can
  extend it.
- `MicrosoftAuthUtil.authenticateWithRefreshToken(config, refreshToken, scope)`, so every hop of a
  renewal names its account and a `ProxyProvider` can route a refresh per account.
- `SkinAvatarCache.invalidate(uuid)` drops a cached head so the next `get` fetches it again, and returns
  the dropped handle so the host can free the texture. A fetch still in flight when the entry is
  invalidated is discarded.
- `AsyncCache(loader, ttlMillis, maxEntries)`, `AsyncCache.size()`, `NtpTimeSource(server, port,
  resyncInterval)`, `NtpTimeSource.synced()` and `offset()`.
- Build metadata: an `Automatic-Module-Name` of `lol.trq.alts`, and a POM with URL, SCM, developer and
  issue-tracker entries.

### Changed

- All blocking work runs on the library executor rather than the common pool.
- Store files are written atomically: staged in a sibling temporary file, forced to disk, moved into
  place. Writers are serialized and ordered, the replaced file is kept as a rolling `<name>.bak`, and
  the file is created owner-only on POSIX file systems. Mutations are atomic with respect to each other
  and to a save. One derived key seals many writes, so PBKDF2 runs once per process and not once per
  save. The bundle format is unchanged.
- Builder-created runtimes coalesce store writes (see Upgrading).
- An authenticated HTTP proxy now works for HTTPS targets. The library opens the `CONNECT` tunnel
  itself and sends the credential on the `CONNECT` only. Kept-alive connections are reused only by the
  same proxy host, port and credential. A plain `http` request through an authenticated proxy is not
  kept alive.
- The binary fetch follows redirects by hand: never when the request carries an `Authorization` header,
  dropping credential headers when a hop leaves the origin, refusing a step from `https` to `http`, and
  stopping after five hops. The route is resolved once per fetch.
- `Retry-After` is read as seconds or as an HTTP-date, the latter measured against the response's own
  `Date` header.
- A bulk run that meets a rate limit stops when `stopOnRateLimit` is set, and otherwise holds the whole
  run back for the stated wait, or a growing one when none was stated, before that entry tries again.
- `CredentialKind` takes a bare word for an offline account only when it is a valid name: 3 to 16
  letters, digits or underscores.
- A scheduled name claim stops on a rate limit and on cancellation of the returned future.
- Avatar downloads are bounded to six in flight; the rest queue. The texture address must name the
  Mojang texture host, is fetched over HTTPS, redirects are held to that host, and the image's declared
  dimensions are checked before decoding.
- The sign-in callback server listens on `127.0.0.1` and `::1`, releases its port as soon as the login
  completes or is cancelled, and lets only a request carrying the login's `state` decide the outcome.
- The cookie chain is followed to the redirect that carries the token instead of a fixed count,
  resolves relative redirects, accepts a token only from the service the sign-in starts at, and reads
  `#HttpOnly_` lines of a Netscape export as cookies. Its Minecraft services endpoints come from
  `MicrosoftAuthConfig`.
- Names placed in URL paths are percent-encoded as one path segment. A public lookup accepts legacy
  names of one and two characters; creating and changing a name keep the stricter rule.
- Gson is declared `compileOnlyApi`, so the published metadata carries it for compilation. The host
  still provides it at runtime.
- The examples are compiled with `-Xlint:deprecation -Werror`.

### Deprecated

- `SharedVault(KeyWrapScheme)`, `SharedVault.addMember(RepoContext, MemberPublicKey)`,
  `rotateKey(RepoContext, List<AltAccount>, List<MemberPublicKey>)` and
  `removeMember(RepoContext, List<AltAccount>, List<MemberPublicKey>)`. See Upgrading.

### Removed

- `AccountNetworkUtil.fetchProfileFromToken(String)` and `fetchProfileFromToken(String, String)`.
- `HttpUtil.bind(null)` as a way to remove a proxy provider, and `keyProvider(null)` as a way to remove
  a store key provider. The resets that remain are package-private test seams, refused unless the JVM
  carries `-Dlol.trq.alts.testSeams=true`, which the Gradle `test` task sets.

### Fixed

- Overlapping saves, or a crash mid-write, could leave a truncated store file that the next start
  treated as unreadable. A failed save is now reported on `saveError()` instead of being swallowed.
- `AltStore.useAccount` no longer writes a caller's stale credentials back over the stored entry.
  Entries with no UUID, and duplicates, are skipped on load and noted on `loadWarning()`.
- A proxy that required a credential answered `407` to every HTTPS request, because the JDK built its
  `CONNECT` without the `Proxy-Authorization` header.
- `getHeader` and `getBytes` disconnected after every response and a redirect's body was never drained,
  so those calls opened a new socket each time.
- A `429` with an HTTP-date `Retry-After`, or with none, was treated as naming no delay or as an outage.
- A refresh answer with no `access_token`, or a JSON `null` `refresh_token`, threw an unchecked
  exception that the import route reported as a network failure. It is now a classified failed step,
  and a missing rotated token keeps the one just redeemed.
- A refusal further down the renewal chain keeps its own reason instead of passing for an outage.
- `loginAccount(null)` returns a failed result rather than throwing.
- The avatar retry backoff now grows. A retry replaced the failure record before fetching, so every
  retry waited the base five seconds. A small PNG declaring a huge canvas left its cache entry pending
  forever; any throwable in the fetch or upload now resolves the entry to failed with retry.
- `AsyncCache` eviction could abort with a comparator contract violation under concurrent reads and
  leave a key pending forever.
- A scheduled claim kept sending for the rest of its window after a `429`.
- `NameService.eligibility()` threw an unchecked exception on a `null` `nameChangeAllowed`.
- The sign-in callback matched `error_code=` as `code=`, and listened on the IPv4 loopback only, which
  a system resolving `localhost` to `::1` first could not reach.
- A relative `Location` in the cookie chain failed the login.
- Vault and crypto input from outside the process (a stored identity, a wrapped key, an envelope, a
  payload, a manifest) could surface `IllegalArgumentException`, `NullPointerException` or a Gson
  exception. These are now `CryptoException` or `VaultException`, and null list elements are skipped.
- The Javadoc builds without warnings.

### Security

- **Tokens stay out of messages and `toString`.** A header value holding a line break made the JDK
  throw an exception quoting the whole value, usually `Bearer <token>`, and that message was appended
  to login results, account statuses and account exceptions. Headers with control characters are now
  refused before the JDK sees them, pasted tokens are stripped of whitespace and control characters,
  and a failure the library did not write is described by its kind. `HttpResponse`, `JsonResponse`,
  `HeaderResponse` and `AuthToken` print no body, header value or token.
- **The proxy credential no longer reaches the origin.** For an HTTPS target the JDK sent the
  `Proxy-Authorization` header to the origin inside the tunnel on every call.
- **Credentials stay on their origin across redirects.** The binary fetch delegated redirects to the
  JDK, which replayed a `Cookie` header to whatever host a `3xx` named.
- **Cookie login no longer sends unrelated cookies to the sign-in hosts**, and no longer attaches the
  `Cookie` header to whatever URL a `Location` header named.
- **A web page can no longer end a pending browser login.** Any request to the loopback callback path
  with missing parameters or the wrong `state` used to complete the login exceptionally.
- **PKCE** protects the authorization code on its way to the loopback redirect.
- **A session token's identity is confirmed before it is stored.** The fast path read the username and
  UUID from the unsigned token payload and, in `ADD` mode, merged the result over the stored account
  with the claimed UUID.
- **Host-keyed stores cannot be weakened or overwritten.** Migration reseals every kept copy, the
  machine-derived key is not accepted unless the host opts in for a launch, a second runtime cannot
  reset the key, and a store whose key was unavailable is not overwritten.
- **Proxy routes copy their password** on the way in and out, so neither side can rewrite the
  credential a route authenticates with.
- **Response bodies are capped** at 1 MiB for JSON and text.
- **The skin upload uses a random multipart boundary** per request; a constant one could be embedded in
  a crafted file to append fields.
- **Shared vault.** The key-binding verifier existed but nothing called it; it now runs before every
  wrap, and the data key is wrapped only to the keys it returned. Manifests below a host-persisted
  `RepoPin`, scheme mismatches and epoch mismatches are rejected. A stored identity's public keys are
  checked against its private material on unlock, its PBKDF2 iteration count is bounded, and key
  material is cleared from temporary arrays after use. `RepoAddress` rejects hosts carrying userinfo.
- **Test seams are out of a host's reach.** `HttpUtil.resetForTests()` was public and removed the proxy
  provider for the whole process.

### Notes

The device-code flow and the reworked cookie sign-in chain were tested against loopback and scripted
servers only. Neither has been verified against the live Microsoft services in this release, so treat
both as unproven there until a host has exercised them.

What the shared vault does not protect against, and what the default store key is and is not, are
stated in [SECURITY.md](SECURITY.md). One limit of the proxy tunnel is stated there too: the JVM still
resolves the origin host name through the local resolver.

Of the 1.0.0 design, this release ships device-code
login, the bulk entitlement sweep and the removal of the deprecated profile methods. Username and
password login was not built, by decision.

## [0.11.1] - 2026-10-11

### Fixed

- Cookie login works again. The sign-in chain it follows grew a step: the Xbox Live sign-in endpoint
  now hands off to the Microsoft identity platform before `login.live.com`, so the chain is four
  redirects long rather than three. The library stopped one short and read the token out of a URL that
  carried only the code it is traded for, and every cookie login failed with
  `Invalid redirect: No accessToken`. The chain is now followed to its end, and the cookies are sent
  only to the two Microsoft sign-in hosts.
- The token on that last redirect is percent-decoded and parsed as JSON rather than cut apart as text,
  so an encoded padding character or a reordered field no longer fails a login.

## [0.11.0] - 2026-08-06

The full post-login account surface — everything an account owner can do to their own account through
the public Minecraft services. The bulk of the
1.0.0 design, shipped ahead of the freeze so the
freeze itself, and the one sensitive route it holds back, are a decision made deliberately rather than
in passing.

### Added

- **A new `account/` package**, reached as `alts.accountServices(account)`. Focused single-job services
  built over one live token, each holdable on its own, none of which install a session or touch the
  store:
  - **`ProfileService`** — the full profile read (`PlayerProfile`): name, UUID, skins, capes, and pending
    `profileActions`. The slim name-and-UUID read the auth chain does stays internal.
  - **`EntitlementService`** — `Entitlements`, the product *set* rather than a boolean, with
    `ownsJava()` / `ownsJavaOutright()` / `viaGamePass()` / `ownsBedrock()`. An account that owns Java is
    told from one entitled only through a Game Pass that can lapse — the distinction an alt manager cares
    about and a boolean throws away.
  - **`NameService`** — `checkAvailability`, `eligibility` (whether a change is allowed now, and the
    account's creation time), `change` (classified: a 400 invalid name told from a 403 cooldown from a
    404 no-entitlement, error body read for the reason), and `claimAt` — a scheduled claim that fires a
    bounded burst of change attempts around a target instant and stops on the first success.
  - **`SkinService`** — set from a URL, upload from bytes, reset, with the classic/slim model.
  - **`CapeService`** — show a cape, hide it, list owned.
- **A new `time/` package** — `TimeSource` (the corrected-clock seam the scheduled claim reads),
  `SystemTimeSource` (default), and `NtpTimeSource` (a minimal one-round-trip SNTP client, for a claim
  that needs the sub-second edge). The claim's drop time is an input a host reads off wherever names are
  listed; the library claims at the time it is given and does not monitor for one.
- **`XstsError`** — the Xbox `XErr` codes decoded (`NO_XBOX_ACCOUNT`, `REGION_BLOCKED`,
  `ADULT_VERIFICATION_REQUIRED`, `CHILD_ACCOUNT`, …). A `MicrosoftAuthUtil.XstsAuthException` carries the
  classified reason, so an account that just needs a one-time Xbox sign-in stops surfacing as a bare
  "Xbox auth failed".
- `net/Multipart` (the skin upload's body) and `HttpUtil.sendForStatus` / `postJsonForStatus` (the
  PUT/DELETE and status-returning JSON the account mutations need).

### Notes

The account services are additive — a host that does not call `accountServices(...)` is unaffected, and
nothing in the existing surface changed shape. The one thing that turned out cleaner than the design
record proposed: the full profile is a new `PlayerProfile` in `account/` rather than a widened
`MinecraftProfile`, so the auth chain's result type is untouched and there is no breaking change to it.

Held back for the 1.0.0 freeze, deliberately: credential (username + password) login, which the design
record flags for an explicit decision; the removal of the deprecated
`AccountNetworkUtil.fetchProfileFromToken`; and a bulk entitlement sweep. 1.0.0 is where the surface is
frozen and those are settled.

## [0.10.0] - 2026-08-06

Identity that stays current — the third milestone of the
alt-management surface.

### Added

- **`AvatarSource` seam and the `MojangAvatarSource` default.** The avatar cache used to fetch from a
  hardcoded third-party head-render URL, which disclosed every account's username to that service on
  every cache miss — for an alt manager, the whole list one person controls, arriving from one address.
  The default now resolves the skin from Mojang's own session server and crops the face locally, so the
  identity is disclosed to no party the host was not already authenticating through.
- **`UrlTemplateAvatarSource`**, the opt-in for a host that wants a head-render service back (its 3D
  renders, its CDN). Installing it is a deliberate trade — that service sees each UUID — rather than the
  default a host gets by doing nothing.
- `AltAccount.withUsername(String)`, and username correction on `check`/`refresh`: the profile lookup
  that validates a token already carries the current name, so a renamed account has its stored username
  updated for free rather than showing the name it was saved under.

### Changed

- **Breaking:** `SkinAvatarCache.get` is keyed by **UUID**, not username. A username is a mutable display
  attribute, so a username-keyed cache breaks a renamed account's head permanently — the old name stops
  resolving. Pass `account.uuid()` where you passed `account.username()`.
- **Breaking:** the default avatar source changed from the third-party service to Mojang. A host that
  wants the old behaviour installs `UrlTemplateAvatarSource` with its URL template. No API change beyond
  the key, but the faces now come from elsewhere.
- **Breaking:** `SkinAvatarCache`'s constructor takes an `AvatarSource` first. Hosts using `AltsRuntime`
  are unaffected; only direct construction of the cache changes.

### Fixed

- A failed avatar fetch is retried after a growing backoff instead of being cached as failed for the life
  of the process. One network blip used to cost the head until restart.
- The avatar fetch no longer downloads without a size cap, and it routes through the proxy seam like
  every other request (both carried over from the 0.8.0 transport unification, now exercised by the new
  source).

## [0.9.0] - 2026-08-05

Bulk operations — the second milestone of the
alt-management surface.

### Added

- **`lol.trq.alts.bulk`**, reached as `alts.bulk()`. Three operations, none of which install a session:
  `checkAll` (validate only), `refreshAll` (validate and renew, persisting each rotation), and
  `importCredentials` (resolve a pasted list into accounts). A host's own loop over `loginAccount` gets
  fifty session switches and, somewhere around account nine, a rate limit it has no way to recognise.
- `BulkOptions` — concurrency, spacing between starts, retry budget, and whether a stated rate limit ends
  the run. `defaults()` is four at a time, 250ms apart, two retries growing from two seconds, stopping on
  a rate limit. Deliberately unambitious: the failure being avoided is a source address earning a longer
  ban, and the cost of being slower than necessary is another minute.
- `BulkProgress`, `BulkEntryResult`, `BulkReport`, and `BulkHandle`. Progress is per entry rather than a
  percentage, because what a user needs is *which* alt failed. The report separates `cancelled` from
  `stoppedEarly` from a run where everything ran and some entries failed — three outcomes that call for
  three different things being said.
- `CredentialKind.detect(String)`, public so a host can preview a paste before running it. Anything it
  cannot place is `UNKNOWN` and fails that entry rather than being guessed at: a session token sent to
  the refresh route comes back as an invalid grant, which reads as a dead credential rather than as a
  line that went to the wrong place.
- `net/Backoff` — a stated `Retry-After` is honoured as given; everything else grows and is jittered,
  because fifty entries that failed together would otherwise retry in lockstep and reproduce the burst
  that caused the failure.
- `AccountStatus.retryAfter()` / `rateLimited()` and the same on `AccountNetworkUtil.ProfileLookup`, so
  the layer running a batch can tell a rate limit from any other network failure.

### Changed

- **Breaking:** `AccountStatus` and `AccountNetworkUtil.ProfileLookup` each gain a trailing `retryAfter`
  component, so positional construction of either record must supply it. Every factory is unchanged, and
  a new `AccountStatus.failure(..., Duration)` overload carries the delay.

### Notes

Concurrency is bounded structurally — that many worker chains pulling from one cursor — rather than by an
executor, so the library still creates no threads of its own and everything runs on the common pool.

Spacing is global rather than per proxy route, which the design record called for. Per-route pacing means
asking the host's `ProxyProvider` which route an entry would take before making the request, and a
rotating provider treats every ask as an allocation — so the library would claim two pool slots per entry
and hand one back unused. Asking a provider more times than requests are made is a bug a host cannot see.

§C (identity refresh and UUID-keyed avatars) was specced for this release and held back: two of its
decisions — flipping the default avatar source off the third-party service, and changing what
`skinCache().get()` is keyed on — were put to the repository owner and are unanswered. A focused release
beats one with a guess baked into it. It becomes 0.10.0, and device-code login 0.11.0.

## [0.8.0] - 2026-08-05

The first milestone of the alt-management surface:
requests can be routed, accounts can be operated on without being logged into, and an account that owns
no Minecraft says so.

### Added

- **A proxy seam.** `spi/ProxyProvider` names the route each request takes, asked per request with a
  `NetworkScope` carrying the purpose (`AUTH`, `PROFILE`, `AVATAR`, `STATS`, `VAULT`) and, when there is
  one, the account it is for. Wire it with `AltsRuntime.Builder.proxyProvider(...)`. Microsoft and Mojang
  rate-limit by source address, so an alt manager validating fifty accounts from one machine looks like
  one machine hammering the service — per-account routing is what that costs, and until now nothing could
  change where a request went. Rotation policy, pool health, and where proxies come from stay host-side;
  the library only asks.

  **Resolution fails closed.** A provider that throws or returns `null` fails the request rather than
  falling back to a direct connection. The intuitive fallback is the wrong one here: a silent fallback
  discloses the machine's real address at exactly the moment the host believed every request was covered,
  and unlike a failed request that cannot be taken back. Returning `ProxyRoute.direct()` is how a host
  says direct is fine; a direct route also opens without naming a proxy at all, so a JVM-level proxy
  setting keeps working.

  Authenticated SOCKS5 is refused rather than silently downgraded —
  `ProxyRoute.socks5(...).withCredentials(...)` throws. The JDK reads SOCKS credentials from
  process-global state, and a library that installs a default `Authenticator` has reached into its host's
  JVM to do it; connecting unauthenticated instead would send the request from an address the host did
  not choose, which is the same disclosure by another route. HTTP proxy credentials ride on the
  connection as `Proxy-Authorization` and need no global state, so two accounts can use two different
  authenticated proxies at once.
- **`AltAccountService`** (`alts.accountService()`) — `check(account)` asks the service whether a stored
  token still works and changes nothing; `refresh(account)` renews from the refresh token when the stored
  one is spent and persists the rotation. Neither installs a session. `loginAccount` is now `refresh`
  plus the injection, which is the decomposition the whole thing exists for: a sweep over every stored
  alt cannot be a loop over `loginAccount`, because that switches session once per account and whichever
  finishes last wins.

  `check` is a separate method rather than a flag because rotation is not free. The token endpoint issues
  a *new* refresh token on every redemption, so a validation pass built on renewal spends one rotation
  per account per pass, on accounts nobody was trying to fix.
- **`AccountStatus`**, carrying a `State` — `VALID`, `RENEWED`, `EXPIRED`, `REAUTH_REQUIRED`,
  `NOT_ENTITLED`, `UNREACHABLE`, `UNKNOWN` — and the account as it now stands, renewed credentials
  included. `EXPIRED` is the one the design record did not anticipate: a read-only `check` on a refused
  token cannot report `REAUTH_REQUIRED`, because if the account still holds a refresh token the user's
  next step is to renew it rather than to sit through a browser login. Those are different actions.
- `AccountNetworkUtil.fetchProfile(token, profileUrl, scope)` and its `ProfileLookup`, which report the
  status instead of collapsing every outcome to `null`.
- `HttpUtil.getForStatus`, `HttpUtil.getHeader` (a header-only GET, for following a redirect chain by
  hand), and `HttpUtil.getBytes` (a size-capped binary GET). `HttpUtil.HttpResponse` gains `retryAfter`
  and `rateLimited()`, so a host can honour a 429 today.

### Fixed

- **An account that owns no Minecraft no longer reports a bad token.** Authenticating succeeds and the
  profile endpoint answers 404, which the library reported as "Invalid token" — sending the user through
  a browser login that resolves nothing. It is now `NOT_ENTITLED`, from every route rather than only the
  new surface. The one ambiguity is stated rather than papered over: a 404 also covers an account that
  owns the game and has never chosen a username, so the message says "no Minecraft profile".
- **The cookie redirect chain and the avatar fetch each opened their own connection**, so neither had the
  finite timeouts nor the refusal to follow redirects that every other request has had since 0.6.0 — and
  neither could be routed through a proxy at all. Both now go through `HttpUtil`. The avatar fetch keeps
  following redirects, because image hosts redirect and it carries no credential to replay; a caller that
  passes an `Authorization` header gets the strict behaviour back automatically.
- The avatar fetch reads at most a megabyte. An unbounded read from an endpoint reached over someone
  else's proxy is where a cap belongs.

### Changed

- **Breaking:** `HttpUtil.HttpResponse` gains a trailing `retryAfter` component, so positional
  construction of the record must supply it. `successful()` and the factory paths are unchanged.
- **Breaking:** `AltLoginCallback.FailureReason` gains `NOT_ENTITLED`, so an exhaustive `switch` over it
  needs a new case.
- **Deprecated:** `AccountNetworkUtil.fetchProfileFromToken`, both overloads, in favour of
  `fetchProfile`. They cannot express the difference between a refused token and an account with no
  profile, which are different problems with different answers. Removal is planned for 1.0.0.

### Notes

Rate-limit backoff was specced as part of this milestone and deferred to 0.9.0, where the bulk
operations that drive it land. Shipping a public utility with no caller is worse than shipping it with
one; what landed now is the input it needs, `HttpResponse.retryAfter`.

## [0.7.0] - 2026-08-05

A login route, a second Microsoft dialect, and a durability pass over the local stores after a full audit
of the library.

### Added

- `AltLoginService.loginCookieFile(Path, LoginMode)`, for authenticating from an exported cookie file
  rather than pasted text. Browser extensions produce cookie exports as files, and the Netscape format
  they use is line-oriented, so pasting one through a single-line input mangles it. Reading is
  byte-order-mark aware: a file redirected out of PowerShell is UTF-16LE, which decoded as UTF-8 yields
  text interleaved with NUL bytes that no parser recognises, and the resulting failure reads as "my
  cookies are bad" rather than "my file is in another encoding". The read runs off the calling thread
  and an unreadable file fails as an `INVALID_TOKEN` result rather than throwing, so a host can hand
  over a path straight from a file picker on its render thread.
- `CookieFile`, the reader behind that route. Public so a host that collects cookie text its own way
  can reuse the size cap and the encoding handling.
- **JSON cookie exports are parsed.** The common cookie-editor extensions write an array of
  `{name, value, domain, ...}` objects rather than the Netscape format, and some nest it under a wrapper
  key. That shape previously fell through to the mangled-text parser, which found the cookie names it
  knows and took the surrounding JSON as their values — producing a header the service rejected and a
  failure that read as bad cookies rather than an unread export. The tree is now walked (to a bounded
  depth), so any wrapper shape works.
- `CookieFile.EXTENSIONS`, the extensions a cookie export normally carries, so a host's file picker and
  this parser agree on what to offer. Advisory only: `read` accepts any path.
- `MicrosoftAuthConfig.legacyMsa(String)`, for authenticating against a *legacy MSA* application
  rather than an Azure OAuth one. The two are different dialects of the same flow and the library
  previously spoke only the OAuth one, so a refresh token issued to a legacy app could not be
  redeemed at all: the token endpoint answered the grant with a flat `400`. Three things differ, and
  all three are load-bearing — the grant must declare the desktop redirect the app registered, it
  must request the `MBI_SSL` scope instead of the delegated Xbox scopes, and the access token that
  comes back is an RPS ticket that Xbox Live wants prefixed `t=` rather than `d=`. A host holding a
  credential minted by a legacy application now has a way to redeem it.
- `MicrosoftAuthConfig.withClientId(String)`, to retarget a config at another application while
  keeping its dialect and endpoints.
- `AltStore.loadError()` and `SecretStore.loadError()` — why the last load could not read an existing
  file, so a host can tell the user their accounts did not load instead of showing them an empty list.
  The two states were previously indistinguishable from the outside.

### Fixed

- **A store that fails to load is no longer overwritten with an empty one.** `load()` swallowed every
  failure and left an empty list, and the next `save()` — which any login triggers — wrote that empty
  list straight over the file. The encryption key is derived from machine properties, so a renamed OS
  user or a moved home directory was enough to reach this, and every stored account was then gone with
  no way back. A failed load now leaves the in-memory collection alone, reports itself on `loadError()`,
  and the file is copied aside to `<name>.unreadable` before any save can replace it. The copy is made
  once, so a second failure cannot overwrite the backup that holds the data, and a save that cannot make
  the copy is skipped rather than allowed to destroy the original. Applies to both `AltStore` and
  `SecretStore`.
- **The stores are safe to touch off-thread.** The account list was a plain `ArrayList` and the secret
  map a `LinkedHashMap`, both mutated from whichever pool thread a login resolved on while the host reads
  them from its render thread. They are now copy-on-write and concurrent respectively, so iterating
  `accounts()` during a login sees a snapshot instead of failing.
- **`AltStore.removeAccount` keys on the UUID** like every other mutator, rather than on whole-record
  equality plus a reference comparison for the current account. Since `AltAccount` is a record, its
  equality covers the credentials too, so a caller holding a copy read before a renewal rotated its
  tokens — the normal case — silently removed nothing.
- **The session route separates a refused token from an unreachable service.** `loginSession` collapsed
  every failure onto `INVALID_TOKEN`, so an outage was reported as a spent credential and a host
  following the documented advice to branch on the reason sent the user through a fresh interactive
  login to fix a network problem. It now reports `NETWORK` for a transport failure, matching what
  `loginAccount` already did.
- **The authorization code is decoded before it is redeemed.** The callback server matches the raw query
  string, so the captured code and state were still percent-encoded; the token exchange then encoded
  every parameter it sent, escaping those escapes and redeeming a value the service never issued.
  Current codes happen to be URL-safe, so this had not yet bitten.
- **A rejected HTTP response has its body drained.** An unread error body keeps its connection out of the
  keep-alive pool, so a run of rejections — a rate limit, a service having a bad minute — opened a fresh
  socket every time.
- **The cookie file's size cap binds the read itself**, rather than a size check taken before it. Reading
  a file to find out it was too big is the thing the cap exists to prevent, and a file that grew between
  the check and the read slipped it entirely. The read now stops one byte past the limit.
- **A cookie-file failure names the file, never the path to it.** The JDK's I/O messages are the absolute
  path, and this message travels into a `LoginResult` a host shows in its UI and writes to its log, so an
  access-denied on an export under a home directory published that directory.
- A null username handed to `loginOffline` reports `INVALID_TOKEN` rather than `UNKNOWN`, and
  `cleanToken` has its Javadoc back after it was orphaned by the refresh-token cleaner landing above it.

### Security

- **The OAuth state can no longer fall back to a guessable value.** `generateState` answered a
  `SecureRandom.getInstanceStrong()` failure with `"fallback-state-" + currentTimeMillis()`, which
  defeats the CSRF check the state exists to make: an attacker who can guess the state can feed the
  loopback callback a code of their choosing. `getInstanceStrong` also maps to a blocking entropy source
  on some platforms, so the failure it guards against is real rather than theoretical. The default
  `SecureRandom` is used instead — cryptographically strong, non-blocking, and unable to fail to
  construct, so there is nothing to fall back from.
- The browser fallback passes its URL as a discrete argument rather than as one command line, which
  `Runtime.exec` splits on whitespace.
- `SECURITY.md` now states the threat model explicitly. The local store's PBKDF2 password is derived from
  machine properties, not from a user secret: it stops a copied file being read on another machine, and
  does nothing against code already running as the same user. That was true before and is now written
  down, along with the shared vault's two documented boundaries.

### Changed

- `MicrosoftAuthConfig` gains a `redirectUri` and an `rpsTicketPrefix` component. Both default to the
  previous behaviour — no redirect on the refresh grant, a `d=` ticket — so an OAuth host sees no
  change on the wire. Hosts calling the canonical constructor rather than `of(...)` must pass the two
  new arguments.
- **`AltsRuntime.Builder.build()` now loads both stores.** It bound the directory provider and configured
  the filename but never read the file, so a host that followed the getting-started guide wired
  everything correctly and still saw an empty account list — the extra call it needed was documented
  nowhere. A host already calling `AltStore.load()` itself is unaffected, since a load clears its
  in-memory state before refilling it.

## [0.6.2] - 2026-07-28

### Fixed

- `loginRefreshToken` now sanitizes the token it is given. Refresh tokens are pasted, and they are
  routinely pasted out of account lists that prefix them with a name (`name:token`), out of an
  `Authorization` header, or out of a quoted config value. `loginSession` has always stripped that
  surrounding text; the refresh route did not, so it went to the token endpoint as part of the
  credential and came back as an invalid grant. In a password-style input the stray prefix is
  invisible, so the failure was indistinguishable from a genuinely dead token. Note that
  `loginSession`'s existing cleaner could not have covered this: it selects the `eyJ`-prefixed segment
  of a JWT and cannot recognise a refresh token.

## [0.6.1] - 2026-07-28

### Added

- `AltsRuntime.Builder.vaultTransportResolver(VaultTransportResolver)` and the matching
  `AltsRuntime.vaultTransportResolver()` accessor. The `VaultTransportResolver` SPI interface shipped in
  an earlier release with no way to install one, so the seam was unreachable: a host could implement the
  interface but never hand it to the runtime, leaving federated repositories (`avp://host/repoId`)
  resolvable in principle and unusable in practice. The wiring existed only on an unmerged branch, which
  consumers were pinning to directly. It now ships on the release line.

## [0.6.0] - 2026-07-28

Refresh tokens become a first-class credential: importable as a login route, redeemable to renew a stored
session silently, and shareable into a repository only when that repository opts in.

### Added

- **Refresh-token login route** — `AltLoginService.loginRefreshToken(refreshToken, mode)` redeems a stored
  OAuth refresh token for a live session, skipping the interactive browser step entirely.
- **Silent renewal in `loginAccount`** — a stored Microsoft account no longer dies with its access token.
  It renews from its refresh token proactively (when the expiry says the token is spent) and once
  reactively (when a token that looked live is refused, as after a password change), persisting the
  rotated credential before installing the session. Renewal never loops.
- `MicrosoftAuthUtil.authenticateWithRefreshToken(config, refreshToken)` — starts the existing Xbox Live /
  XSTS / Minecraft services chain from a `grant_type=refresh_token` exchange instead of an authorization
  code. Failures surface as `MicrosoftAuthUtil.RefreshRejectedException`, whose `permanent()` separates a
  token that will never work again (4xx) from a failure worth retrying (5xx or transport), so an outage
  never costs a user a working credential.
- `AltLoginCallback.FailureReason` (`NONE`, `UNKNOWN`, `REAUTH_REQUIRED`, `INVALID_TOKEN`, `NETWORK`,
  `NOT_CONFIGURED`) with a matching `LoginResult.failure(String, FailureReason)` factory, so a host can
  branch on the outcome instead of matching a human-readable message that obfuscation and localization
  both change.
- `TokenExpiry` — expiry arithmetic for access tokens: `SKEW_MILLIS`, `jwtExpiryMillis(String)`, and
  `isExpired(AltAccount, Clock)`. The account's stored expiry wins when known, the token's own `exp` claim
  is the fallback, and a wholly unknown expiry reads as expired, since renewing a live session is cheap and
  installing a dead one is not.
- `AltAccount.withTokens(accessToken, refreshToken, expiresAt)` and `AltAccount.hasRefreshToken()`.
- `AltAccount.mergedOnto(AltAccount existing)` — applies this account's identity and credentials onto a
  record the store already holds, so re-authenticating an alt refreshes what it logs in with while its
  bans, provenance, and shared attribution survive. A route that issues no refresh token leaves the
  stored one in place rather than clearing it.
- `AltStore.updateCredentials(AltAccount)` and `AltStore.clearRefreshToken(String uuid)` — persisting
  mutators, so a rotated token reaches disk and a spent one does not stay at rest.
- `HttpUtil.HttpResponse` (status plus parsed body, with `successful()`) and `HttpUtil.postFormForStatus`,
  which keeps the error body so a caller can classify a rejection rather than collapsing every non-2xx to
  `null`.
- `AccountNetworkUtil.fetchProfileFromToken(String token, String profileUrl)` — a host fronting Minecraft
  services with its own proxy now validates through the same route it authenticates through. The
  one-argument overload is unchanged and delegates to the public default.
- **Per-repository refresh-token sharing policy** — `SharedVault.createRepo(identity, alts,
  shareRefreshTokens)` alongside the existing two-argument form, backed by `shareRefreshTokens` on
  `VaultManifest` and `RepoContext`. Repositories withhold refresh tokens unless the manifest opts in, and
  the strip runs at the single encrypt/decrypt choke point on **both** write and read — on write so the
  credential never reaches the server, and on read so a peer running a modified build cannot push tokens
  into a repository whose policy forbids them.
- AVP conformance-vector tests (`AvpConformanceVectorsTest`). The crypto primitives and envelope
  compositions are now gated byte for byte against the published Alt Vault Protocol vectors, vendored under
  `src/test/resources/avp-vectors/` from `trqlmao/avp`: HKDF, X25519, Ed25519, the AAD and
  key-binding-message constructions, the payload AEAD, the key wrap, and the MUST-reject negative bank. The
  round-trip tests proved self-consistency; these prove interoperability with every other AVP
  implementation, so a silent change to a construction is caught.

### Fixed

- **Logging into a stored account no longer strips it.** `loginAccount` routed any account it could not
  renew — one carrying no refresh token, or any account at all when Microsoft login is unconfigured —
  through the session route, which rebuilt the record as `AccountType.SESSION` with no refresh token and
  then replaced the stored entry with that poorer copy. A non-offline account that is already stored is
  now installed as it stands, so its type, refresh token, bans, and provenance survive the login.
- **A rate-limited renewal no longer destroys the refresh token.** Redemption failures were classified as
  permanent on any 4xx, so an HTTP 429 (throttling) or 408 (request timeout) deleted a perfectly good
  credential, as did `invalid_client` / `invalid_scope`, which report a misconfigured host rather than a
  spent token. Only a stated `invalid_grant` outside those statuses is permanent now; everything else is
  transient and the credential is kept.
- **Re-authenticating a stored alt no longer resets what the store knows about it.** `AltStore.addAccount`
  replaced an existing same-UUID entry outright, so importing a refresh token for an alt the user already
  had wiped its observed bans, provenance, and shared attribution. The incoming credentials are now merged
  onto the stored record instead, via the new `AltAccount.mergedOnto(AltAccount)`.
- **A host-side failure no longer spends a refresh-token rotation.** `loginAccount`'s reactive renewal
  fired on any unsuccessful outcome from the stored-token attempt, including a `SessionInjector` that
  threw and an unreachable service. Since the token endpoint rotates the refresh token on every
  redemption, a broken injector cost the user a rotation on every attempt. Renewal is now gated on the
  failure being `INVALID_TOKEN`.
- **Records carrying credentials no longer print them.** `AltAccount`, `SessionData`, and
  `MinecraftProfile` are records, so their generated `toString` emitted the access and refresh tokens
  verbatim — and `LoginResult` embeds an `AltAccount`, so a host logging a login outcome wrote a durable
  credential to its log file. All three now redact the token fields and keep the identity fields
  readable.
- **Every HTTP request now has a deadline.** Neither executor set a connect or read timeout, so an
  endpoint that accepted a connection and then went quiet held a common-pool thread for the life of the
  process and left the login future to never complete. Connections time out after 10s connecting and 30s
  reading.
- **Redirects are no longer followed.** `HttpURLConnection` replays the caller's request properties to
  the redirect target, so a `3xx` from a profile or token endpoint sent the `Authorization: Bearer`
  header to whatever host the `Location` named. Redirect following is off on both executors; a `3xx` is
  now reported to the caller like any other non-2xx.
- **The Microsoft client id is URL-encoded** in both the authorization-code and refresh-token exchanges.
  It was interpolated raw while every other parameter was encoded, so a client id containing `&` or `=`
  injected extra form parameters into the token request.
- **Expired tokens no longer report a successful login.** The fast JWT path read a token's name and UUID
  claims without ever inspecting `exp`, so an expired token reported success, installed a dead session, and
  failed later at the server with no useful diagnostic. It now falls through to validation or renewal.
- Corrected the Alt Vault Protocol spec link in the README (`trqlmao/avp-spec` to `trqlmao/avp`).

### Security

- **Known limitation: the refresh-token sharing policy binds members, not the repository host.**
  `shareRefreshTokens` is plain manifest metadata the server serves, with no signature over it and no
  binding into the payload AAD, so a malicious or compromised host can serve `true` for a repository
  created withholding and every member will honour it. The docs previously claimed the policy held
  unconditionally; they now state the boundary. Authenticating the manifest is follow-up work.
- **Opting a repository into refresh-token sharing is effectively irreversible.** `removeMember` and
  `rotateKey` re-key future payloads, but a refresh token that already reached a member's disk cannot be
  clawed back by any protocol message — only by revoking the account at the identity provider. Now
  documented in `docs/GETTING_STARTED.md`.

### Changed

- **Breaking:** `AltAccount` gains two trailing components, `refreshToken` and `expiresAt`, so positional
  construction of the record must supply them (`AltAccount.of` is unchanged). Both are absent on accounts
  written by earlier versions, which reads as "no refresh token, expiry unknown" and therefore renews on
  first use — existing `accounts.dat` files load unchanged.
- **Breaking:** `AltLoginCallback.LoginResult` gains a trailing `FailureReason` component. The existing
  `LoginResult.failure(String)` is retained and maps to `UNKNOWN`, so only direct positional construction
  of the record breaks.
- **Breaking:** `MinecraftProfile` gains `refreshToken` and `expiresAt` components. The stamped expiry
  comes from the Minecraft services token (roughly a day), not the Microsoft OAuth token (roughly an
  hour), so a renewed account is not marked expired twenty-three hours early.
- **Breaking:** `AltLoginService` gains an abstract `loginRefreshToken` method, so any host implementing
  the interface directly must add it. Hosts using `AltsRuntime` are unaffected.
- **Breaking:** `VaultManifest` and `RepoContext` each gain a trailing `shareRefreshTokens` component.
  `SharedVault.createRepo` keeps its two-argument form, which withholds. A manifest written by an earlier
  version carries no such key and deserializes to `false`, which is the safe reading.

## [0.5.0] - 2026-06-01

### Changed

- **Breaking:** bans are now **per-server**. `AltAccount.ban: BanInfo` is replaced by `bans: Map<serverId, BanInfo>`; `banned()` now means "banned on any server" and `banned(String serverId)` checks one server; `bannedServers()` returns the banned server ids; `withBan(BanInfo)` becomes `withBan(String serverId, BanInfo)`; and `AltStore.markBanned(uuid, ban)` becomes `markBanned(uuid, serverId, ban)`. `serverId` is an opaque, host-supplied string (the same namespace as game stats) — the library performs no server detection. Old `accounts.dat` files are migrated on load: a single legacy `ban` becomes `bans = { "unknown": ban }`, so existing badges are preserved.

## [0.4.0] - 2026-06-01

### Changed

- **Breaking (crypto):** the `X25519-HKDF-SHA256-AESGCM-v1` key-wrap scheme's HKDF `info` (also the wrap GCM AAD) changed from the library-namespaced `lol.trq.alts/rdk-wrap/v1` to the vendor-neutral **`avp/rdk-wrap/v1`**, matching the published Alt Vault Protocol scheme so the wrap interoperates with any conformant implementation. Wrapped keys produced by 0.2.0/0.3.0 cannot be unwrapped by 0.4.0 and vice versa. This is safe in practice because no shared vault has been deployed yet. The change is a single constant in `X25519HkdfAesGcmKeyWrap`; nothing else moves.

## [0.3.0] - 2026-06-01

### Changed

- **Breaking:** replaced the Hypixel-specific stats surface with a server-agnostic one. `GameStats` (an ordered list of `Stat` display chips) replaces `HypixelStats` / `BedwarsStats` / `SkywarsStats`; `GameStatsSource` (with a `serverId()`) replaces `HypixelStatsSource`; and `AltsRuntime.hypixelStats()` becomes `gameStats(String serverId)`, backed by one cache per registered source. A host registers a source per server via `Builder.gameStatsSource(...)` (a duplicate server id throws). Migrate by formatting your stats into `GameStats.Stat` chips and reading them back with `gameStats(yourServerId)`.

### Added

- `StaticGameStatsSource`, a fixed in-memory `GameStatsSource` for demos and tests.
- A compiled `examples/` source set (`ExampleNetGameStatsSource`) so examples cannot drift from the API.

## [0.2.0] - 2026-06-01

### Added

- **Shared vault** (`lol.trq.alts.vault`, `lol.trq.alts.crypto`) — a zero-knowledge shared alt repository: Ed25519 identity + X25519 key-agreement (`VaultIdentity`), AES-256-GCM payloads with replay-binding AAD (`PayloadCipher`), a pluggable `KeyWrapScheme` (default `X25519HkdfAesGcmKeyWrap`), and `SharedVault` — pure client-side crypto for create / open / encrypt / decrypt / rotate-on-removal over plain transport DTOs. The server (a host-supplied `VaultTransport`) sees only ciphertext, wrapped keys, public keys, and counters.
- **Federation** (`lol.trq.alts.vault.federation`) — `RepoAddress` (`avp://host/repoId`), `InviteRequest`, and `RepoLocator` make repositories reachable across independently-hosted servers using one portable identity. New `VaultTransportResolver` SPI seam maps a host authority to a transport, so a member pointed at one server can join a repository hosted on another.
- **Provenance** — `AltAccount` gains `sourceClient` / `sourceUser`: which client a shared alt was added from and the user within it. Carried inside the encrypted payload only (the server never sees them). `AltAccount.withSource(client, user)` stamps them.
- **Anti-MITM** — `MemberEntry` gains an optional `keyBindingSig`, and `IssuerSignedKeyBindingVerifier` checks a member's served public keys against an identity-provider signature before wrapping a data key to them — for joining repositories on servers you do not operate.
- `MicrosoftAuthConfig` — the Microsoft client id, scope, redirect path, and every service endpoint are now host-supplied; wire it via `AltsRuntime.Builder.microsoftAuth(...)`.

### Changed

- **Breaking (pre-1.0):** `MicrosoftAuthUtil.authenticate()` now takes a `MicrosoftAuthConfig`. There is no built-in Microsoft client id any more — a host must supply its own Azure app id to enable Microsoft login (offline / cookie / session login are unaffected). Hosts using `AltsRuntime` only need to add `.microsoftAuth(MicrosoftAuthConfig.of(yourClientId))`.

## [0.1.0] - 2026-05-29

### Added

- Initial release.
- **Auth** (`lol.trq.alts.auth`) — Microsoft OAuth 2.0, browser-cookie, session-token, and offline login behind `AltLoginService`, all `CompletableFuture`-based.
- **Store** (`lol.trq.alts.store`) — `AltStore`, an AES-256-GCM + PBKDF2 encrypted local account file; filename and key-binding are host-configurable.
- **Cache** (`lol.trq.alts.cache`) — `AsyncCache<K,V>`, a lazy non-blocking value cache with stale-while-revalidate TTL.
- **Skin** (`lol.trq.alts.skin`) — `SkinAvatarCache<H>`, async player-head fetch/cache generic over the host texture-handle type.
- **Model** (`lol.trq.alts.model`) — `AltAccount`, `AccountType`, `LoginMode`, `SessionData`, `HypixelStats`, `BanInfo`.
- **SPI** (`lol.trq.alts.spi`) — host seams: `SessionInjector`, `VaultDirectoryProvider`, `TextureUploader<H>`, `MainThreadExecutor`, `ToastSink`, `HypixelStatsSource`.
- `AltsRuntime` wiring root with an accumulating builder.
- Spotless / palantir-java-format toolchain, JUnit 5 tests, GitHub Actions CI, and JitPack publishing manifest.

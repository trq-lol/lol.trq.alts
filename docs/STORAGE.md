# Storage and network

## Encryption

Accounts and host secrets live in two AES-256-GCM files in your directory.

**The default key is obfuscation.** It is derived from machine properties, which are not secret. Supply your own key for
real protection:

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

- With a provider, a file opens under your key or not at all. Nothing falls back to the default key.
- **Set `migrateFromMachineKey` for one launch only.** While it is on, anyone who can write to the directory can plant a
  file sealed under the guessable key.
- The key must be the same every time, and at least 16 bytes.

## A file that does not open

The library reports it on `loadError()`, keeps a copy as `<name>.unreadable.<time>` and refuses every write until a
later `load()` succeeds. Start over only when the user says so:

```java
// Only on the user's word. The old file is copied aside first, and the next write starts a new store.
if (alts.store().loadError().isPresent() && !alts.store().discardUnreadable()) {
    // The copy aside failed, so the refusal stands; saveError() says why.
    alts.store().saveError().ifPresent(failure -> showError(failure.message()));
}
```

`alts.secrets()` has the same methods. `loadWarning()` on the account store lists skipped entries, and `saveError()`
says why the last write failed.

## Proxies

A `ProxyProvider` names the route of each request, for example one proxy per account.

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

Install it with `.proxyProvider(...)`.

- **It fails closed.** A provider that throws or returns `null` fails the request. Return `ProxyRoute.direct()` when
  direct is fine.
- **A first sign-in has no UUID yet.** Use `alts.loginService().routed(tag)`, or `BulkOptions.withRouteTag(tag)`, and
  read `scope.routeTag()`.
- **HTTP proxies work with or without a password**, through a `CONNECT` tunnel. The password goes to the proxy only, and
  is not encrypted on the way there.
- **SOCKS5 works without a password only.** Adding credentials throws.
- **DNS can leak.** The JVM also looks up the target host locally.
- `NtpTimeSource` does not use the provider.

## Threads and shutdown

- Blocking work runs on the runtime's executor: virtual threads by default, or your own with `.executor(...)`.
- **Callbacks do not run on your main thread.** One usually runs on the executor, or on the calling thread if the future
  was already done.
- The stores write 100 ms after a change. `save()` and `flush()` write at once.
- `close()` flushes the stores, releases their locks and refuses new work with `CANCELLED`. It leaves your own executor
  running.
- Failures caused by `close()` run on the thread that calls it. Do not block there on something only `close()` releases.
- A normal exit flushes the stores without `close()`. Call `flush()` before an exit that skips shutdown hooks.

## Builder options

| Option | Purpose |
|---|---|
| `accountEndpoints` | Point account services and lookup at another base |
| `executor` | Your own executor |
| `proxyProvider` | Route requests |
| `avatarSource`, `avatarUrlTemplate` | Where faces come from |
| `storeKeyProvider`, `migrateFromMachineKey` | The store key |
| `storeFileName`, `storeKeyBinding` | Keep an existing account store |
| `secretsFileName`, `secretsKeyBinding` | Keep an existing secrets file |
| `vaultHostAddress` | Where a vault host is reached |

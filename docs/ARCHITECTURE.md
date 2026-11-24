# Architecture

For contributors. To use the library, start with [getting started](GETTING_STARTED.md).

## Layers

```
host            implements spi/
spi/            session, directory, main thread, toasts, proxy, store key, ...
AltsRuntime     builds and owns everything below
public API      auth  account  bulk  store  vault  net  time  cache  skin  model
internal/       transport, sign-in chains, store files, crypto, vault engine
```

- **`AltsRuntime<H>`** validates the required seams, locks the stores, then builds the executor, transport and services.
  A failed build releases what it opened. `H` is the host's texture type.
- **Nothing is process-wide.** Two runtimes on two directories share no state, connection or thread.
- **`spi/`** is the whole host boundary. A method added to one of its interfaces needs a default.
- **`auth/`** has `AltLoginService`, which installs a session, and `AltAccountService`, which only checks or renews.
- **`account/`** works over a live token and touches neither the session nor the store.

## Module and API

The jar is the module `lol.trq.alts`. It exports twelve API packages and nothing under `internal`. It opens three
packages, to Gson only.

- `ModulePathConsumerTest` shows that an internal import does not compile on the module path.
- On the class path the jar is sealed, so no other jar can add classes to its packages.
- `javadocCheck` fails on an internal type in the published Javadoc.
- `apiCheck` compares the jar with `api/lol.trq.alts.api`. `apiDump` records an intended addition, and refuses to erase
  lines within a major version unless given `-PapiAllowBreaking=<reason>`.

Public types that only the runtime may build have no factory. Each package has a package-private bridge, which an
`internal.*Access` class accepts once and only from the library's own class loader.

`check` runs the tests on the class path and again as a named module.

## Threading

- Blocking work runs on the runtime's executor, never the common pool.
- Every delay goes through the transport, so `close()` can end it.
- `SessionInjector` is called off the main thread. Texture uploads use `MainThreadExecutor`.
- Each store writes on its own daemon thread, and a shutdown hook flushes it.
- Avatars have at most six fetches in flight, as a queue rather than blocked threads.
- A bulk run is a fixed number of worker chains over one cursor.
- The account list is copy-on-write: iterating it during a sign-in sees a snapshot.
- `close()` is idempotent. Whatever was waiting fails on the calling thread.

## Store

- **Format:** AES-256-GCM with a PBKDF2 key, derived once per store, and a fresh nonce per write.
- **Lock:** an exclusive lock on `<name>.lock` while the runtime is open.
- **Write:** to `<name>.tmp`, forced to disk, then moved into place. Snapshots are ordered, so an older one never wins.
  The previous good file becomes `<name>.bak`. Files are owner-only on POSIX.
- **Unreadable file:** memory is left alone, the file is copied aside (the newest five copies are kept) and writes are
  refused until a load succeeds, the file is gone or the host calls `discardUnreadable()`.
- **Key provider:** fails closed. Migration rewrites the store, its backup and its unreadable copies under the new key.
- **Errors:** stores throw nothing for I/O. They report on `loadError()`, `loadWarning()` and `saveError()`.

## Transport

Every HTTP request goes through one `HttpTransport` per runtime.

- **Timeouts:** 10 s to connect, 30 s to read.
- **Routing:** asks the `ProxyProvider` per request, and fails closed. A direct route still follows the JVM's own proxy
  configuration.
- **Tunnel:** an HTTPS target behind an HTTP proxy uses the library's own `CONNECT`, because the JDK cannot authenticate
  per request without global state. Connections are never shared between proxy identities.
- **Redirects:** JDK following is off. Only binary fetches follow them: five hops at most, never from HTTPS to HTTP, and
  without credentials across origins.
- **Limits:** 1 MiB for JSON and text, 16 MiB for vault exchanges.
- **Headers:** control characters and a caller's `Proxy-Authorization` are refused.
- **Rate limits:** `Retry-After` is read as seconds or as a date measured against the response's `Date`.
- **Closing:** tunnels close and new requests are refused. Connections the JDK pools itself stay with the JDK.
- No system property, authenticator, `SSLContext` or proxy selector is installed.

## Errors

One value, `AltsFailure`, and one unchecked exception, `AltsException`.

1. An outcome the caller branches on is a result with `failure()`. It never throws, even on a closed runtime.
2. Everything else throws `AltsException`.
3. Stores report instead of throwing.

A message never contains a token, cookie, code, path, a service's text or a transport exception's text. Messages are not
a contract; kinds are. `ErrorKindMigrationTableTest` pins the kinds that replaced the 0.12 constants.

## Bulk runs

Only `NETWORK` is retried, with jittered backoff. A rate limit ends the run, or pauses all of it. A run cut short reports
every unfinished entry as `CANCELLED`. A throwing `started` callback fails its entry, and other callback exceptions are
ignored. An `Error` cuts the run short.

## Vault

A client for [AVP 0.5](https://github.com/trqlmao/avp). `internal.avp` holds the constructions, `internal.vault` the
engine and `vault/` the public handles.

- **Data:** an owner-signed chain of states and a graph of member-signed commits. Accounts merge per field by a hybrid
  logical clock.
- **Verification:** every state from genesis and every commit, with strict Ed25519. A host's acceptance is never
  trusted.
- **Pin:** a chain without the pinned state is refused, unless it diverges at or below the pin and wins the tie rule,
  which only two offline owner devices can cause. `divergedAt()` reports it.
- **Failing closed:** one bad state fails the whole operation and nothing from that pull is adopted.
- **Hosts** are matched by key. Bearer tokens are cached per host key and origin.
- **Profiles:** HTTP/JSON on the runtime's transport, or gRPC over the host's `VaultRpcChannel` when
  `vaultHostAddress` maps a locator to `grpc://` or `grpcs://`. Both share every client rule.
- **Refresh tokens:** the policy is inside the signed state. When it is off, the engine strips the tokens from everything
  it encrypts, decrypts or merges.
- **0.4 import:** read-only, with no rollback floor.

The AVP test vectors under `src/test/resources/avp-vectors/` gate the constructions byte for byte.

## Design rules

- Only the JDK and Gson. No Minecraft, renderer or consumer types.
- DTOs are records with `@SerializedName` on every component. Types expected to grow are final classes with factories.
- The names and order of `AltAccount`'s fields are the store format.
- Optional features return `null` when their seam is missing.
- No statics for state.

# AGENTS.md

See [CLAUDE.md](CLAUDE.md) for the full guidance: mental model, patterns, and pitfalls. The short
version for any agent working here:

- This is a **published, consumer-agnostic account library** for Minecraft: Java Edition. Never
  reference a specific consuming application, client, product, sync server, or hosted instance, and
  never name another authentication library, launcher or tool, in source, comments, docs, tests, or
  commit messages. Provenance fields and `avp://` locators define field names only; the real values
  are host-supplied at runtime. CI fails the build on a leak.
- **The boundary is `spi/`.** The library never imports a host type. If a change seems to need one, it
  needs a new seam. Only the JDK, Gson, and `lol.trq.alts` may be imported.
- **The runtime owns all state.** Each `AltsRuntime` builds its own `AccountStore` (`alts.store()`),
  `HostSecrets` (`alts.secrets()`), transport and executor, and passes them to services through
  constructors. There are no statics to reach for. `AltsRuntime` is `AutoCloseable`; `close()` flushes
  and unlocks the stores and ends whatever waits on the runtime.
- **Never export `internal`.** Implementation lives under `lol.trq.alts.internal`, which the module does
  not export and the Javadoc leaves out. `api/lol.trq.alts.api` is the frozen API: `apiCheck` fails a
  removed or changed line, or new API missing from the dump (`./gradlew apiDump` records an intended
  addition).
- **No secrets, no IDE files, no machine paths.** Never commit API keys, tokens, `.idea/`, or `*.iml`.
  Host-side seams supply every credential.
- **Failures are one type.** A failure is an `AltsFailure`; branch on `failure.kind()`, never on a
  message string. Results carry it as `failure()`, everything else throws `AltsException`, and a future
  completes exceptionally with nothing else. Keep a refused credential (`UNAUTHORIZED` /
  `REAUTH_REQUIRED`), an unreachable service (`NETWORK`) and a throttle (`RATE_LIMITED`) apart.
- **Messages never repeat a transport exception.** Use `internal.net.FailureText.of(failure)`; the JDK
  quotes tokens and paths in its own messages.
- **Credentials are handled carefully.** A refresh token is durable: redact it from `toString`, discard it
  only on a stated `invalid_grant`, and never write it for an account the store does not already hold. A
  store file that did not load is never written over until a load succeeds or the host calls
  `discardUnreadable()`, and each store file is locked to one runtime.
- **One way out, one executor, per runtime.** Requests go through the runtime's `HttpTransport`;
  blocking work runs on its executor, never the common pool. Proxy resolution fails closed.
- **The vault trusts no host.** AVP 0.5: verify every state and commit, wrap only to invite-token keys.
  A forged state or a rollback fails the whole operation with `PROTOCOL`; a forged commit is discarded
  (neither merged nor a parent) and counted in the report. Constructions are gated by the vendored
  vectors; do not change one casually.
- **Test seams** are package-private and need no system property. A test builds and closes its own
  runtime, store or transport; from other packages use `StoreTestHooks`, `StoreFileSeams`,
  `TestTransports` and the vault's `TestAvpHost`. `check` runs the suite on the class path and again on
  the module path.
- **Style:** palantir-java-format (4-space, 120-col), records for DTOs with `@SerializedName` on every
  component, full Javadoc with one `@since` per exported declaration. Run `./gradlew spotlessApply`, then
  `./gradlew check`.
- **Docs snippets are compiled.** Change the method in `examples/` first, then the guide that inlines it.
- **Commits:** Conventional Commits, one logical change each, and never a `Co-Authored-By` or any other
  AI-attribution trailer. You own what you ship.

# AGENTS.md

See [CLAUDE.md](CLAUDE.md) for the full guidance: mental model, patterns, and pitfalls. The short
version for any agent working here:

- This is a **published, consumer-agnostic account library** for Minecraft: Java Edition. Never
  reference a specific consuming application, client, product, sync server, or hosted instance, and
  never name another authentication library, launcher or tool, in source, comments, docs, tests, or
  commit messages. Provenance fields and `avp://` addresses define field names only; the real values
  are host-supplied at runtime. CI fails the build on a leak.
- **The boundary is `spi/`.** The library never imports a host type. If a change seems to need one, it
  needs a new seam. Only the JDK, Gson, and `lol.trq.alts` may be imported.
- **No secrets, no IDE files, no machine paths.** Never commit API keys, tokens, `.idea/`, or `*.iml`.
  Host-side seams supply every credential.
- **Failures are typed.** Branch on `AltLoginCallback.FailureReason`, never on a message string, and keep
  a refused credential (`INVALID_TOKEN` / `REAUTH_REQUIRED`), an unreachable service (`NETWORK`) and a
  throttle (`RATE_LIMITED`) classified apart.
- **Messages never repeat a transport exception.** Use `FailureText.of(failure)`; the JDK quotes tokens
  and paths in its own messages.
- **Credentials are handled carefully.** A refresh token is durable: redact it from `toString`, discard it
  only on a stated `invalid_grant`, and never write it for an account the store does not already hold. An
  unreadable store file is never overwritten, and nothing is written while a host store key is
  unavailable.
- **One way out, one executor.** Requests go through `HttpUtil`; blocking work runs on
  `IoExecutor.executor()`, never the common pool. A `null` never removes an installed proxy provider,
  executor or store key.
- **Test seams** are package-private and need `-Dlol.trq.alts.testSeams=true`, which the Gradle `test`
  task sets. Use `NetTestHooks` and `StoreTestHooks` from other test packages.
- **Style:** palantir-java-format (4-space, 120-col), records for DTOs with `@SerializedName` on every
  component, full Javadoc with `@since`. Run `./gradlew spotlessApply`, then `./gradlew check`.
- **Docs snippets are compiled.** Change the method in `examples/` first, then the guide that inlines it.
- **Commits:** Conventional Commits, one logical change each, and never a `Co-Authored-By` or any other
  AI-attribution trailer. You own what you ship.

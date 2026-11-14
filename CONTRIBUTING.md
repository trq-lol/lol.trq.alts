# Contributing to lol.trq.alts

Thanks for your interest in contributing!

## Getting started

1. Fork the repository and clone your fork.
2. Ensure you have **JDK 25** installed.
3. Build: `./gradlew build`.

## Development workflow

- **Format before committing:** `./gradlew spotlessApply`. CI rejects unformatted code.
- **House style:** palantir-java-format (4-space indent, 120-column limit). Records for DTOs with `@SerializedName` on every component. Full Javadoc on public and protected members.
- **Tests:** add JUnit 5 tests for new behaviour; run `./gradlew test`. Tests pin what the design and the protocol specify, not what the code happens to do.
- **Test seams:** there is no process-wide state and no system property to set. A test builds its own runtime, store or transport, and closes it. The hooks that remain (`Builder.afterStoresOpenForTests`, `StoreFile.beforeWriteForTests`, `fileForTests`, `SharedVault.engineForTests`, the transport's TLS override for a loopback certificate) are package-private. From another test package, reach them through the helpers in the test sources: `StoreTestHooks` and `StoreFileSeams` for the stores, `TestTransports` for a transport (direct, routed, on a given executor, or trusting a loopback certificate), `AccountStoreTestSupport` for the sign-in tests, and `TestAvpHost` / `VaultWorld` for an in-process AVP 0.5 host. A test run from an IDE needs nothing extra.
- **Network in tests:** tests talk to loopback and scripted servers only, never to the live services. Do not describe a flow as verified against a live service unless it was.
- **Blocking work:** pass the runtime's executor (`transport.executor()`) to `supplyAsync` and `runAsync`, and wait through the transport's `delay` or `schedule`, which `close()` ends. Nothing runs on the common pool, and nothing reaches for a static.
- **Internal code:** implementation goes under `lol.trq.alts.internal`, which the module never exports. No exported signature may name an internal type.
- **Keep it host-agnostic:** the library must never import or reference a specific consuming application, must not name other authentication libraries, launchers or tools, and must never hold secrets. Credentials and API keys come from host-implemented seams.

## The gate

`./gradlew check` is what CI runs, and it is more than the tests:

- **`test` and `moduleTest`.** The suite runs twice: on the class path, and again with the jar as the named module `lol.trq.alts` and the tests patched into it, so a missing `requires` or `opens` in `module-info.java` fails. `ModulePathConsumerTest` compiles a consumer module against the jar and checks that an internal import does not compile.
- **`apiCheck`.** `api/lol.trq.alts.api` is the committed dump of the exported API, one line per type, record component, constant, field, constructor and method. The check fails when a line is removed or changed while the build's major version is not greater than the dump's, when the jar has API the dump lacks, when an internal package is exported, or when an exported signature names an internal type. An intended addition is recorded with `./gradlew apiDump`; commit the dump with the change and review its diff as the API review it is.
- **`apiDump`'s refusals.** It reads the existing dump first and refuses to write one that erases lines within the same major version, to replace a missing or headerless baseline, or to write one for a major above the build's. A deliberate break inside a major is possible only with `-PapiAllowBreaking=<reason>`, and the reason is written into the dump's header for review. A new abstract method on an `spi` seam passes the gate but breaks every host that implements the seam: give it a default.
- **`apiToolTest`** tests the gate itself.
- **`javadocCheck`.** The published Javadoc documents the exported packages only; the check fails on any internal entry or reference in the javadoc jar.
- **`SinceTagsTest`** (in `test`) requires exactly one `@since` naming a release on every exported declaration.
- **`ErrorKindMigrationTableTest`** (in `test`) pins the CHANGELOG's error-kind table row for row.
- **`compileExamplesJava`** compiles `examples/` with `-Xlint:deprecation -Werror`, and `spotlessCheck` holds it to the house style.

Run `./gradlew check --rerun-tasks` before calling something done: an up-to-date run proves nothing about the change.

**Proving a test bites.** For a change to a security rule or a protocol check, mutate a scratch copy of the tree (never the working tree), one mutant at a time, run the affected tests with `--rerun-tasks`, and keep a test for every mutant that survived and should not have.

## Commit messages

This project uses [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <summary>
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`. Breaking changes append `!` and a `BREAKING CHANGE:` footer.

Keep the subject under ~72 characters, lowercase after the colon, imperative mood, no trailing period. One logical change per commit — if two types fit, it is two commits.

## Commit ownership

**You are the responsible author of every commit you ship, including code an AI wrote.** AI assistance is a tool, not a co-author: commits must never carry a `Co-Authored-By: <assistant>` or any other AI-attribution trailer, and a commit that has one should be rewritten before it is pushed.

Owning the commit means reviewing what was produced as if you had written it — its correctness, its security, and what it might leak. This matters more than usual here, because the library holds credentials and is published.

## Documentation

Every multi-line Java snippet in [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) is inlined from a method in [`examples/`](examples/), which the `examples` source set compiles on every build with `-Xlint:deprecation -Werror`. Change the example first, then the guide, so that an API change breaks the build and the docs cannot drift. An example may not use deprecated API.

New public and protected members need Javadoc with an `@since` carrying the version they will first ship in, a line in the API dump (`./gradlew apiDump`), and a `CHANGELOG.md` entry under `[Unreleased]`. Within 1.x a host-visible member is never removed or changed; a change a host has to act on (a changed default, a new behaviour) goes in that release's upgrade notes.

## Releases

A release is a `build: release X.Y.Z` commit that:

1. sets `version` in `build.gradle`;
2. runs `./gradlew apiDump`, so the dump's header names the release and every addition since the last one is recorded (a major release may also drop lines);
3. dates the changelog heading (`## [X.Y.Z] - YYYY-MM-DD`);
4. passes `./gradlew check --rerun-tasks`.

It is followed by a `vX.Y.Z` tag on that commit. CI builds the tag and publishes a GitHub release whose notes are that changelog section, so the heading has to match the tag's version exactly.

## Pull requests

- Keep PRs focused on a single change.
- Ensure `./gradlew build` passes (compile, both test runs, the API and Javadoc checks, the examples, spotlessCheck).
- Describe the motivation and the approach in the PR body.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).

# Contributing to lol.trq.alts

Thanks for your interest in contributing!

## Getting started

1. Fork the repository and clone your fork.
2. Ensure you have **JDK 25** installed.
3. Build: `./gradlew build`.

## Development workflow

- **Format before committing:** `./gradlew spotlessApply`. CI rejects unformatted code.
- **House style:** palantir-java-format (4-space indent, 120-column limit). Records for DTOs with `@SerializedName` on every component. Full Javadoc on public and protected members.
- **Tests:** add JUnit 5 tests for new behaviour; run `./gradlew test`.
- **Test seams:** the resets tests rely on (removing the proxy provider, the executor, the store key, the TLS trust) are package-private and refuse to work unless the JVM carries the `lol.trq.alts.testSeams=true` system property. The Gradle `test` task sets it. A test run from an IDE needs `-Dlol.trq.alts.testSeams=true` added to its JVM arguments. From another test package, reach the seams through `NetTestHooks` and `StoreTestHooks` in the test sources, and reset whatever a test installed: binding `null` does not remove a provider.
- **Network in tests:** tests talk to loopback and scripted servers only, never to the live services. Do not describe a flow as verified against a live service unless it was.
- **Blocking work:** pass `IoExecutor.executor()` to `supplyAsync` and `runAsync`. Nothing runs on the common pool.
- **Keep it host-agnostic:** the library must never import or reference a specific consuming application, must not name other authentication libraries, launchers or tools, and must never hold secrets. Credentials and API keys come from host-implemented seams.

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

New public and protected members need Javadoc with an `@since` carrying the version they will first ship in, and a `CHANGELOG.md` entry under `[Unreleased]`. A change a host has to act on (a removed method, a record that gained a component, a changed default) also goes in that release's "Upgrading" block.

## Releases

A release is a `build: release X.Y.Z` commit that sets `version` in `build.gradle` and dates the changelog heading (`## [X.Y.Z] - YYYY-MM-DD`), followed by a `vX.Y.Z` tag on that commit. CI builds the tag and publishes a GitHub release whose notes are that changelog section, so the heading has to match the tag's version exactly.

## Pull requests

- Keep PRs focused on a single change.
- Ensure `./gradlew build` passes (compile + test + spotlessCheck).
- Describe the motivation and the approach in the PR body.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).

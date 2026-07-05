# Contributing to Extension Guard

Thanks for your interest in contributing! Extension Guard is a native companion
that locks browser extensions in place via enterprise force-install policy, with
a tamper-resistant service on **Windows** and **Linux**. This guide covers how
to get set up, the conventions we follow, and how to submit changes.

By participating in this project you agree to abide by our
[Code of Conduct](CODE_OF_CONDUCT.md).

## Ways to contribute

- **Report bugs** — open an issue with clear reproduction steps, your OS and
  browser versions, and the relevant output of `guard verify` / `guard detect`.
- **Suggest features** — open an issue describing the use case before writing
  code, so we can agree on the approach.
- **Fix issues / add features** — see the workflow below.
- **Improve docs** — README, the `docs/` folder, and these community files.

> ⚠️ **Security issues do not belong in public issues.** If you find a way to
> bypass the guard, escalate privileges, or defeat the uninstall password,
> please follow our [Security Policy](SECURITY.md) instead.

## Development setup

This is a single Go codebase; OS-specific behavior is selected at build time via
Go build tags (`*_windows.go` / `*_linux.go`), so it is one app, not two.

### Prerequisites

- **Go 1.25+**
- **Node.js LTS** — used by [Wails](https://wails.io) for the status UI
- **Wails CLI** — `go install github.com/wailsapp/wails/v2/cmd/wails@latest`
- **Windows only:** Inno Setup 6 (installer) and the WebView2 runtime
- **Linux only:** `build-essential libgtk-3-dev libwebkit2gtk-4.1-dev`

### Build & test

The Go core builds and tests on any platform:

```sh
go test ./...
go build ./cmd/guard
```

Full release artifacts:

```powershell
# Windows: tests, then guard.exe + status UI + installer into release\
powershell -ExecutionPolicy Bypass -File build.ps1
```

```sh
# Linux: guard + status UI + config into release-linux/
bash build-linux.sh
```

The `guard` engine is cross-compile-friendly, but the Wails status UI links
native GTK/WebKit on Linux and WebView2 on Windows, so the UI must be built on
its target OS.

## Making changes

1. **Fork** the repository and create a branch from `main`:
   `git checkout -b feat/short-description` (or `fix/…`, `docs/…`).
2. **Keep changes focused.** One logical change per pull request.
3. **Match the surrounding code** — naming, structure, and comment density.
4. **Respect the platform split.** Windows-only code goes in `*_windows.go`,
   Linux-only in `*_linux.go`, and shared fallbacks in `*_other.go`. Keep the
   cross-platform interface identical so both builds stay in sync.
5. **Add or update tests** for behavior changes. Table-driven tests are the norm
   in this repo (see the existing `*_test.go` files).
6. **Update docs** when you change user-facing behavior, CLI flags, or config.

## Commit messages

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<optional scope>): <short summary>
```

Common types: `feat`, `fix`, `docs`, `refactor`, `test`, `build`, `chore`.
Examples from this repo:

```
docs(desktop): document Windows install + Linux build/install in README
feat(policy): support multiple extensions per browser
fix(watcher): re-apply policy within milliseconds on tamper
```

Keep the summary in the imperative mood and under ~72 characters.

## Pull requests

Before opening a PR, please make sure:

- [ ] `go test ./...` passes.
- [ ] `go build ./cmd/guard` succeeds (and the UI builds if you touched it).
- [ ] Code is formatted with `gofmt` (`gofmt -l .` reports nothing).
- [ ] `go vet ./...` is clean.
- [ ] New behavior is covered by tests and reflected in the docs.
- [ ] The PR description explains **what** changed and **why**, and links any
      related issue.

A maintainer will review your PR. Please be responsive to feedback — small,
well-scoped PRs get merged fastest.

## License

By contributing, you agree that your contributions will be licensed under the
[MIT License](../LICENSE) that covers this project.

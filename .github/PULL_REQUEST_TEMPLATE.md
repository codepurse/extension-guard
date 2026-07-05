<!--
Thanks for contributing! Please read CONTRIBUTING.md first.
Keep the PR focused on one logical change.
-->

## Summary

<!-- What does this PR change, and why? -->

## Related issue

<!-- e.g. Closes #123 -->

## Type of change

- [ ] 🐛 Bug fix (non-breaking change that fixes an issue)
- [ ] ✨ New feature (non-breaking change that adds functionality)
- [ ] 💥 Breaking change (fix or feature that changes existing behavior)
- [ ] 📝 Documentation only
- [ ] 🧹 Refactor / chore (no user-facing behavior change)

## Platforms affected

- [ ] Windows
- [ ] Linux
- [ ] Cross-platform / shared code

## How was this tested?

<!-- Commands run, manual steps, OS/browser versions used to verify. -->

## Checklist

- [ ] `go test ./...` passes
- [ ] `go build ./cmd/guard` succeeds (and the status UI builds if I touched it)
- [ ] `gofmt -l .` reports nothing and `go vet ./...` is clean
- [ ] Platform-specific code stays behind the correct build tags (`*_windows.go` / `*_linux.go` / `*_other.go`) with a matching cross-platform interface
- [ ] Tests added/updated for behavior changes
- [ ] Docs updated (README / `docs/` / config) for user-facing changes
- [ ] This PR does **not** disclose a security vulnerability (those go through the [Security Policy](SECURITY.md))

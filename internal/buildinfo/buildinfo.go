// Package buildinfo carries the compiled-in build metadata shared by the guard
// CLI/service and the status window. Version is overwritten at build time via
//
//	-ldflags "-X github.com/codepurse/extension-guard/internal/buildinfo.Version=<v>"
//
// (see build.ps1, which reads the repo-root VERSION file). A plain `go build`
// leaves the "dev" sentinel, which the updater treats as older than every real
// release and never auto-applies over.
package buildinfo

// Version is the semantic version of this build (e.g. "1.2.0"), or "dev" for an
// un-stamped local build.
var Version = "dev"

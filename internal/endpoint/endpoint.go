// Package endpoint centralizes the remote URLs the guard talks to - the update
// manifest and the announcement document.
//
// Why this exists: every shipped binary carries its network endpoints compiled
// in, and there is no way to repoint an install that is already in the field. If
// those endpoints name a GitHub repository directly, the repository's name
// becomes permanently load-bearing: renaming it breaks the announcement channel
// (raw.githubusercontent.com does not follow repository rename redirects) and
// leaves the old name claimable by someone who would then control the URL our
// updater trusts. Routing through a host we own removes that coupling - the repo
// can be renamed, moved, or replaced without stranding a single install.
//
// Base is deliberately empty until a domain is available. While it is empty the
// callers fall back to their original GitHub URLs, so this package can ship
// (and start propagating) before DNS exists; the day Base is filled in, every
// build carrying it switches over with no further code change.
package endpoint

import "strings"

// Base is the root URL serving the guard's remote documents, without a trailing
// slash - for example "https://updates.example.com". Empty means "not yet
// configured": callers use their legacy GitHub URLs instead.
//
// It is a var so tests can point it at a local server.
//
// TODO: set this to the real host once the domain is registered. That single
// edit is what frees the repository name; see docs/endpoints.md.
var Base = ""

// Configured reports whether a base URL has been set.
func Configured() bool { return strings.TrimSpace(Base) != "" }

// join appends a path to Base, tolerating a trailing slash on Base.
func join(path string) string {
	if !Configured() {
		return ""
	}
	return strings.TrimRight(strings.TrimSpace(Base), "/") + path
}

// Latest returns the URL of the update manifest, or "" when unconfigured.
func Latest() string { return join("/latest.json") }

// Announcement returns the URL of the announcement document, or "" when
// unconfigured.
func Announcement() string { return join("/announcement.json") }

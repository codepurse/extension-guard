// Package updater checks GitHub Releases for a newer Extension Guard build,
// downloads and integrity-checks the binaries, and swaps them into place.
//
// The swap is deliberately cooperative. Because the guard runs as a self-healing
// service (watchdog + SCM recovery), the live binaries cannot simply be
// overwritten - the service holds guard.exe open and the watchdog fights any
// restart. Windows won't overwrite or delete a running .exe, but it *will* let
// you rename one (even the caller's own image), so SwapFiles moves each old
// binary aside and drops the new one in its place; the caller (cmd/guard's
// "update" command) pauses the watchdog via the "updating" sentinel, stops the
// service, swaps, then restarts so the new image loads. See guardsvc for the
// watchdog stand-down.
//
// Integrity today rests on a SHA-256 manifest served over HTTPS from the
// release. That catches corruption and casual tampering, but it is NOT a
// substitute for Authenticode code signing: a compromised release could publish
// a matching hash. Signing is a hard prerequisite before enabling silent
// auto-apply in the wild (see docs/pc-version.md) - which is why the service
// defaults to "notify" rather than "apply".
package updater

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Repo is the GitHub "owner/name" the updater queries; apiBase is the API root.
// Both are vars so tests can point them at a local server.
var (
	Repo    = "codepurse/extension-guard"
	apiBase = "https://api.github.com"
)

const (
	userAgent   = "ExtensionGuard-Updater"
	httpTimeout = 60 * time.Second
	maxJSON     = 1 << 20 // 1 MiB cap on release/manifest JSON
)

// FileHash pins one release binary to its expected SHA-256 (lower-case hex).
type FileHash struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

// Manifest is the manifest.json asset attached to each release. Version mirrors
// the release tag without a leading "v"; Files lists the SHA-256 of every binary
// the updater may download.
type Manifest struct {
	Version string     `json:"version"`
	Notes   string     `json:"notes"`
	Files   []FileHash `json:"files"`
}

// Asset is one downloadable release file resolved to its URL and expected hash.
type Asset struct {
	Name   string
	URL    string
	SHA256 string
}

// Release is the resolved "latest release" the updater acts on.
type Release struct {
	Version string
	Notes   string
	Assets  []Asset
}

// Newer reports whether this release is strictly newer than the running build.
func (r Release) Newer(current string) bool { return Compare(r.Version, current) > 0 }

// Asset returns the named asset, or ok=false if the release doesn't carry it.
func (r Release) Asset(name string) (Asset, bool) {
	for _, a := range r.Assets {
		if strings.EqualFold(a.Name, name) {
			return a, true
		}
	}
	return Asset{}, false
}

// ghRelease mirrors the fields of the GitHub "latest release" response we use.
type ghRelease struct {
	TagName string `json:"tag_name"`
	Body    string `json:"body"`
	Assets  []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

// CheckLatest fetches the latest published release and resolves its binaries and
// expected hashes from the attached manifest.json. It does NOT download the
// binaries - callers decide whether the version warrants that.
func CheckLatest(ctx context.Context) (Release, error) {
	var rel Release
	var gh ghRelease
	if err := getJSON(ctx, apiBase+"/repos/"+Repo+"/releases/latest", &gh); err != nil {
		return rel, err
	}

	urls := make(map[string]string, len(gh.Assets))
	manifestURL := ""
	for _, a := range gh.Assets {
		urls[a.Name] = a.URL
		if strings.EqualFold(a.Name, "manifest.json") {
			manifestURL = a.URL
		}
	}
	if manifestURL == "" {
		return rel, fmt.Errorf("release %s has no manifest.json asset", gh.TagName)
	}

	var m Manifest
	if err := getJSON(ctx, manifestURL, &m); err != nil {
		return rel, fmt.Errorf("read manifest: %w", err)
	}

	rel.Version = normalizeVersion(firstNonEmpty(m.Version, gh.TagName))
	rel.Notes = firstNonEmpty(m.Notes, gh.Body)
	if rel.Version == "" {
		return rel, fmt.Errorf("release %s has no usable version", gh.TagName)
	}
	for _, f := range m.Files {
		url, ok := urls[f.Name]
		if !ok {
			return rel, fmt.Errorf("manifest lists %q but the release has no such asset", f.Name)
		}
		rel.Assets = append(rel.Assets, Asset{Name: f.Name, URL: url, SHA256: strings.ToLower(strings.TrimSpace(f.SHA256))})
	}
	return rel, nil
}

// Stage downloads the named assets into dir as "<name>.new", verifying each
// against its manifest SHA-256. It returns the staged paths keyed by asset name.
// On any failure it removes whatever it staged, so a partial download is never
// left behind. dir should be the install directory so the later rename-in-place
// swap stays on one volume (a cross-volume rename would fail).
func (r Release) Stage(ctx context.Context, dir string, names ...string) (map[string]string, error) {
	staged := make(map[string]string, len(names))
	cleanup := func() {
		for _, p := range staged {
			_ = os.Remove(p)
		}
	}
	for _, name := range names {
		a, ok := r.Asset(name)
		if !ok {
			cleanup()
			return nil, fmt.Errorf("release %s has no asset %q", r.Version, name)
		}
		dest := filepath.Join(dir, name+".new")
		sum, err := downloadTo(ctx, a.URL, dest)
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("download %s: %w", name, err)
		}
		if a.SHA256 != "" && sum != a.SHA256 {
			_ = os.Remove(dest)
			cleanup()
			return nil, fmt.Errorf("%s failed its integrity check (want %s, got %s)", name, a.SHA256, sum)
		}
		staged[name] = dest
	}
	return staged, nil
}

func httpClient() *http.Client { return &http.Client{Timeout: httpTimeout} }

// getJSON issues a GET and decodes a (size-capped) JSON body into v. GitHub
// requires a User-Agent; the Accept header pins the stable API media type.
func getJSON(ctx context.Context, url string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxJSON))
	if err != nil {
		return err
	}
	// Strip a leading UTF-8 BOM before decoding: PowerShell's Out-File and many
	// editors prepend one, and encoding/json rejects a BOM-prefixed document.
	// GitHub's own API responses have none, so this only helps the manifest.
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
	return json.Unmarshal(data, v)
}

// downloadTo streams url into dest, returning the lower-case hex SHA-256 of the
// bytes written. On error it removes the partial file.
func downloadTo(ctx context.Context, url, dest string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := httpClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	f, err := os.Create(dest)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, h), resp.Body); err != nil {
		f.Close()
		_ = os.Remove(dest)
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(dest)
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Compare returns -1, 0, or 1 as a is less than, equal to, or greater than b,
// comparing dotted numeric versions ("1.10.0" > "1.9.0"). A leading "v" and any
// pre-release/build suffix ("-rc1", "+meta") are ignored. The sentinel "dev" (an
// un-stamped local build) parses to 0.0.0, so a dev build sorts below every real
// release.
func Compare(a, b string) int {
	pa, pb := parseVersion(a), parseVersion(b)
	for i := 0; i < 3; i++ {
		switch {
		case pa[i] < pb[i]:
			return -1
		case pa[i] > pb[i]:
			return 1
		}
	}
	return 0
}

func parseVersion(s string) [3]int {
	s = normalizeVersion(s)
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	var out [3]int
	for i, part := range strings.SplitN(s, ".", 3) {
		if i > 2 {
			break
		}
		n, _ := strconv.Atoi(strings.TrimSpace(part))
		out[i] = n
	}
	return out
}

func normalizeVersion(s string) string {
	return strings.TrimPrefix(strings.TrimSpace(s), "v")
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

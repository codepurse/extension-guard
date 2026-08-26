// Package announce fetches a small remote "announcement" document from a static
// URL so the status window can show occasional messages - a promo, a heads-up, a
// migration notice - without shipping a new build. It is best-effort and
// read-only: any error yields an inactive announcement so the UI simply shows
// nothing.
package announce

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/codepurse/extension-guard/internal/endpoint"
)

// LegacySourceURL is the original announcement document: a raw file in the
// GitHub repository. It is the fallback used while endpoint.Base is unset, and
// it is the only source every build shipped before the endpoint indirection
// knows about - which is exactly why the repository must keep its current name
// until those builds have aged out. See internal/endpoint.
//
// It is a var so tests can point it at a local server.
var LegacySourceURL = "https://raw.githubusercontent.com/codepurse/extension-guard/main/announcement.json"

const (
	userAgent   = "ExtensionGuard-Announce"
	httpTimeout = 15 * time.Second
	maxJSON     = 64 << 10 // 64 KiB cap - an announcement is tiny
)

// Announcement mirrors the announcement.json document. The schema is shared with
// the developer's other apps so one format serves all of them; unknown fields are
// ignored. An empty or Active=false document means "show nothing". Level is one of
// "info" (default), "warn", or "danger" and only drives banner styling. URL is the
// primary link (e.g. a Chrome Web Store page); URLFirefox is an optional
// browser-specific alternative the frontend falls back to.
type Announcement struct {
	ID         string `json:"id"`
	Active     bool   `json:"active"`
	Level      string `json:"level"`
	Title      string `json:"title"`
	Message    string `json:"message"`
	URL        string `json:"url"`
	URLFirefox string `json:"urlFirefox"`
	LinkText   string `json:"linkText"`
}

// Sources returns the announcement URLs to try, most-preferred first: the
// configured endpoint (when set), then the legacy GitHub raw URL. Trying both
// means a build can ship before the endpoint host exists and still show
// announcements, and keeps showing them if the host is later unreachable.
func Sources() []string {
	var out []string
	if u := endpoint.Announcement(); u != "" {
		out = append(out, u)
	}
	if LegacySourceURL != "" {
		out = append(out, LegacySourceURL)
	}
	return out
}

// Fetch retrieves the announcement document, trying each source in order and
// returning the first that answers. On total failure it returns a zero
// (Active=false) Announcement and the last error; callers that only care about
// "is there anything to show" can ignore the error and check Active.
func Fetch(ctx context.Context) (Announcement, error) {
	sources := Sources()
	if len(sources) == 0 {
		return Announcement{}, fmt.Errorf("no announcement source configured")
	}
	var lastErr error
	for _, src := range sources {
		a, err := fetchFrom(ctx, src)
		if err == nil {
			return a, nil
		}
		lastErr = err
	}
	return Announcement{}, lastErr
}

// fetchFrom retrieves and decodes the announcement document at one URL.
func fetchFrom(ctx context.Context, url string) (Announcement, error) {
	var a Announcement
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return a, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := (&http.Client{Timeout: httpTimeout}).Do(req)
	if err != nil {
		return a, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return a, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxJSON))
	if err != nil {
		return a, err
	}
	// Strip a leading UTF-8 BOM before decoding: editors and PowerShell's Out-File
	// prepend one, and encoding/json rejects a BOM-prefixed document. (Mirrors the
	// updater's manifest handling.)
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
	if err := json.Unmarshal(data, &a); err != nil {
		return a, err
	}
	return a, nil
}

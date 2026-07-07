// Package announce fetches a small remote "announcement" document from a static
// URL (a raw file in the GitHub repo) so the status window can show occasional
// messages - a promo, a heads-up, a migration notice - without shipping a new
// build. It is best-effort and read-only: any error yields an inactive
// announcement so the UI simply shows nothing.
package announce

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// SourceURL is the raw announcement document the status window reads. It is a var
// so tests can point it at a local server. To change what users see, edit the
// file at this URL and push - no new release required (raw.githubusercontent.com
// caches for a few minutes).
var SourceURL = "https://raw.githubusercontent.com/codepurse/extension-guard/main/announcement.json"

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

// Fetch retrieves the announcement document. On any failure it returns a zero
// (Active=false) Announcement and the error; callers that only care about "is
// there anything to show" can ignore the error and check Active.
func Fetch(ctx context.Context) (Announcement, error) {
	var a Announcement
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, SourceURL, nil)
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
		return a, fmt.Errorf("GET %s: %s", SourceURL, resp.Status)
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

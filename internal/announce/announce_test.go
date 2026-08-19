package announce

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/codepurse/extension-guard/internal/endpoint"
)

func serve(t *testing.T, a Announcement) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prepend a UTF-8 BOM as PowerShell's Out-File does, to prove it is stripped.
		_, _ = w.Write([]byte{0xEF, 0xBB, 0xBF})
		_ = json.NewEncoder(w).Encode(a)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func useSources(t *testing.T, endpointBase, legacy string) {
	t.Helper()
	oldBase, oldLegacy := endpoint.Base, LegacySourceURL
	endpoint.Base, LegacySourceURL = endpointBase, legacy
	t.Cleanup(func() { endpoint.Base, LegacySourceURL = oldBase, oldLegacy })
}

// TestFetchPrefersEndpoint checks the configured endpoint wins over the legacy
// GitHub raw URL when both would answer.
func TestFetchPrefersEndpoint(t *testing.T) {
	preferred := serve(t, Announcement{ID: "endpoint", Active: true, Title: "from endpoint"})
	legacy := serve(t, Announcement{ID: "legacy", Active: true, Title: "from legacy"})
	useSources(t, preferred.URL, legacy.URL+"/announcement.json")

	got, err := Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got.ID != "endpoint" {
		t.Errorf("ID = %q, want the endpoint's announcement", got.ID)
	}
}

// TestFetchFallsBackToLegacy is what keeps announcements working between shipping
// this build and standing the endpoint host up.
func TestFetchFallsBackToLegacy(t *testing.T) {
	legacy := serve(t, Announcement{ID: "legacy", Active: true, Title: "from legacy"})
	useSources(t, "http://127.0.0.1:1", legacy.URL+"/announcement.json")

	got, err := Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch fell back with an error: %v", err)
	}
	if got.ID != "legacy" {
		t.Errorf("ID = %q, want the legacy announcement", got.ID)
	}
	if !got.Active {
		t.Error("announcement should be active")
	}
}

// TestFetchUnconfiguredEndpointUsesLegacy covers today's shipping state: Base is
// empty, so the only source is the legacy URL.
func TestFetchUnconfiguredEndpointUsesLegacy(t *testing.T) {
	legacy := serve(t, Announcement{ID: "legacy", Active: true})
	useSources(t, "", legacy.URL+"/announcement.json")

	if srcs := Sources(); len(srcs) != 1 {
		t.Fatalf("Sources() = %v, want just the legacy URL", srcs)
	}
	got, err := Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got.ID != "legacy" {
		t.Errorf("ID = %q, want legacy", got.ID)
	}
}

// TestFetchAllSourcesDownStaysSilent: the banner must fail closed, never surface
// an error to the user.
func TestFetchAllSourcesDownStaysSilent(t *testing.T) {
	useSources(t, "http://127.0.0.1:1", "http://127.0.0.1:1/announcement.json")

	got, err := Fetch(context.Background())
	if err == nil {
		t.Error("expected an error when every source is unreachable")
	}
	if got.Active {
		t.Error("a failed fetch must yield an inactive announcement")
	}
}

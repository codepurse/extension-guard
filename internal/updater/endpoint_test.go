package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/codepurse/extension-guard/internal/endpoint"
)

// useEndpoint points internal/endpoint at a test server for one test.
func useEndpoint(t *testing.T, base string) {
	t.Helper()
	old := endpoint.Base
	endpoint.Base = base
	t.Cleanup(func() { endpoint.Base = old })
}

// useGitHub points the legacy GitHub fallback at a test server for one test.
func useGitHub(t *testing.T, base, repo string) {
	t.Helper()
	oldBase, oldRepo := apiBase, Repo
	apiBase, Repo = base, repo
	t.Cleanup(func() { apiBase, Repo = oldBase, oldRepo })
}

// TestCheckLatestPrefersEndpoint verifies the endpoint manifest is used when one
// is configured, and that a bare file name in it resolves against the manifest's
// own URL - so the manifest stays copyable between hosts without edits.
func TestCheckLatestPrefersEndpoint(t *testing.T) {
	guardBytes := []byte("endpoint guard binary")
	sum := sha256.Sum256(guardBytes)
	guardSHA := hex.EncodeToString(sum[:])

	mux := http.NewServeMux()
	mux.HandleFunc("/latest.json", func(w http.ResponseWriter, r *http.Request) {
		m := Manifest{
			Version: "2.0.0",
			Notes:   "from the endpoint",
			Files: []FileHash{
				{Name: "guard.exe", SHA256: guardSHA}, // relative: sibling of the manifest
			},
		}
		_ = json.NewEncoder(w).Encode(m)
	})
	mux.HandleFunc("/guard.exe", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(guardBytes)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	useEndpoint(t, srv.URL)
	// Point the fallback at a dead address: if the endpoint path is not taken,
	// this test fails rather than silently passing through GitHub.
	useGitHub(t, "http://127.0.0.1:1", "acme/guard")

	rel, err := CheckLatest(context.Background())
	if err != nil {
		t.Fatalf("CheckLatest: %v", err)
	}
	if rel.Version != "2.0.0" {
		t.Errorf("version = %q, want 2.0.0", rel.Version)
	}
	if rel.Notes != "from the endpoint" {
		t.Errorf("notes = %q, want the endpoint's", rel.Notes)
	}
	asset, ok := rel.Asset("guard.exe")
	if !ok {
		t.Fatal("release has no guard.exe asset")
	}
	if want := srv.URL + "/guard.exe"; asset.URL != want {
		t.Errorf("asset URL = %q, want %q", asset.URL, want)
	}

	// The resolved URL must actually be fetchable and pass its integrity check.
	if _, err := rel.Stage(context.Background(), t.TempDir(), "guard.exe"); err != nil {
		t.Fatalf("Stage from endpoint: %v", err)
	}
}

// TestCheckLatestHonoursAbsoluteAssetURL covers a manifest that serves binaries
// from a different host than the manifest itself.
func TestCheckLatestHonoursAbsoluteAssetURL(t *testing.T) {
	assets := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer assets.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/latest.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(Manifest{
			Version: "2.1.0",
			Files:   []FileHash{{Name: "guard.exe", SHA256: "abc", URL: assets.URL + "/bin/guard.exe"}},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	useEndpoint(t, srv.URL)
	useGitHub(t, "http://127.0.0.1:1", "acme/guard")

	rel, err := CheckLatest(context.Background())
	if err != nil {
		t.Fatalf("CheckLatest: %v", err)
	}
	asset, ok := rel.Asset("guard.exe")
	if !ok {
		t.Fatal("release has no guard.exe asset")
	}
	if want := assets.URL + "/bin/guard.exe"; asset.URL != want {
		t.Errorf("asset URL = %q, want %q", asset.URL, want)
	}
}

// TestCheckLatestFallsBackToGitHub is the property that lets this build ship
// before the endpoint host exists: an unreachable (or not-yet-serving) endpoint
// must not leave the install with no update path.
func TestCheckLatestFallsBackToGitHub(t *testing.T) {
	mux := http.NewServeMux()
	var base string
	mux.HandleFunc("/repos/acme/guard/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tag_name": "v1.5.0",
			"assets": []map[string]string{
				{"name": "manifest.json", "browser_download_url": base + "/dl/manifest.json"},
				{"name": "guard.exe", "browser_download_url": base + "/dl/guard.exe"},
			},
		})
	})
	mux.HandleFunc("/dl/manifest.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(Manifest{
			Version: "1.5.0",
			Files:   []FileHash{{Name: "guard.exe", SHA256: "abc"}},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	base = srv.URL

	// Endpoint configured but dead - exactly the state between shipping this
	// build and standing the host up.
	useEndpoint(t, "http://127.0.0.1:1")
	useGitHub(t, srv.URL, "acme/guard")

	rel, err := CheckLatest(context.Background())
	if err != nil {
		t.Fatalf("CheckLatest fell back with an error: %v", err)
	}
	if rel.Version != "1.5.0" {
		t.Errorf("version = %q, want 1.5.0 from the GitHub fallback", rel.Version)
	}
}

// TestCheckLatestRejectsVersionlessManifest keeps a malformed or placeholder
// document from being read as a release.
func TestCheckLatestRejectsVersionlessManifest(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/latest.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(Manifest{Files: []FileHash{{Name: "guard.exe"}}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	if _, err := checkDirect(context.Background(), srv.URL+"/latest.json"); err == nil {
		t.Fatal("expected an error for a manifest with no version")
	}
}

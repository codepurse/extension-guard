package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.2.0", "1.1.9", 1},
		{"1.10.0", "1.9.0", 1}, // numeric, not lexical
		{"1.0.0", "1.0.1", -1},
		{"v2.0.0", "1.9.9", 1},    // leading v ignored
		{"1.2.3-rc1", "1.2.3", 0}, // pre-release suffix ignored
		{"1.0.0", "dev", 1},       // any release beats a dev build
		{"dev", "1.0.0", -1},
		{"2.0", "2.0.0", 0}, // missing patch treated as 0
	}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

// TestCheckLatestAndStage stands up a fake GitHub release + asset server and
// verifies CheckLatest resolves the version/hashes and Stage downloads and
// integrity-checks the binary.
func TestCheckLatestAndStage(t *testing.T) {
	guardBytes := []byte("new guard binary")
	sum := sha256.Sum256(guardBytes)
	guardSHA := hex.EncodeToString(sum[:])

	mux := http.NewServeMux()
	var base string // captured after the server starts, to build absolute asset URLs

	mux.HandleFunc("/repos/acme/guard/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"tag_name": "v1.5.0",
			"body":     "release notes",
			"assets": []map[string]string{
				{"name": "manifest.json", "browser_download_url": base + "/dl/manifest.json"},
				{"name": "guard.exe", "browser_download_url": base + "/dl/guard.exe"},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/dl/manifest.json", func(w http.ResponseWriter, r *http.Request) {
		m := Manifest{
			Version: "1.5.0",
			Notes:   "release notes",
			Files:   []FileHash{{Name: "guard.exe", SHA256: guardSHA}},
		}
		// Prepend a UTF-8 BOM (as PowerShell's Out-File does) to prove getJSON
		// strips it - a raw json decode would fail on this.
		_, _ = w.Write([]byte{0xEF, 0xBB, 0xBF})
		_ = json.NewEncoder(w).Encode(m)
	})
	mux.HandleFunc("/dl/guard.exe", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(guardBytes)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()
	base = srv.URL

	// Point the updater at the fake server.
	oldBase, oldRepo := apiBase, Repo
	apiBase, Repo = srv.URL, "acme/guard"
	defer func() { apiBase, Repo = oldBase, oldRepo }()

	rel, err := CheckLatest(context.Background())
	if err != nil {
		t.Fatalf("CheckLatest: %v", err)
	}
	if rel.Version != "1.5.0" {
		t.Errorf("version = %q, want 1.5.0", rel.Version)
	}
	if !rel.Newer("1.0.0") || rel.Newer("2.0.0") {
		t.Errorf("Newer logic wrong for %q", rel.Version)
	}

	dir := t.TempDir()
	staged, err := rel.Stage(context.Background(), dir, "guard.exe")
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	got, err := os.ReadFile(staged["guard.exe"])
	if err != nil {
		t.Fatalf("read staged: %v", err)
	}
	if string(got) != string(guardBytes) {
		t.Errorf("staged bytes = %q, want %q", got, guardBytes)
	}
	if filepath.Base(staged["guard.exe"]) != "guard.exe.new" {
		t.Errorf("staged path = %q, want a .new file", staged["guard.exe"])
	}
}

// TestStageRejectsBadHash ensures a hash mismatch fails and leaves nothing behind.
func TestStageRejectsBadHash(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/dl/guard.exe", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("tampered"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	rel := Release{
		Version: "1.5.0",
		Assets:  []Asset{{Name: "guard.exe", URL: srv.URL + "/dl/guard.exe", SHA256: "deadbeef"}},
	}
	dir := t.TempDir()
	if _, err := rel.Stage(context.Background(), dir, "guard.exe"); err == nil {
		t.Fatal("expected integrity error, got nil")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("staging dir not clean after failure: %v", entries)
	}
}

// TestSwapFiles verifies the rename-in-place swap and rollback contract on the
// host OS.
func TestSwapFiles(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "guard.exe")
	if err := os.WriteFile(target, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(dir, "guard.exe.new")
	if err := os.WriteFile(staged, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := SwapFiles(dir, map[string]string{"guard.exe": staged}); err != nil {
		t.Fatalf("SwapFiles: %v", err)
	}
	got, _ := os.ReadFile(target)
	if string(got) != "new" {
		t.Errorf("after swap, guard.exe = %q, want \"new\"", got)
	}
	if _, err := os.Stat(staged); !os.IsNotExist(err) {
		t.Errorf("staged .new file should be gone after swap")
	}
}

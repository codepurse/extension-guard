package policy

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// fakeStore swaps the trusted store for an in-memory one and restores the real
// (registry / state-file) implementation when the test ends.
type fakeStore struct {
	data    []byte
	present bool
	setErr  error
	writes  int
}

func useFakeStore(t *testing.T, s *fakeStore) {
	t.Helper()
	oldGet, oldSet := getTrusted, setTrusted
	getTrusted = func() ([]byte, bool) {
		if !s.present {
			return nil, false
		}
		return s.data, true
	}
	setTrusted = func(b []byte) error {
		if s.setErr != nil {
			return s.setErr
		}
		s.data, s.present = append([]byte(nil), b...), true
		s.writes++
		return nil
	}
	t.Cleanup(func() { getTrusted, setTrusted = oldGet, oldSet })
}

func writeFile(t *testing.T, path string, cfg Config) {
	t.Helper()
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func cfgWith(disabled bool) Config {
	return Config{Extensions: []Extension{{
		Name:     "sieve",
		Disabled: disabled,
		Chrome:   Target{ExtensionID: "abc", UpdateURL: "https://example.test/crx"},
	}}}
}

// TestCanonicalMatchesCommit is the invariant the whole comparison rests on: the
// bytes Commit writes to disk are exactly the bytes it records as trusted, so an
// untouched file compares equal without any normalization.
func TestCanonicalMatchesCommit(t *testing.T) {
	store := &fakeStore{}
	useFakeStore(t, store)

	path := filepath.Join(t.TempDir(), "extension-ids.json")
	cfg := cfgWith(false)
	if err := Commit(cfg, path); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(onDisk) != string(store.data) {
		t.Errorf("file and trusted copy differ:\nfile:    %q\ntrusted: %q", onDisk, store.data)
	}

	_, trust, err := LoadTrusted(path)
	if err != nil {
		t.Fatalf("LoadTrusted: %v", err)
	}
	if trust != TrustOK {
		t.Errorf("trust = %v, want ok", trust)
	}
}

// TestLoadTrustedAdoptsWhenEmpty covers a fresh install and the first run after
// upgrading from a build that had no trusted store: whatever is on disk becomes
// the baseline.
func TestLoadTrustedAdoptsWhenEmpty(t *testing.T) {
	store := &fakeStore{}
	useFakeStore(t, store)

	path := filepath.Join(t.TempDir(), "extension-ids.json")
	writeFile(t, path, cfgWith(false))

	cfg, trust, err := LoadTrusted(path)
	if err != nil {
		t.Fatalf("LoadTrusted: %v", err)
	}
	if trust != TrustAdopted {
		t.Errorf("trust = %v, want adopted", trust)
	}
	if !cfg.AnyEnabled() {
		t.Error("adopted config should still enforce the extension")
	}
	if !store.present {
		t.Error("adoption should have recorded a trusted copy")
	}
}

// TestLoadTrustedRepairsTamper is the bypass this layer exists to close: the file
// is edited by hand to switch enforcement off, and the guard must ignore the edit
// and put the file back.
func TestLoadTrustedRepairsTamper(t *testing.T) {
	store := &fakeStore{}
	useFakeStore(t, store)

	path := filepath.Join(t.TempDir(), "extension-ids.json")
	if err := Commit(cfgWith(false), path); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// Hand-edit: "disabled": true, exactly what an admin could do in Notepad.
	writeFile(t, path, cfgWith(true))

	cfg, trust, err := LoadTrusted(path)
	if err != nil {
		t.Fatalf("LoadTrusted: %v", err)
	}
	if trust != TrustRepaired {
		t.Fatalf("trust = %v, want repaired", trust)
	}
	if !cfg.AnyEnabled() {
		t.Error("tampered config was honoured: the extension is no longer enforced")
	}
	if len(cfg.Targets(Chrome)) != 1 {
		t.Errorf("Targets(chrome) = %d, want 1", len(cfg.Targets(Chrome)))
	}

	// The file itself is put back, so the next reader sees the truth too.
	restored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != string(store.data) {
		t.Errorf("file was not restored:\ngot:  %q\nwant: %q", restored, store.data)
	}
}

// TestLoadTrustedRepairsDeletedFile covers deleting the config outright rather
// than editing it - otherwise "rm extension-ids.json" would be a bypass.
func TestLoadTrustedRepairsDeletedFile(t *testing.T) {
	store := &fakeStore{}
	useFakeStore(t, store)

	path := filepath.Join(t.TempDir(), "extension-ids.json")
	if err := Commit(cfgWith(false), path); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	cfg, trust, err := LoadTrusted(path)
	if err != nil {
		t.Fatalf("LoadTrusted: %v", err)
	}
	if trust != TrustRepaired {
		t.Errorf("trust = %v, want repaired", trust)
	}
	if !cfg.AnyEnabled() {
		t.Error("deleting the config disabled enforcement")
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("config file was not recreated: %v", err)
	}
}

// TestCommitRefusesWhenTrustedStoreFails guards the ordering rule: if a trusted
// copy exists and we cannot update it, writing the file anyway would produce an
// authorized change that the next cycle reverts as tamper. Better to fail loudly.
func TestCommitRefusesWhenTrustedStoreFails(t *testing.T) {
	store := &fakeStore{data: []byte("{}"), present: true, setErr: errors.New("access denied")}
	useFakeStore(t, store)

	path := filepath.Join(t.TempDir(), "extension-ids.json")
	if err := Commit(cfgWith(false), path); err == nil {
		t.Fatal("Commit succeeded despite a failing trusted store")
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("Commit wrote the config file even though it could not record it")
	}
}

// TestCommitProceedsWithoutTrustedStore keeps unsupported platforms (and callers
// with no rights to the store) working exactly as they did before this layer.
func TestCommitProceedsWithoutTrustedStore(t *testing.T) {
	store := &fakeStore{setErr: errors.New("not supported on this platform")}
	useFakeStore(t, store)

	path := filepath.Join(t.TempDir(), "extension-ids.json")
	if err := Commit(cfgWith(false), path); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("config file was not written: %v", err)
	}
}

// TestLoadTrustedIgnoresFormatting checks that reformatting alone is not treated
// as tamper - only a change in meaning is.
func TestLoadTrustedIgnoresFormatting(t *testing.T) {
	store := &fakeStore{}
	useFakeStore(t, store)

	path := filepath.Join(t.TempDir(), "extension-ids.json")
	if err := Commit(cfgWith(false), path); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	compact, err := json.Marshal(cfgWith(false))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, compact, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, trust, err := LoadTrusted(path); err != nil {
		t.Fatalf("LoadTrusted: %v", err)
	} else if trust != TrustOK {
		t.Errorf("trust = %v, want ok (reformatting is not tamper)", trust)
	}
}

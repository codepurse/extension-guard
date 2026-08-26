package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/codepurse/extension-guard/internal/scm"
)

// This file closes a bypass in the original design. The service reloads
// extension-ids.json from disk on every cycle, and a disabled extension is
// skipped by Targets - so anyone who could edit that file could switch
// enforcement off by adding "disabled": true, with no password and no elevation
// beyond what writing to the install directory already needs. The CLI's password
// gate on disable-extension was guarding the front door while the file sat
// unlocked next to it.
//
// The fix is to stop treating the file as authoritative. Every authorized
// mutation goes through Commit, which records the config in SYSTEM-owned state
// (registry on Windows, the root-owned state file on Linux) before writing the
// file. LoadTrusted then reconciles the two on every cycle and lets the recorded
// copy win, rewriting the file to match.
//
// What this does and does not buy: on a machine where the user is a local
// administrator, no user-space store is beyond reach - an admin can edit the
// registry as readily as the file. What changes is that tampering must now
// survive continuous correction by a SYSTEM service instead of persisting the
// moment it is saved, and it has to happen somewhere far less discoverable than
// a JSON file sitting beside the binary. That is the same bar comparable
// blockers hold, and it is the bar the timer work depends on: a "locked until
// Friday" promise is worth nothing if the deadline lives in a file the blocked
// person can open in Notepad.

// The trusted store is reached through these vars rather than called directly so
// tests can substitute an in-memory one; the real store is the registry (Windows)
// or the root-owned state file (Linux), neither of which a test should touch.
var (
	getTrusted = scm.GetTrustedConfig
	setTrusted = scm.SetTrustedConfig
)

// Trust describes how the on-disk config compared against the trusted copy.
type Trust int

const (
	// TrustAdopted means no trusted copy existed, so the on-disk config was taken
	// as the starting point and recorded. This is the expected result on a fresh
	// install and on the first run after upgrading from a build that predates the
	// trusted store.
	TrustAdopted Trust = iota
	// TrustOK means the on-disk config matched the trusted copy.
	TrustOK
	// TrustRepaired means the on-disk config had been changed behind the guard's
	// back; the trusted copy was enforced and the file rewritten to match.
	TrustRepaired
)

func (t Trust) String() string {
	switch t {
	case TrustOK:
		return "ok"
	case TrustRepaired:
		return "repaired"
	default:
		return "adopted"
	}
}

// Canonical returns the config's canonical JSON encoding: the exact bytes
// Commit writes to disk, so a file written by Commit compares equal to its
// trusted copy byte for byte. Comparing canonical encodings rather than raw file
// bytes means reformatting or reordering whitespace is not mistaken for tamper -
// only a change in meaning counts.
func (c Config) Canonical() ([]byte, error) {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// LoadTrusted loads the config at path and reconciles it against the trusted
// copy, returning the config the guard should actually enforce.
//
// It self-heals: when the file disagrees with the trusted copy, the trusted copy
// is returned and the file is rewritten to match, mirroring how the guard
// already re-asserts the browser policy after registry tamper. A failure to
// rewrite is not fatal - enforcing the right config matters more than fixing the
// file, and the next cycle tries again.
func LoadTrusted(path string) (Config, Trust, error) {
	diskCfg, diskErr := LoadConfig(path)

	trusted, haveTrusted := getTrusted()
	if !haveTrusted {
		// Nothing recorded yet: adopt what is on disk and remember it.
		if diskErr != nil {
			return Config{}, TrustAdopted, diskErr
		}
		canon, err := diskCfg.Canonical()
		if err != nil {
			return diskCfg, TrustAdopted, err
		}
		// Best-effort: an unprivileged caller (the status window) cannot write the
		// state store, and should still get a usable config back.
		_ = setTrusted(canon)
		return diskCfg, TrustAdopted, nil
	}

	var trustedCfg Config
	if err := json.Unmarshal(trusted, &trustedCfg); err != nil {
		// The recorded copy is unreadable, which is worse than useless. Fall back to
		// disk and re-record it rather than enforce nothing.
		if diskErr != nil {
			return Config{}, TrustAdopted, fmt.Errorf("trusted config unreadable (%v) and %w", err, diskErr)
		}
		if canon, cErr := diskCfg.Canonical(); cErr == nil {
			_ = setTrusted(canon)
		}
		return diskCfg, TrustAdopted, nil
	}

	if diskErr != nil {
		// Unreadable or missing file, but we know what it should contain.
		_ = os.WriteFile(path, trusted, 0o644)
		return trustedCfg, TrustRepaired, nil
	}

	canon, err := diskCfg.Canonical()
	if err != nil {
		return trustedCfg, TrustRepaired, err
	}
	if bytes.Equal(canon, trusted) {
		return diskCfg, TrustOK, nil
	}

	_ = os.WriteFile(path, trusted, 0o644)
	return trustedCfg, TrustRepaired, nil
}

// TrustedConfig returns the recorded config and whether one exists. Callers that
// need to compare a proposed change against what is currently enforced use this
// rather than reading the file, which is only a mirror.
func TrustedConfig() (Config, bool) {
	data, ok := getTrusted()
	if !ok {
		return Config{}, false
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, false
	}
	return cfg, true
}

// Commit records cfg as the trusted copy and writes it to path. Every authorized
// mutation - the installer's component pick, the extension toggles, an install -
// goes through here, and nothing else should write the config file.
//
// The trusted copy is recorded first on purpose. If recording succeeds and the
// file write then fails, the next LoadTrusted repairs the file from the trusted
// copy and the change survives. In the other order, a failure to record would
// leave an authorized change on disk that the next cycle would revert as tamper.
func Commit(cfg Config, path string) error {
	canon, err := cfg.Canonical()
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	if err := setTrusted(canon); err != nil {
		// Platforms with no state store (and unprivileged callers) simply have no
		// trusted copy; that is the pre-existing behaviour and the file is still
		// the config. But if a copy *is* recorded and we could not update it, the
		// write would be reverted on the next cycle - refuse rather than mislead.
		if _, haveTrusted := getTrusted(); haveTrusted {
			return fmt.Errorf("record trusted config: %w", err)
		}
	}
	if err := os.WriteFile(path, canon, 0o644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

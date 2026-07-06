package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/codepurse/extension-guard/internal/auth"
	"github.com/codepurse/extension-guard/internal/buildinfo"
	"github.com/codepurse/extension-guard/internal/guardsvc"
	"github.com/codepurse/extension-guard/internal/policy"
	"github.com/codepurse/extension-guard/internal/scm"
	"github.com/codepurse/extension-guard/internal/updater"
)

// App is the Wails-bound backend. Its exported methods are callable from the
// frontend as window.go.main.App.<Method>().
type App struct {
	ctx     context.Context
	cfg     policy.Config
	cfgPath string
}

// Status is the snapshot the frontend renders.
type Status struct {
	ServiceRunning bool           `json:"serviceRunning"`
	Disabled       bool           `json:"disabled"`
	LockedCount    int            `json:"lockedCount"`
	HasPassword    bool           `json:"hasPassword"`
	Browsers       []BrowserRow   `json:"browsers"`
	Extensions     []ExtensionRow `json:"extensions"`
}

// ExtensionRow is one manageable extension in the status window. Name is the
// stable id the toggle actions pass to the guard; Label is what the user sees.
type ExtensionRow struct {
	Name    string `json:"name"`
	Label   string `json:"label"`
	Enabled bool   `json:"enabled"`
}

// ActionResult is what the disable/enable methods report back to the frontend.
type ActionResult struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

// BrowserRow is one row in the status list.
type BrowserRow struct {
	Kind      string `json:"kind"`
	Installed bool   `json:"installed"`
	Locked    bool   `json:"locked"`
	Detail    string `json:"detail"`
}

// NewApp loads the shared config so status reflects the configured extension.
// The resolved path is kept so disable/enable can hand it to the elevated guard.
func NewApp() *App {
	p := defaultConfigPath()
	cfg, _ := policy.LoadConfig(p)
	return &App{cfg: cfg, cfgPath: p}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

// GetStatus returns the current protection status. Read-only and admin-free.
// It reloads the config each call so a just-toggled extension is reflected.
func (a *App) GetStatus() Status {
	if cfg, err := policy.LoadConfig(a.cfgPath); err == nil {
		a.cfg = cfg
	}
	verified := policy.Verify(a.cfg)
	rows := make([]BrowserRow, 0, len(verified))
	locked := 0
	for _, s := range verified {
		if s.Locked {
			locked++
		}
		rows = append(rows, BrowserRow{
			Kind:      string(s.Kind),
			Installed: s.Installed,
			Locked:    s.Locked,
			Detail:    s.Detail,
		})
	}
	exts := make([]ExtensionRow, 0, len(a.cfg.Extensions))
	for _, e := range a.cfg.Extensions {
		label := e.Label
		if label == "" {
			label = e.Name
		}
		exts = append(exts, ExtensionRow{Name: e.Name, Label: label, Enabled: !e.Disabled})
	}
	_, hasPw := scm.GetPasswordHash()
	return Status{
		ServiceRunning: scm.IsRunning(guardsvc.ServiceName),
		Disabled:       scm.IsDisabled(),
		LockedCount:    locked,
		HasPassword:    hasPw,
		Browsers:       rows,
		Extensions:     exts,
	}
}

// Disable temporarily turns protection off - the one action that *weakens*
// protection, so it requires the uninstall password (verified locally for
// instant feedback, then re-verified by the elevated guard so the gate can't be
// bypassed from the renderer). Enable turns it back on; because that only
// strengthens protection it needs admin (a UAC prompt) but no password.
func (a *App) Disable(password string) ActionResult {
	hash, ok := scm.GetPasswordHash()
	if !ok {
		return ActionResult{Message: "No uninstall password is set. Install protection with the installer (or `guard install-service`) first."}
	}
	if !auth.Verify(hash, password) {
		return ActionResult{Message: "Incorrect password."}
	}
	return a.execGuard([]string{"-config", a.cfgPath, "-password", password, "disable"}, "Protection disabled.")
}

// Enable restores protection. Free (no password) - it only strengthens - but
// still elevated (UAC).
func (a *App) Enable() ActionResult {
	return a.execGuard([]string{"-config", a.cfgPath, "enable"}, "Protection enabled.")
}

// EnableExtension starts locking an extension. Free (no password) since it only
// strengthens protection; still needs admin (UAC).
func (a *App) EnableExtension(name string) ActionResult {
	if name == "" {
		return ActionResult{Message: "No extension selected."}
	}
	return a.execGuard([]string{"-config", a.cfgPath, "enable-extension", name}, name+" is now protected.")
}

// DisableExtension stops locking an extension. That weakens protection, so it
// requires the password - EXCEPT while protection is in the authorized paused
// state (scm.IsDisabled), where there is no active lock to bypass. The check
// keys off the authorized-pause sentinel, not a transient "service not running",
// so a momentary stop can't be exploited to strip extensions without the password.
func (a *App) DisableExtension(name, password string) ActionResult {
	if name == "" {
		return ActionResult{Message: "No extension selected."}
	}
	args := []string{"-config", a.cfgPath}
	if !scm.IsDisabled() {
		hash, ok := scm.GetPasswordHash()
		if !ok {
			return ActionResult{Message: "No password is set. Install protection first."}
		}
		if !auth.Verify(hash, password) {
			return ActionResult{Message: "Incorrect password."}
		}
		args = append(args, "-password", password)
	}
	args = append(args, "disable-extension", name)
	return a.execGuard(args, name+" is no longer locked.")
}

// execGuard runs guard.exe elevated (a UAC prompt), waits, and maps the outcome
// to an ActionResult, returning okMsg on success.
func (a *App) execGuard(args []string, okMsg string) ActionResult {
	guardExe, err := a.guardPath()
	if err != nil {
		return ActionResult{Message: err.Error()}
	}
	code, err := runElevatedAndWait(guardExe, args)
	if err != nil {
		if errors.Is(err, errElevationCancelled) {
			return ActionResult{Message: "Cancelled at the Windows permission prompt."}
		}
		return ActionResult{Message: "Could not run the guard: " + err.Error()}
	}
	if code != 0 {
		return ActionResult{Message: fmt.Sprintf("The guard reported an error (exit code %d).", code)}
	}
	return ActionResult{OK: true, Message: okMsg}
}

// GetVersion returns the running build version, shown in the footer.
func (a *App) GetVersion() string { return buildinfo.Version }

// UpdateStatus is what CheckForUpdate reports to the frontend.
type UpdateStatus struct {
	Available bool   `json:"available"`
	Current   string `json:"current"`
	Latest    string `json:"latest"`
	Notes     string `json:"notes"`
	Error     string `json:"error"`
}

// CheckForUpdate asks GitHub whether a newer release exists. Read-only and
// admin-free; the frontend calls it on open and behind a "Check for updates"
// button.
func (a *App) CheckForUpdate() UpdateStatus {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	rel, err := updater.CheckLatest(ctx)
	if err != nil {
		return UpdateStatus{Current: buildinfo.Version, Error: "Couldn't check for updates."}
	}
	return UpdateStatus{
		Available: rel.Newer(buildinfo.Version),
		Current:   buildinfo.Version,
		Latest:    rel.Version,
		Notes:     rel.Notes,
	}
}

// ApplyUpdate runs `guard update` elevated (a UAC prompt). Updating only
// strengthens protection, so - like enabling an extension - it needs admin but
// NOT the uninstall password. The elevated guard re-checks GitHub, swaps the
// binaries, and restarts the service.
func (a *App) ApplyUpdate() ActionResult {
	guardExe, err := a.guardPath()
	if err != nil {
		return ActionResult{Message: err.Error()}
	}
	code, err := runElevatedAndWait(guardExe, []string{"-config", a.cfgPath, "update"})
	if err != nil {
		if errors.Is(err, errElevationCancelled) {
			return ActionResult{Message: "Cancelled at the Windows permission prompt."}
		}
		return ActionResult{Message: "Could not run the updater: " + err.Error()}
	}
	if code != 0 {
		return ActionResult{Message: fmt.Sprintf("The updater reported an error (exit code %d).", code)}
	}
	return ActionResult{OK: true, Message: "Update installed. Close and reopen Extension Guard to use the new version."}
}

// guardPath locates guard.exe next to this status binary, where the installer
// places both.
func (a *App) guardPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	name := "guard"
	if runtime.GOOS == "windows" {
		name = "guard.exe"
	}
	p := filepath.Join(filepath.Dir(exe), name)
	if !fileExists(p) {
		return "", fmt.Errorf("%s was not found next to this app", name)
	}
	return p, nil
}

// defaultConfigPath finds extension-ids.json next to the binary (where the
// installer places a copy) or by walking up from the working directory.
func defaultConfigPath() string {
	if exe, err := os.Executable(); err == nil {
		if p := filepath.Join(filepath.Dir(exe), "extension-ids.json"); fileExists(p) {
			return p
		}
	}
	if dir, err := os.Getwd(); err == nil {
		for i := 0; i < 6; i++ {
			if p := filepath.Join(dir, "extension-ids.json"); fileExists(p) {
				return p
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	return "extension-ids.json"
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

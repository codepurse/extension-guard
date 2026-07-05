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

// Disable temporarily turns protection off. Enable turns it back on. Both verify
// the password locally for instant feedback, then hand the actual work to an
// elevated guard.exe (a UAC prompt) - the binary re-verifies the password so the
// gate can't be bypassed from the renderer.
func (a *App) Disable(password string) ActionResult { return a.runGuard("disable", password) }
func (a *App) Enable(password string) ActionResult  { return a.runGuard("enable", password) }

func (a *App) runGuard(action, password string) ActionResult {
	hash, ok := scm.GetPasswordHash()
	if !ok {
		return ActionResult{Message: "No uninstall password is set. Install protection with the installer (or `guard install-service`) first."}
	}
	if !auth.Verify(hash, password) {
		return ActionResult{Message: "Incorrect password."}
	}
	guardExe, err := a.guardPath()
	if err != nil {
		return ActionResult{Message: err.Error()}
	}
	code, err := runElevatedAndWait(guardExe, []string{"-config", a.cfgPath, "-password", password, action})
	if err != nil {
		if errors.Is(err, errElevationCancelled) {
			return ActionResult{Message: "Cancelled at the Windows permission prompt."}
		}
		return ActionResult{Message: "Could not run the guard: " + err.Error()}
	}
	if code != 0 {
		return ActionResult{Message: fmt.Sprintf("The guard reported an error (exit code %d).", code)}
	}
	if action == "disable" {
		return ActionResult{OK: true, Message: "Protection disabled."}
	}
	return ActionResult{OK: true, Message: "Protection enabled."}
}

// EnableExtension starts locking an extension. Turning protection ON is free
// (no password) - it only strengthens protection - but still needs admin, so it
// runs the guard elevated (a UAC prompt). DisableExtension stops locking one and
// requires the password, like turning protection off.
func (a *App) EnableExtension(name string) ActionResult {
	return a.runGuardExt("enable-extension", name, "")
}

func (a *App) DisableExtension(name, password string) ActionResult {
	return a.runGuardExt("disable-extension", name, password)
}

func (a *App) runGuardExt(action, name, password string) ActionResult {
	if name == "" {
		return ActionResult{Message: "No extension selected."}
	}
	args := []string{"-config", a.cfgPath}
	if action == "disable-extension" {
		hash, ok := scm.GetPasswordHash()
		if !ok {
			return ActionResult{Message: "No password is set. Install protection first."}
		}
		if !auth.Verify(hash, password) {
			return ActionResult{Message: "Incorrect password."}
		}
		args = append(args, "-password", password)
	}
	guardExe, err := a.guardPath()
	if err != nil {
		return ActionResult{Message: err.Error()}
	}
	args = append(args, action, name)
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
	if action == "enable-extension" {
		return ActionResult{OK: true, Message: name + " is now protected."}
	}
	return ActionResult{OK: true, Message: name + " is no longer locked."}
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

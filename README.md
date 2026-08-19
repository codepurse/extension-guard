# Extension Guard (PC version)

A small native companion that **locks one or more browser extensions in place**
so they can't be removed from the browser UI. It resists tampering (watchdog),
requires a password to uninstall, and ships a small status window.

It does **no** content blocking itself — that all stays in the extensions it
protects. This app just plants and guards the browser "force-install" enterprise
policy for every extension listed in its config. It's product-neutral: point it
at any set of store-published extensions (e.g. BlockNSFW and Sieve) and it locks
them all with one install.

It runs on **Windows** (registry + Service Control Manager) and **Linux**
(managed policy files + systemd). The OS-specific code is selected automatically
at build time by Go build tags (`*_windows.go` / `*_linux.go`), so it's one app,
not two — see the **Linux** section below.

> Why this works: a browser extension can't prevent its own uninstall, but a
> privileged process *above* the browser can force-install it via policy, which
> greys out the Remove/Disable buttons. See `docs/pc-version.md` for the full
> picture.

## Status — milestone roadmap

| # | Milestone | State |
|---|-----------|-------|
| 1 | Force-install **policy writer** (apply / verify / remove) | ✅ done |
| 2 | Run as a **Windows service** + tamper watcher (re-apply on delete) | ✅ done |
| 3 | **Watchdog** (survive being killed) | ✅ done |
| 4a | **Password-gated** uninstall (set-password, gated install/uninstall) | ✅ done |
| 4b | **Installer** (Inno Setup wizard + consent + password page) | ✅ done (unsigned until cert) |
| 5 | Status **UI** window (Wails, day-to-day screen from the mockup) | ✅ done |
| 6 | **Temporary disable/enable** toggle + polish (fixed window, app icon) | ✅ done |
| 7 | **Linux** port (managed-policy files + systemd) | 🟡 code-complete; engine compile-verified, UI/scripts need a Linux box |
| 8 | **Multi-extension** config (lock several extensions at once) | ✅ done |
| 9 | **In-app updater** (GitHub Releases: auto-check + one-click update) | ✅ done (silent auto-apply gated on signing) |

## Prerequisites — Windows build (via winget)

- **Go 1.23+** — `winget install GoLang.Go`
- **Node.js LTS** — `winget install OpenJS.NodeJS.LTS` (Wails uses it for the status UI)
- **Wails CLI** — `go install github.com/wailsapp/wails/v2/cmd/wails@latest`
- **Inno Setup 6** — `winget install JRSoftware.InnoSetup` (builds the installer)
- WebView2 runtime (already on Windows 11)

## Build everything — Windows (release artifacts)

```powershell
powershell -ExecutionPolicy Bypass -File build.ps1
```

Runs the tests, then builds all three artifacts into `release\`:

| Artifact | What it is |
|----------|-----------|
| `guard.exe` | CLI + Windows service + watchdog |
| `extension-guard-status.exe` | the status window (Wails) |
| `Extension-Guard-Setup.exe` | installer that bundles both + creates shortcuts |

Go core only: `go test ./...` then `go build ./cmd/guard`.

## Install the app (end users — Windows)

Run `release\Extension-Guard-Setup.exe`. It shows a consent page, asks
you to **set an uninstall password** (give it to the parent / accountability
partner, *not* the person being filtered), installs + starts the guard service,
locks the browsers, and creates an **Extension Guard** shortcut.

> Windows will likely warn that this is from an **"unknown publisher,"** and some
> antivirus may flag it. That's expected for now — see
> [Is it safe? Why Windows and antivirus warn you](#is-it-safe-why-windows-and-antivirus-warn-you)
> for why, and how to verify it yourself.

To **update** an installed copy, use the built-in updater (status window →
**Update now**, or `guard update` from an elevated shell) — it swaps the
binaries in place and restarts the service, no uninstall or password needed. See
[Updates](#updates) below. (Reinstalling over a running install via the setup
still fails, because the service holds `guard.exe` open — that's what the
in-place updater works around.)

### Is it safe? Why Windows and antivirus warn you

When you run the installer, Windows SmartScreen will likely show **"Windows
protected your PC — unknown publisher,"** and some antivirus tools may warn or
quarantine it. Here's the honest *why*, and how to check for yourself.

**Why it happens (two reasons, neither is malware):**

1. **It isn't code-signed yet.** Code-signing certificates normally cost money;
   we're getting a **free certificate for open-source projects** via the
   [SignPath Foundation](https://about.signpath.io/product/open-source). Until
   that's in place, releases are unsigned, so Windows can't display a verified
   publisher — hence "unknown publisher." *A cert is on the way; once it's in
   place these warnings go away.*
2. **It's deliberately tamper-resistant.** Extension Guard runs a service with a
   watchdog that restarts itself if it's killed — that's the entire point (it
   stops the filtered user from simply uninstalling it). That "won't stay dead"
   behavior is *also* what some malware does, so a **small number** of heuristic /
   machine-learning antivirus engines (e.g. Bkav, Elastic) may flag it as a
   generic false positive — not a named-threat signature. It only installs after
   you tick the **consent** box, and only the person holding the uninstall
   password can remove it. See [docs/signing.md](docs/signing.md) for the full
   story, the signing plan, and how false positives are reported.

**What it does — and doesn't:** it only writes the browsers' enterprise
"force-install" policy and keeps it applied. It does **no** content filtering
itself (the extensions do that), collects **no** personal data, and makes **no**
network calls except checking GitHub for updates.

**Don't take our word for it — verify:**

- The **full source is public** in this repo — read every line, and build it
  yourself with `build.ps1`.
- Every release ships a **`manifest.json`** listing the SHA-256 of each binary.
  Confirm your download matches:
  ```powershell
  (Get-FileHash .\guard.exe -Algorithm SHA256).Hash
  ```
- Scan the binaries yourself on [VirusTotal](https://www.virustotal.com/).

**To install past the SmartScreen prompt:** click **More info → Run anyway**.

**Code signing:** free code signing for this project is provided by
[SignPath.io](https://signpath.io), with a certificate issued by the
[SignPath Foundation](https://signpath.org). (Application in progress — until it
is active, release binaries are unsigned, which is why the warnings above appear.)

**Privacy:** Extension Guard collects no personal data — see
[PRIVACY.md](PRIVACY.md).

### Status window (day-to-day)

`extension-guard-status.exe` shows whether protection is **Active / Paused / Inactive**,
how many browsers are locked, and the service state. To pause or resume, type the
password and click **Disable protection** / **Enable protection** — each pops a
Windows **UAC** prompt, and the guard re-verifies the password itself, so the
button can't be bypassed from the UI.

The **Protected extensions** list lets you turn each configured extension on or
off after install: turning one **on** is free (it only adds protection), turning
one **off** requires the password. Each toggle runs the guard elevated (UAC) and
rewrites the config; the service picks the change up on its next cycle. This is
how you add a second extension (e.g. Sieve) to a guard you first installed for
just one — no reinstall needed.

The **Blocked sites** section lists the domain block list with a box to add one.
Adding is free; removing needs the password. A site that is on but currently
outside its schedule window is badged **Waiting**, not shown as failing. See
[Blocked sites](#blocked-sites).

If any **scheduled blocks** are configured, a section below lists them with
their timetable and lock state, and offers a **Lock** button. See
[Scheduled blocks](#scheduled-blocks).

## Try it (Windows, Administrator shell required)

`apply`, `remove` write to `HKLM`, so run them from an **elevated** terminal.

```sh
guard domains      # blocked sites: which are on the list, which are enforced now
guard blocks       # scheduled blocks: which are enforcing now, which are locked
guard detect       # which browsers are installed
guard apply        # enforce everything the config asks for
guard verify       # show what is enforced, per area and target
guard remove       # lift it all (authorized uninstall)
```

`verify` reports one row per target with the columns `area`, `target`,
`present`, `enforced`, `detail`. Today the only area is `extensions` and every
target is a browser; the columns are general so blocked applications can appear
alongside them without a second command.

### Enforcement backends

`internal/enforce` is the seam between *what* the guard should enforce and *how*
each kind of thing is enforced. An `Enforcer` applies, verifies, and removes one
kind of rule; `enforce.Default()` is the set the service drives, and the service
knows only that set - not what is in it. Locking browser extensions is currently
the only member, a thin adapter over `internal/policy`, which still owns the
registry and managed-policy-file work.

`Apply` and `Remove` fan out across the whole set and join errors rather than
stopping at the first failure, so one backend failing cannot silently leave the
others unenforced. Adding application blocking means writing an `Enforcer` and
putting it in `Default()`, not threading a second code path through the service.

### Run it as a service (milestone 2)

The service applies the policy on start, then re-applies it within milliseconds
whenever anything under `HKLM\SOFTWARE\Policies` changes (the tamper case), plus
a 30s backstop timer. Install/start/stop need an elevated shell.

```sh
guard -config <abs> -password <pw> install-service  # set password + install + harden + start
guard set-password                                   # set/change the password (prompts, hidden)
guard -password <pw> uninstall-service               # remove the service (password required)
guard start                                          # start it
guard stop                                           # stop it (the watchdog will fight this)
guard run                                            # run in the foreground (Ctrl+C to stop)
```

The uninstall password is stored only as a bcrypt hash in `HKLM\SOFTWARE\ExtensionGuard`.
`uninstall-service` refuses to proceed without it - that's the gate that makes
removal require the parent/accountability-partner, not just admin rights. (A
determined admin who knows the internals can still wipe the registry state; see
the honest ceiling in `docs/pc-version.md`.)

Flags go **before** the command (`guard -config X run`), because Go's flag
parser stops at the first non-flag argument. The installed service is given the
absolute config path automatically, since a service's working directory is
`System32`.

### Watchdog & self-healing (milestone 3)

`install-service` also **hardens** the service so stopping it doesn't stick:

- **SCM recovery** — Windows auto-restarts the process if it's killed/crashes.
- **Watchdog process** — spawned by the service; if the service is stopped,
  disabled, or its entry deleted, the watchdog re-enables Automatic start,
  restarts it, or re-installs it. A `Local\` named mutex keeps a single watchdog
  instance running.
- **Disabled sentinel** — `uninstall-service` sets `HKLM\SOFTWARE\ExtensionGuard`
  `GuardDisabled=1` so the watchdog stops resurrecting during an authorized
  teardown; `install-service` clears it.

This defeats casual/impulsive removal. It does **not** stop a determined admin
(Safe Mode, killing both processes at once) - see `docs/pc-version.md` for
the honest ceiling. The two-process respawn pattern is also what antivirus flags
as malware, so this layer makes code signing mandatory before distribution.

Config comes from `extension-ids.json` (found automatically next to the binary,
or by walking up from the working directory). Override with `guard -config <path> apply`.

## Updates

The app can update itself in place, without an uninstall. It resolves releases
from the endpoint configured in `internal/endpoint` when one is set, and from
**GitHub Releases** otherwise - the indirection is what keeps the repository's
name from being permanently load-bearing for installs already in the field. See
`docs/endpoints.md`. Because the guard is a self-healing service (the watchdog fights any
restart and the service holds `guard.exe` open), the update is *cooperative*: it
sets an `updating` sentinel so the watchdog stands down, stops the service,
renames the old binaries aside and the new ones into place (Windows lets you
rename a running `.exe`), then restarts the service — which spawns a fresh
watchdog from the new binary. The old binaries are cleared on the next reboot.

Because updating only *strengthens* protection, it needs **admin (UAC)** but
**not** the uninstall password — same gate as enabling an extension.

**Two ways it triggers:**

- **Manual** — the status window shows an **Update available** banner with an
  **Update now** button (and a **Check for updates** button in the footer). Or
  run `guard update` from an elevated shell. `guard check-update` just reports.
- **Automatic** — the service polls for a new release every 6h and reacts per
  the `autoUpdate` setting in `extension-ids.json`:

  | `autoUpdate` | Behaviour |
  |--------------|-----------|
  | `notify` (default) | logs that an update is available; the user applies it from the status window |
  | `apply` | downloads + installs it silently in the background |
  | `off` | no periodic check |

> **Keep `autoUpdate` at `notify` until the binaries are code-signed.** Integrity
> today rests on a SHA-256 manifest (it catches corruption, not a compromised
> release); only Authenticode proves authenticity, and silently running unsigned
> downloads from a tamper-resistant service is exactly what antivirus quarantines.
> The manual path stays fully usable in the meantime. See `docs/pc-version.md`.

### Publishing a release

`build.ps1` reads the repo-root `VERSION` file, stamps it into both binaries
(`internal/buildinfo.Version` via `-ldflags`) and the installer, and writes
`release\manifest.json` with the SHA-256 of each binary. To publish: bump
`VERSION`, run `build.ps1`, then create a **GitHub release tagged `v<version>`**
(on the repo in `internal/updater.Repo`) and attach `guard.exe`,
`extension-guard-status.exe`, and `manifest.json`. The updater reads
`manifest.json` to learn the version + expected hashes and downloads the
matching assets.

## Linux

The same app builds for Linux. The engine swaps the Windows registry + Service
Control Manager for **managed policy files + systemd**, selected automatically by
Go build tags. The `guard` engine is compile-verified; the Wails status UI and
the packaging scripts still need to be built and run **on a Linux machine** —
Wails links gtk/webkit, so it can't be cross-compiled from Windows.

**Prerequisites (Debian/Ubuntu):**

```sh
sudo apt install build-essential libgtk-3-dev libwebkit2gtk-4.1-dev
# plus Go 1.25+ and the Wails CLI:
go install github.com/wailsapp/wails/v2/cmd/wails@latest
```

**Build, install, uninstall:**

```sh
bash build-linux.sh                  # -> release-linux/{guard, extension-guard-status, extension-ids.json}
sudo installer/linux/install.sh      # copy to /opt/extension-guard + register the systemd service (sets the password)
sudo installer/linux/uninstall.sh    # password-gated removal
```

The CLI is identical to Windows (`guard apply|verify|remove|install-service|
disable|enable|start|stop|run`), just run with `sudo` instead of an elevated
shell. The status UI elevates via **pkexec** (PolicyKit) instead of UAC.

**Where things live on Linux:**

| Thing | Location |
|-------|----------|
| Binaries | `/opt/extension-guard/` |
| Chromium force-install | `/etc/opt/chrome/policies/managed/extension-guard.json` (also `/etc/opt/edge/...`, `/etc/brave/...`) |
| Firefox force-install | `/etc/firefox/policies/policies.json` |
| Guard state (disabled flag + password hash) | `/etc/extension-guard/state.json` |
| Service | systemd unit `ExtensionGuard.service` |

**Linux caveats:**

- **snap / flatpak browsers** (e.g. Ubuntu's default Firefox) are sandboxed and
  ignore `/etc/.../policies/managed` — the lock only takes effect on natively
  installed (`.deb` / `.rpm`) browsers.
- Tamper-resistance is weaker than on Windows: `root` can stop the service and
  delete the policy files. It's effective against a **standard (non-admin) user**
  — the real target — but not against someone with `sudo`.
- Real-time tamper watching isn't wired up on Linux yet; the 30s backstop
  re-apply covers it. macOS is not started (needs an Apple Developer account +
  notarization).

## Config — extension-ids.json

The guard reads a single `extension-ids.json`. It lists **every extension** to
force-install; each extension carries a per-browser target, because each browser
force-installs only from **its own store**. A browser left as a `REPLACE_*`
placeholder (or omitted) is skipped (`not configured` in `verify`).

```json
{
  "extensions": [
    {
      "name": "blocknsfw",
      "chrome":  { "extensionId": "ekdegpeejlidlkofccgakfdbiegmicmj", "updateUrl": "https://clients2.google.com/service/update2/crx" },
      "edge":    { "extensionId": "imccbmfplknoadpaoopicfdpnnimgdab", "updateUrl": "https://edge.microsoft.com/extensionwebstorebase/v1/crx" },
      "brave":   { "extensionId": "ekdegpeejlidlkofccgakfdbiegmicmj", "updateUrl": "https://clients2.google.com/service/update2/crx" },
      "firefox": { "addonId": "blocknsfw@extension.local", "installUrl": "https://addons.mozilla.org/firefox/downloads/latest/blocknsfw-porn-adult-content/latest.xpi" }
    },
    {
      "name": "sieve",
      "chrome":  { "extensionId": "REPLACE_WITH_SIEVE_CHROME_ID", "updateUrl": "https://clients2.google.com/service/update2/crx" }
    }
  ]
}
```

The config is the full **catalog** of extensions the guard *can* lock; each
extension carries a `disabled` flag. At install time the setup wizard shows a
**Select Components** page, and the installer runs `guard -extensions <chosen> select`
to enable the chosen extensions and disable the rest (all stay in the file). So
one installer can lock BlockNSFW, Sieve, or both. After install, the **status
window** (or `guard enable-extension <name>` / `guard disable-extension <name>`)
flips those flags, so you can add or drop an extension without reinstalling.

**Editing the file by hand does nothing.** The flags are what decide whether an
extension is enforced, so a file anyone could edit would have made the password
gate on `disable-extension` pointless - `"disabled": true` in Notepad and the
lock is off. Every authorized change instead records the config in SYSTEM-owned
state (the registry on Windows, the root-owned state file on Linux), and the
service reconciles the file against that copy on every cycle: a change made any
other way loses and the file is rewritten, the same way registry tamper loses to
the policy the guard re-applies. The status window reports the enforced config,
not the file's claim, so the two never silently disagree.

This is not a claim that the config is beyond a determined local admin - the
state store is Administrator-writable, because the elevated CLI paths that
legitimately update it are not running as SYSTEM. What it means is that tampering
has to survive continuous correction by a service instead of persisting the
moment it is saved. That is the same ceiling described in `docs/pc-version.md`,
and the floor the scheduled-block work depends on.

The two exceptions are the installer and `guard commit`. `guard select` adopts
the freshly shipped `extension-ids.json`, so an upgrade that widens the catalog
or corrects an extension ID takes effect instead of being reverted; `guard
commit` is how *you* adopt an edit you made on purpose (see below).

## Blocked sites

Add a domain and it is blocked in every supported browser, **including all its
subdomains**: `reddit.com` covers `www.reddit.com`, `old.reddit.com`, and
`https://reddit.com/r/anything`.

```sh
guard block-domain reddit.com     # admin; no password - it only adds protection
guard unblock-domain reddit.com   # password (unless protection is paused)
guard domains                     # what is on the list and what is enforced now
```

Or type it into the **Blocked sites** box in the status window.

```json
{
  "domains": [
    { "name": "reddit.com" },
    { "name": "news.ycombinator.com", "disabled": true }
  ]
}
```

### How it works, and what it does not cover

This uses each browser's **enterprise URL filter**, not the hosts file:
`URLBlocklist` on Chrome/Edge/Brave, `WebsiteFilter` on Firefox. Three reasons
that matters:

- A hosts entry is resolved by the **OS**, and both Chrome and Firefox can use
  **DNS-over-HTTPS**, which skips the OS resolver — the block would silently stop
  working. A policy is enforced inside the browser, above DNS.
- It lands in `HKLM\SOFTWARE\Policies`, which the guard's **tamper watcher
  already watches**, so a deleted key is restored within milliseconds for free.
- It writes registry policy and kills no processes, which is why this could ship
  **without waiting on code signing**, unlike blocking applications.

What it does **not** cover, plainly: a browser the guard doesn't support, and any
non-browser app. Those need enforcement below the browser — still to come.

### Input handling

Paste whatever you have; it is reduced to the bare hostname.
`https://www.Reddit.com/r/x?sort=new` and `reddit.com:443` and `REDDIT.com.` all
become `reddit.com`. A leading `www.` is dropped on purpose — someone typing
`www.reddit.com` means Reddit, and keeping the prefix would leave
`old.reddit.com` reachable.

Refused, with an explanation:

| Input | Why |
|---|---|
| `*`, `*.reddit.com` | A bare `*` is a valid Chromium pattern meaning *block every URL*. Reaching that by typo would take the whole web out. |
| `localhost` | No dot, so not a domain. |
| `reddit.com, twitter.com` | Add them one at a time. |
| `old.reddit.com` when `reddit.com` is already blocked | Tightens nothing, and burns one of the 1000 entries browsers honour. |
| `redditÉ.com` | Use the punycode form (`xn--…`). |

## Scheduled blocks

A **block** is a named group of extensions enforced on a schedule, optionally
locked so it cannot be released early. Add a `blocks` array alongside
`extensions`:

```json
{
  "extensions": [ ... ],
  "blocks": [
    {
      "id": "work",
      "label": "Work hours",
      "extensions": ["sieve"],
      "windows": [
        { "days": ["mon","tue","wed","thu","fri"], "start": "09:00", "end": "17:00" }
      ]
    },
    {
      "id": "quiet-hours",
      "windows": [{ "start": "22:00", "end": "06:00" }],
      "lockedUntil": "2026-09-01T09:00:00+08:00"
    }
  ]
}
```

- **`extensions`** / **`domains`** — what the block governs. Naming neither means
  it governs everything in both lists; naming either means it governs exactly what
  is listed, and nothing of the kind it leaves out.
- **`windows`** — recurring local-time ranges. Omit `days` for every day. An
  `end` at or before `start` runs **past midnight**: `22:00`–`06:00` on `fri`
  covers Friday night into Saturday morning. A block with no windows is simply
  always on.
- **`lockedUntil`** — RFC 3339. While it is in the future the block cannot be
  changed or removed **even with the uninstall password**. Capped at 90 days, so
  a mistyped year cannot lock someone out for decades.

A schedule only ever *narrows* enforcement. An extension no block governs is
enforced around the clock exactly as before, and an extension you switched off
stays off inside a window. **A config with no `blocks` behaves identically to
one written before schedules existed** — which is what keeps every existing
install unchanged on upgrade.

```sh
guard blocks                    # what is configured, what is enforcing now, what is locked
guard -until 72h lock work      # also 7d, 2026-09-01, 2026-09-01T17:00
guard commit                    # adopt your edits to extension-ids.json
```

In the **status window**, a "Scheduled blocks" section lists each block, its
timetable, whether it is enforcing right now, and its lock; unlocked blocks get
a **Lock** button offering 24h / 3d / 7d / 30d or a typed deadline. An extension
under a block is tagged `scheduled`, so one that is idle outside its window does
not read as a fault. The section is hidden entirely when no blocks are
configured, and an invalid schedule shows a banner saying the schedule is not in
use. **Authoring** blocks is still a config-file job — edit `extension-ids.json`
and run `guard commit`.

`lock` needs admin but no password — it only strengthens, and no command can
shorten a lock; it runs out on its own. `commit` needs the password, because it
can redefine enforcement wholesale, and is refused outright if it would touch a
block that is currently locked.

The service re-checks the schedule every 5s, comparing a computed signature
rather than reading the registry, so crossing a boundary takes effect promptly
without the polling cost.

**An invalid schedule fails closed.** A window that will not parse would make its
block look inactive and silently unlock everything it governs, so a config that
does not validate is enforced with its schedule *ignored* — everything enabled
stays locked until you fix it. `guard blocks` and `guard verify` both say so.

### What a lock is and is not

A lock means the commitment cannot be walked back early through the guard: not
by editing the file, not with the password, not by rebooting (the deadline lives
in the same SYSTEM-owned state as everything else, and the service enforces from
boot). It does **not** survive an authorized uninstall, which still needs only
the password. That is the honest ceiling, and it is the same one described in
`docs/pc-version.md` — the escape hatch is deliberate, because software that
cannot be removed at all is malware.

`verify` reports each browser as locked when **all** configured extensions for
that browser are force-installed. See `docs/pc-version.md` for the full
per-browser publishing rules — including Edge's "unmanaged devices can only
force-install from the Edge Add-ons store" restriction, which is why Edge needs
its own store listing.

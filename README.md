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
| 10 | **Activity log** (append-only local record + "Recent activity" in the window) | ✅ done |
| 11 | **Held pause** (protection off as a state the service keeps, with a deadline it resumes at) | ✅ done |
| 11 | **Time limits** (daily budget per block, counted by watching processes) | ✅ done |

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
how many browsers are locked, and the service state. To pause or resume, click
**Disable protection** / **Enable protection** — each pops a Windows **UAC**
prompt, and the guard re-verifies the password itself, so the button can't be
bypassed from the UI. Turning protection off asks **how long for** as well as for
the password; see [Pausing protection](#pausing-protection).

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

The **Blocked apps** section has four ways in - **Add .exe file** and **Add
folder** open the Windows pickers, **Add Store app** lists the Microsoft Store
apps installed for you, and **Add window title** takes typed text. Each row says
underneath what the rule actually covers, because "Steam" alone does not
distinguish one executable from a whole folder. Adding is free; removing needs the
password. See [Blocked apps](#blocked-apps).

The **Scheduled blocks** section lists any blocks with their timetable and lock
state, and offers **New block**, **Lock** and **Remove**. Creating a block with a
timetable needs the password (a schedule enforces things only *sometimes*);
creating an always-on one, and locking it, does not. See
[Scheduled blocks](#scheduled-blocks).

## Try it (Windows, Administrator shell required)

`apply`, `remove` write to `HKLM`, so run them from an **elevated** terminal.

```sh
guard domains      # blocked sites: which are on the list, which are enforced now
guard apps         # blocked applications: same, per rule
guard blocks       # scheduled blocks: which are enforcing now, which are locked
guard detect       # which browsers are installed
guard apply        # enforce everything the config asks for
guard verify       # show what is enforced, per area and target
guard remove       # lift it all (authorized uninstall)
```

`verify` reports one row per target with the columns `area`, `target`,
`present`, `enforced`, `detail`. The areas are `extensions`, `domains` and
`apps`; a target is a browser for the first two and one block rule for the last,
which is why the columns are worded generally rather than per browser.

### Enforcement backends

`internal/enforce` is the seam between *what* the guard should enforce and *how*
each kind of thing is enforced. An `Enforcer` applies, verifies, and removes one
kind of rule; `enforce.Default()` is the set the service drives, and the service
knows only that set - not what is in it. There are three members - `extensions`,
`domains`, `apps` - each a thin adapter over `internal/policy`, which owns the
registry and managed-policy-file work.

`Apply` and `Remove` fan out across the whole set and join errors rather than
stopping at the first failure, so one backend failing cannot silently leave the
others unenforced. Adding a kind of blocking means writing an `Enforcer` and
putting it in `Default()`, not threading a second code path through the service.

One backend needs more than "apply once": a browser honours a force-install
policy by itself, but *an application nobody has looked at yet is an application
that is running*. An `Enforcer` that also implements `Sweeper` says so, and the
service drives `Sweep` on a 1s ticker - which is how a blocked app is closed
promptly without re-writing policy keys every second. The service does not know
which backend needs it.

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
  **without waiting on code signing**, unlike [blocking
  applications](#blocked-apps).

What it does **not** cover, plainly: a browser the guard doesn't support, and any
non-browser app reaching a site of its own accord. Blocking the *app* is covered
below; filtering a non-browser app's traffic needs enforcement below the browser
and is still to come.

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

## Blocked apps

Games and other distracting applications are blocked alongside sites. A blocked
application **does not start** — and is closed if it is already running.

There are four kinds of rule, because "the app I want gone" is not one thing:

| `-kind` | What you give it | What it blocks |
|---|---|---|
| `exe` (default) | A full path (`C:\Games\Steam\steam.exe`) or a bare name (`steam.exe`) | That copy — or, for a bare name, that executable wherever it is installed |
| `folder` | A folder (`C:\Games\Steam`) | Every `.exe` under it, now and after an update renames one |
| `store` | A Microsoft Store package family name | That Store app, across version updates |
| `title` | Text (`Solitaire`) | Any window whose title contains it |

```sh
guard block-app "C:\Games\Steam\steam.exe"                  # admin; no password
guard -kind folder -label Epic block-app "C:\Games\Epic"    # every .exe in it
guard -kind store block-app Microsoft.MinecraftUWP_8wekyb3d8bbwe
guard -kind title block-app "Spider Solitaire"
guard unblock-app steam.exe                                 # password (unless paused)
guard apps                                                  # what is on the list, what is enforced now
```

Or use the four buttons in the **Blocked apps** section of the status window,
which browse for the file or folder, list the installed Store apps, and take a
typed window title. `unblock-app` needs the same `-kind` the rule was added with:
`Steam` as a window title is not `steam.exe`, and unblocking one must not unblock
the other.

```json
{
  "apps": [
    { "kind": "exe", "value": "C:\\Games\\Steam\\steam.exe", "label": "Steam" },
    { "kind": "folder", "value": "C:\\Games\\Epic" },
    { "kind": "store", "value": "Microsoft.MinecraftUWP_8wekyb3d8bbwe", "label": "Minecraft" },
    { "kind": "title", "value": "Solitaire", "disabled": true }
  ]
}
```

### How it works, and what it does not cover

Two mechanisms, because neither covers the ground alone:

- **A launch block**, via **Image File Execution Options** — the loader's "run
  this under a debugger" hook. With `Debugger` pointed at `guard blocked`, Windows
  starts the guard instead of the program and the user gets a message saying it is
  blocked. This is the only way to stop an app appearing on screen at all. IFEO is
  keyed on the executable's *file name* (with an optional full-path filter), so it
  can express an `exe` rule and nothing else, and it does not apply to Store apps,
  which are activated through a broker.
- **A sweep**, terminating anything running that matches any rule. It covers all
  four kinds and writes nothing, but it acts after the process exists — so a
  blocked app that slips past the launch block flickers for up to a second before
  it closes. The service sweeps every **1s**, and does nothing at all when no app
  rules are configured.

The launch block lives outside `HKLM\SOFTWARE\Policies`, so unlike the browser
policies it is **not** restored within milliseconds by the tamper watcher — it is
re-asserted by the 30s re-apply. The sweep is what covers the gap: delete the key
and the app starts, then closes a second later.

### Window titles need a session helper

A Windows service runs in **session 0** and cannot see the signed-in user's
windows — `EnumWindows` there enumerates the service desktop, which has none. A
title rule evaluated from the service would therefore match nothing and silently
enforce nothing, which is the one failure this project refuses to ship.

So when — and only when — a title rule is configured, the service starts a copy of
itself in the console session (`guard agent`, via `CreateProcessAsUser` on the
session token) that sweeps the title rules from where the windows actually are.
It holds no password, writes nothing, and exits when protection is paused, when
the service stops, or when the last title rule goes away. Every other rule kind is
matched on the process list, which is session-independent, and stays with the
service — whose SYSTEM rights let it close processes the user cannot.

Consequences worth knowing: a title rule does nothing while nobody is signed in
(there are no windows), and after signing in the helper appears within one
re-apply cycle (≤30s).

Reconciled, not accumulated: every re-apply removes launch blocks the guard owns
and no longer wants — including for a rule deleted from the config outright — and
leaves anything under IFEO it did **not** write alone. A rule on an executable
some other tool already debugs is refused with an error rather than silently
overwritten (the sweep still closes it).

What this is **not**: a kernel-level block. AppLocker needs Enterprise, Software
Restriction Policies are absent from Home editions, and a filesystem filter driver
needs an EV certificate and WHQL signing. What the guard has instead is the same
thing it has everywhere else — a SYSTEM service, a watchdog, and a password gate —
so a bypass has to survive continuous correction rather than just being applied
once. It also does not stop you *browsing* a blocked folder; it stops the
executables in it from running.

### Guardrails

Blocking the wrong thing here does not inconvenience you, it breaks the machine,
so the refusals are not negotiable:

| Refused | Why |
|---|---|
| `explorer.exe`, `lsass.exe`, `svchost.exe`, … | Windows needs them; killing one takes the desktop away or forces a reboot |
| `guard.exe`, `extension-guard-status.exe` | A rule must not be able to disarm the guard from inside |
| `C:\`, `D:` | A whole drive is every program on the machine |
| `C:\Windows`, `C:\Windows\System32`, or any parent of them | Same, by inclusion |
| A window title under 3 characters | It would match nearly every window, and the sweep closes what owns a match |
| `readme.txt`, `Games\steam.exe` | Not an executable; not a full path |

The protected-image list is checked **twice** — when a rule is added, so you are
told no rather than finding out later, and again in the sweep, so a rule that
reached the config some other way still cannot fire. A guardrail that only exists
at the input is not a guardrail.

### Code signing

This is the backend that made code signing a prerequisite rather than a nicety.
An **unsigned** service running as LocalSystem that terminates processes and
writes launch-block registry keys is exactly the shape antivirus heuristics are
built to quarantine — see [`docs/signing.md`](docs/signing.md). Blocking sites
could ship before the certificate; shipping this to end users should wait for it.

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

- **`extensions`** / **`domains`** / **`apps`** — what the block governs. Naming
  none of them means it governs everything in every list; naming any means it
  governs exactly what is listed, and nothing of the kinds it leaves out. Apps are
  listed by the `value` their rule is stored under (`"steam.exe"`), not by kind.
- **`windows`** — recurring local-time ranges. Omit `days` for every day. An
  `end` at or before `start` runs **past midnight**: `22:00`–`06:00` on `fri`
  covers Friday night into Saturday morning. A block with no windows is simply
  always on.
- **`limit`** — a daily time budget (`"45m"`, `"1h30m"`, or a bare number of
  minutes). The block enforces nothing until that much time has been used, and
  blocks from then until the day resets. It may only cover **apps** — see *Time
  limits* below.
- **`lockedUntil`** — RFC 3339. While it is in the future the block cannot be
  changed or removed **even with the uninstall password**. Capped at 90 days, so
  a mistyped year cannot lock someone out for decades. A lock covers the `limit`
  too: it cannot be raised, lowered, added, or dropped while the lock holds.

A schedule only ever *narrows* enforcement. An extension no block governs is
enforced around the clock exactly as before, and an extension you switched off
stays off inside a window. **A config with no `blocks` behaves identically to
one written before schedules existed** — which is what keeps every existing
install unchanged on upgrade.

```sh
guard blocks                    # what is configured, what is enforcing now, what is locked
guard limits                    # each daily limit and how much of today is left
guard -until 72h lock work      # also 7d, 2026-09-01, 2026-09-01T17:00
guard commit                    # adopt your edits to extension-ids.json

# create one without touching the file
guard -label "Work hours" -days weekdays -from 09:00 -to 17:00 \
      -extensions sieve -domains reddit.com -apps steam.exe add-block
guard -label "Seven day commitment" add-block     # no window: always on, made to be locked
guard remove-block work-hours
```

`add-block` takes the *name* and derives the id (`Work hours` → `work-hours`), so
nothing has to invent an identifier; pass one positionally to choose it yourself.
`-days` accepts `mon,wed,fri` or `weekdays` / `weekends` / `daily`, and omitting it
means every day. Naming no `-extensions`/`-domains`/`-apps` governs everything. One
window per block; a second window is still a config-file job.

**The gate is inverted here, on purpose.** Everywhere else, adding a rule
strengthens protection and costs only admin. A *schedule* does the opposite: it
takes something enforced around the clock and enforces it only sometimes, so
`add-block` **with** a window needs the password, exactly like unblocking a site.
With no window the block is always on, cannot weaken anything, and is free — that
is the shape you create and then `lock`. `remove-block` takes the password too:
when two blocks govern the same thing, dropping one can narrow the union of their
windows, and deciding which case applies is the window-coverage reasoning the guard
refuses to do. A locked block is refused outright either way.

In the **status window**, a "Scheduled blocks" section lists each block, its
timetable, whether it is enforcing right now, and its lock; unlocked blocks get
**Lock** (24h / 3d / 7d / 30d or a typed deadline) and **Remove** buttons, while a
locked one gets neither, because the guard would refuse both. An extension under a
block is tagged `scheduled`, so one that is idle outside its window does not read
as a fault, and an invalid schedule shows a banner saying the schedule is not in
use.

**New block** opens a form: a name, day chips (none chosen means every day),
`from`/`to` times or an **Always on** tick, and either *Everything* or a picked
list of the extensions, sites and apps you already have. It asks for the password
only when a window was set — the same inverted gate as the CLI, decided in one
place (`policy.Block.Narrows`) and re-checked by the elevated guard, so it cannot
be skipped from the renderer. Hand-editing `extension-ids.json` plus `guard commit`
still works, and is still the way to give one block several windows.

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
boot), and **not by pausing protection** — while any block is locked,
`guard disable` and the window's Disable button both refuse, and the attempt is
recorded. Pausing would otherwise be the cheapest way out there is: it lifts
everything the lock was holding, needs only the password, and leaves the
commitment nominally in place during exactly the window it is not being kept.
It does **not** survive an authorized uninstall, which still needs only
the password. That is the honest ceiling, and it is the same one described in
`docs/pc-version.md` — the escape hatch is deliberate, because software that
cannot be removed at all is malware.

`verify` reports each browser as locked when **all** configured extensions for
that browser are force-installed. See `docs/pc-version.md` for the full
per-browser publishing rules — including Edge's "unmanaged devices can only
force-install from the Edge Add-ons store" restriction, which is why Edge needs
its own store listing.

## Time limits

A block can carry a **daily budget** instead of - or as well as - a timetable:

```json
{
  "resetAt": "04:00",
  "apps": [{ "kind": "exe", "value": "steam.exe" }],
  "blocks": [
    { "id": "games", "label": "Games", "apps": ["steam.exe"], "limit": "45m" }
  ]
}
```

That block enforces nothing while there is time left, and blocks Steam the moment
the forty-five minutes are gone - closing it if it is running, and refusing to let
it start after that - until the day rolls over.

```sh
guard limits                                        # allowed, used, and the state of each limit
guard -label Games -apps steam.exe -limit 45m add-block
guard -label Evenings -apps steam.exe -limit 1h -days weekdays -from 18:00 -to 22:00 add-block
guard -until 7d lock games                          # the budget cannot be raised for a week
```

`-limit` accepts `45m`, `1h30m`, `1.5h`, or a bare number of minutes, and is capped
at 24h - a budget longer than the day it resets in could never be reached, which
would look like protection and be none. In the **status window** the New block form
has a *Daily limit* field, and a limited block's row reads `33m left today`,
`Used up`, or `Idle` rather than using one badge for three different states.

**The gate is inverted, like a schedule's, and more obviously so.** An app that was
blocked outright becomes one you may use for forty-five minutes, so creating a
limit needs the password. `policy.Block.Narrows` is the one place that decides, and
the elevated guard re-checks it.

### What is measured, and what is not

- **Apps only.** A limit needs usage measured, and the guard can only measure what
  it can watch: the process list, once a second, in the same sweep that closes
  blocked apps. A blocked *site* is enforced by handing the browser a policy and
  trusting it - nothing comes back - so "thirty minutes of Reddit" would be a
  promise nothing here could keep. A limit on extensions or domains is **refused by
  `Validate`**, not accepted and quietly ignored.
- **Running, not focused.** A game left open in the background spends its budget.
  Window focus is not visible from a service (session 0 cannot see the user's
  desktop), so measuring it would depend on the session helper being alive - and a
  limit that stops counting when nobody is signed in has an obvious way around it.
  Over-counting fails towards the commitment; under-counting fails away from it.
- **One budget per block**, shared by everything it covers: "an hour of games", not
  "an hour of each game". One app per block gives the per-app version for free.
- **Out-of-window time is not charged.** A block with both a window and a limit
  reads as "forty-five minutes *during these hours*", so use at an hour the block
  does not apply to spends nothing.
- **`resetAt`** (top level, `"HH:MM"`, default midnight) is when the day rolls over.
  A 4 a.m. reset matches what a person means by "a day" better than the calendar
  does - somebody still up at 00:30 should not be handed a fresh hour mid-session.

### Where the count lives

`C:\ProgramData\ExtensionGuard\usage.json` (`/var/lib/extension-guard` on
Linux): one small JSON object, `SYSTEM` and `Administrators` full control, **Users
read**.

Read matters - the status window is unprivileged and has to be able to show what is
left, and being able to see where you stand is most of the difference between a
limit and an ambush. Users get *no* write, not even the append the activity log
grants them, because there is no unprivileged writer here.

The counters are held in memory and flushed every 30s, plus immediately whenever a
limit is reached, so the ledger is not rewritten once a second for a number that
matters at one moment. A power cut can therefore hand back up to half a minute,
once. The service loads the file on start, so restarting it does not hand back the
day.

Three things it deliberately refuses to be fooled by:

- **An unreadable ledger fails closed** - every limit counts as spent, because the
  alternative makes "corrupt the file" mean "reset my limits". Failing closed is a
  *moment*, not a trap: the service rewrites the file from its own running count at
  the next flush, and rebuilds it from zero on startup if that is where it finds it -
  it has to, because a blocked app cannot run, so nothing would ever be charged and
  nothing flushed. A rebuild from zero is written to the activity log
  (`usage.reset`), because it is a budget coming back and every other way that can
  happen is recorded too. The window and `guard limits` both say what happened
  rather than showing a limit that looks broken.
- **The clock going back** does not un-spend time: the ledger remembers the latest
  day it has recorded and refuses to serve an earlier one.
- **A long gap between observations** is capped, so a machine that slept for eight
  hours is not charged for them.

And two it cannot. An administrator can **delete** the file, and a missing ledger
is indistinguishable from a fresh install; and setting the clock *forward* rolls
into a day nothing has been spent on. Both are the same class of hole as stopping
the service, and are answered the same way - the watchdog, and the fact that they
have to be done again every day. (Moving the clock forward and back again does not
help: the ledger's day only ever advances, so the day you left is not the one you
return to.) The honest ceiling is the one in `docs/pc-version.md`, and it has not
moved.

## Pausing protection

Protection can be turned off without uninstalling — but a pause is a **state the
guard holds**, not a teardown. The service stays installed, stays running and
stays watched by the watchdog; it simply enforces nothing.

That distinction is the whole feature. A pause used to *be* an uninstall, and
with the service gone there was nothing left to notice a deadline, nothing to
resume, nothing re-asserting the trusted config, and nothing writing the activity
log — during exactly the window protection was off. A pause with a deadline is
only worth anything if something outlives it.

```powershell
guard -for 30m disable    # back on in half an hour, by itself
guard -for 1d disable     # back on tomorrow
guard disable             # off until you turn it back on
guard enable              # end a pause now
```

`-for` takes what `-until` takes: `30m`, `2h`, `1d`, or a time like
`2026-09-01T17:00`. Pausing needs the password; ending a pause only strengthens
protection, so it needs admin and no password. In the status window, **Disable
protection** asks for a duration and the password together, and a bounded choice
is preselected — an indefinite pause is the one that goes wrong by accident.

**A bounded pause ends by the clock, not by anything running.** The deadline is
stored, and once it has passed every part of the guard reads protection as on
again — even if the service was killed, or the machine was off for a week. The
service noticing is how *enforcement* catches up, usually within a few seconds;
it is not how the pause ends. A pause value that cannot be read at all also means
protection is on, so a corrupted deadline fails towards being protected.

**A locked block refuses a pause outright.** See
[What a lock is and is not](#what-a-lock-is-and-is-not).

While paused, the window shows when protection comes back, and the activity log
records the pause and its deadline — along with anything that happens during it.

## Activity log

Every other part of the app answers *what is enforced right now*. The activity log
answers *what happened* — which is the question that matters when nobody was at the
machine. A refused launch at two in the morning, a pause nobody lifted, a config
edit the service reverted: each of those was invisible the moment it scrolled past.

The **Recent activity** list near the top of the status window shows the latest
entries, and `guard activity` prints them:

```powershell
guard activity            # the last 30 entries, newest first
guard -n 200 activity     # reach further back
```

```
  2026-08-20 21:50:31  Protection paused [Alfon]
  2026-08-20 02:40:00  Settings were changed outside the app; restored what is enforced - noticed on the periodic check [service]
  2026-08-20 01:15:00  Wrong password entered for unblocking an application [kid]
  2026-08-20 01:12:09  Closed steam.exe - matched the rule for Steam [service]
  2026-08-19 23:31:44  Blocked a launch of steam.exe [kid]
```

Reading it needs **no admin and no password**. That is deliberate: the record is
meant to be readable by everyone it is about, and needing elevation to see it
would make that transparency theoretical.

### What is recorded

| Event | Written when |
|-------|--------------|
| `launch.blocked` | a blocked application was started, and refused before it opened |
| `app.closed` | something already running matched a rule and was closed |
| `tamper.config` | `extension-ids.json` was edited behind the guard's back, and the trusted copy was restored |
| `tamper.policy` | a browser policy key was changed, and the guard put it back |
| `protection.installed` `.removed` `.paused` `.resumed` | protection as a whole was turned on or off |
| `pause.refused` | somebody tried to pause protection while a block was locked |
| `service.started` `.stopped` | the guard service came up or went down |
| `domain.blocked` `.unblocked` | a site was added to, or lifted from, the block list |
| `app.blocked` `.unblocked` | an application rule was added or lifted |
| `extension.enabled` `.disabled` | an extension started or stopped being locked |
| `block.created` `.removed` `.locked` | a scheduled block was created, deleted, or locked |
| `limit.reached` | a block's daily time budget ran out, so what it covers is blocked until the reset |
| `usage.reset` | the record of today's usage was unreadable, so the daily counts were started again |
| `password.changed` | the uninstall password was changed |
| `password.failed` | a wrong password was entered — and which action it was for |
| `update.applied` | the binaries were swapped for a newer release |
| `log.rotated` | the log passed its size cap, and older entries were moved aside |

Each entry also records **who**: the signed-in account for anything done at the
keyboard, or `service` / `agent` for the guard's own doing. For an action that
weakens protection, who did it is most of the point of writing it down.

Nothing about browsing is recorded — no URLs, no page content. The log holds the
guard's own actions. See [PRIVACY.md](PRIVACY.md).

Repeats collapse. The app sweep runs about once a second, so an application that
relaunches itself is recorded once every five minutes rather than sixty times a
minute, and corrected tamper is recorded at most once a minute.

The status window colours each row by what it means rather than by which
subsystem produced it: green for protection doing its job, amber for protection
being weakened — or somebody trying, which is why a failed password is amber.

### Where it lives, and how tamper-resistant it is

`C:\ProgramData\ExtensionGuard\activity.jsonl` on Windows — one JSON object per
line, appended and never rewritten. On Linux,
`/var/log/extension-guard/activity.jsonl`.

The Windows permissions are the interesting part:

| Who | Rights |
|-----|--------|
| SYSTEM, Administrators | full control |
| Users | read, and **append** — not write, not delete |

Read is deliberate, for the transparency reason above. Append is a narrow
concession, and it buys the single most valuable event: a refused launch is
reported by a handler Windows starts in the **blocked user's own unprivileged
session** (see the *Blocked apps* section), so without append it could not record
itself at all. Only privileged code ever *creates* the log, and the guard takes
ownership of it — an owner keeps the right to rewrite permissions however the
permissions read, so letting a standard user create the file would hand them that
right permanently.

What this does and does not buy, stated plainly:

- A standard user **cannot** delete the file, and cannot remove or alter one entry
  in it.
- A standard user **can** append noise, and enough noise eventually rotates older
  entries out (the log rotates at 2 MB and keeps one previous file). A rotation
  writes its own marker, so a forced one appears in the record instead of leaving
  a silent gap.
- A **local administrator** is outside all of this, exactly as everywhere else in
  the guard — see the tamper-resistance discussion in `docs/pc-version.md`.

An authorized uninstall does **not** delete the log. It records that protection was
removed, and a record an uninstall erases is not a record.

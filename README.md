# Ward (PC version)

A native parental-control and self-control tool for **Windows** and **Linux**. It
blocks websites, applications and browsers, hardens the browser's own settings,
holds all of it to a schedule and a daily budget, and resists being switched off:
a watchdog restarts it, weakening it costs minutes of typing, and removing it
needs a password.

It works by running as a privileged service *above* the browser, which is what
makes any of this stick. An extension cannot prevent its own uninstall; a process
with enterprise-policy rights can force-install one and grey out the Remove and
Disable buttons. The same position lets it write a URL blocklist the browser
obeys, pin DNS to a filtering resolver, and refuse to let an unmanaged browser run
at all.

Everything below is verified on a timer and re-applied if it is tampered with:

| Area | What is enforced |
|---|---|
| **Extensions** | force-installed by enterprise policy, un-removable from the browser UI |
| **Sites** | per-browser `URLBlocklist`, subdomains included — or allowlist mode, where everything *else* is blocked |
| **Apps** | matched on the name compiled into the executable, so renaming the file does not help |
| **Browsers** | the ones it cannot filter are blocked outright, rather than left as a hole |
| **Browser settings** | private and guest windows off, SafeSearch forced, DNS pinned to a filtering resolver |
| **Schedules** | named windows — days, start, end — instead of always-on |
| **Time limits** | a daily budget per block, counted by watching processes, against the real day |

It stays product-neutral about the extensions it locks: point it at any set of
store-published extensions (e.g. BlockNSFW and Sieve) and it locks them all with
one install.

The OS-specific code is selected at build time by Go build tags
(`*_windows.go` / `*_linux.go`) — Windows uses the registry and the Service
Control Manager, Linux uses managed-policy files and systemd — so this is one
app, not two. See the **Linux** section below.

> `docs/pc-version.md` has the full picture of why a process above the browser is
> the only place this can be enforced from.

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
| 12 | **Unmanaged browsers** (find the browsers the guard cannot filter, and block them) | ✅ done |
| 13 | **Rename-resistant rules** (match the name compiled into an executable, not just the file's) | ✅ done |
| 14 | **Hardened browser settings** (no private/guest windows, forced SafeSearch) | ✅ done |
| 15 | **Usage statistics** (per-application time, today and over 60 days) | ✅ done |
| 16 | **Allowed sites only** (block every site except a list, on a timetable) | ✅ done |
| 17 | **Typing challenge** (weakening protection costs minutes of typing, not one keystroke) | ✅ done |

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
| `Ward-Setup.exe` | installer that bundles both + creates shortcuts |

Go core only: `go test ./...` then `go build ./cmd/guard`.

## Install the app (end users — Windows)

Run `release\Ward-Setup.exe`. It shows a consent page, asks
you to **set an uninstall password** (give it to the parent / accountability
partner, *not* the person being filtered), installs + starts the guard service,
locks the browsers, and creates an **Ward** shortcut.

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
2. **It's deliberately tamper-resistant.** Ward runs a service with a
   watchdog that restarts itself if it's killed — that's the entire point (it
   stops the filtered user from simply uninstalling it). That "won't stay dead"
   behavior is *also* what some malware does, so a **small number** of heuristic /
   machine-learning antivirus engines (e.g. Bkav, Elastic) may flag it as a
   generic false positive — not a named-threat signature. It only installs after
   you tick the **consent** box, and only the person holding the uninstall
   password can remove it. See [docs/signing.md](docs/signing.md) for the full
   story, the signing plan, and how false positives are reported.

**What it does — and doesn't:** it writes browser and system policy —
force-install, URL blocklists, hardened browser settings — keeps it applied, and
blocks the applications and unmanaged browsers you have listed. It collects **no**
personal data and sends nothing anywhere: the only calls it makes are the update
check and the announcement banner. The one exception worth naming is `dns-filter`,
and it is not the guard calling out — it points the *browser's* DNS at Cloudflare
for Families, so name resolution goes there instead of to your ISP.

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

**Privacy:** Ward collects no personal data — see
[PRIVACY.md](PRIVACY.md).

### Status window (day-to-day)

`extension-guard-status.exe` shows whether protection is **Active / Paused / Inactive**,
how many browsers are locked, and the service state. To pause or resume, click
**Disable protection** / **Enable protection** — each pops a Windows **UAC**
prompt, and the guard re-verifies the password itself, so the button can't be
bypassed from the UI. Turning protection off asks **how long for** as well as for
the password; see [Pausing protection](#pausing-protection).

The window is a console rather than one long page: a top bar carrying
**Overview**, **Browsers**, **Blocking** and **Schedule & time** (`Ctrl+1` to
`Ctrl+4`) plus whatever acts on the open page, a workspace of cards, and a
status bar. Every page opens on a row of figures — safeguards on, browsers
locked, rules enforcing, screen time today — each one a count of rows on a card
below it, so the two can never disagree. The Overview charts the week's screen
time and the mix of rules being enforced; the Schedule page charts the same
week as a column per day beside the applications the time went to.

Cards are sized by what is in them. A list of three sites is three rows tall,
a card with nothing in it becomes a strip carrying the way in, and the cards
sharing a row divide the width by how much each has to show — so a quiet
machine is a short page rather than a screenful of empty panels. The **?**
beside a card's title explains it, `/` jumps to the filter over the block
lists, and `Ctrl+R` re-reads the state. The appearance button next to
**Refresh** switches between **Follow system**, **Light** and **Dark** — the
choice is per user, kept in `%AppData%\Ward\ui.json`, and read before the
window opens so a cold start does not flash the other theme.

The **Protected extensions** list lets you turn each configured extension on or
off after install: turning one **on** is free (it only adds protection), turning
one **off** requires the password. Each toggle runs the guard elevated (UAC) and
rewrites the config; the service picks the change up on its next cycle. This is
how you add a second extension (e.g. Sieve) to a guard you first installed for
just one — no reinstall needed.

The **Other browsers here** section lists every browser the guard
writes no policy for, badged **Reachable**, **Waiting**, **Blocked** or **File
gone**, with the executable to block it by. A warning sits above it whenever
anything is Reachable, because a window saying "protection active" over a browser
that filters nothing is the one thing this app must not do. See
[Browsers the guard cannot manage](#browsers-the-guard-cannot-manage).

The **Where the time went** card, on the Schedule & time page, shows how long each
blocked application actually ran, today and over the last week, with **By day**
charting the span beside it. It is the one card that is a record rather than a control -
there is nothing to click, and reading it needs neither admin nor the password.
See [Time used](#time-used).

The **Allowed sites only** section is the block list read the other way round -
one box, one list, and a button that turns the mode on or off. Turning it on is
free; turning it off, and letting a site through, need the password. A warning box
appears when the mode is on with an empty list, because that blocks every page in
every managed browser. See [Allowed sites only](#allowed-sites-only).

The **Browser settings** section lists the settings the guard pins so the locks
above hold, each saying which browsers it reaches and — where there is one — which
it does not. A warning sits above it whenever private browsing is still available
while an extension is being locked, because an extension does not run in a private
or guest window. Pinning is free; handing one back needs the password, and so does
lowering a SafeSearch level that is already stricter. See
[Browser settings](#browser-settings).

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
guard allowed      # allowed-sites-only: the mode, its timetable, what it lets through
guard usage        # how long each blocked application actually ran
guard hardening    # pinned browser settings, and whether private browsing is still open
guard domains      # blocked sites: which are on the list, which are enforced now
guard apps         # blocked applications: same, per rule
guard blocks       # scheduled blocks: which are enforcing now, which are locked
guard detect       # which supported browsers are installed
guard browsers     # every browser here, and which of them the guard cannot filter
guard apply        # enforce everything the config asks for
guard verify       # show what is enforced, per area and target
guard remove       # lift it all (authorized uninstall)
```

`verify` reports one row per target with the columns `area`, `target`,
`present`, `enforced`, `detail`. The areas are `extensions`, `hardening`,
`domains` and `apps`; a target is a browser for the first three and one block rule
for the last, which is why the columns are worded generally rather than per
browser.

### Enforcement backends

`internal/enforce` is the seam between *what* the guard should enforce and *how*
each kind of thing is enforced. An `Enforcer` applies, verifies, and removes one
kind of rule; `enforce.Default()` is the set the service drives, and the service
knows only that set - not what is in it. There are four members - `extensions`,
`hardening`, `domains`, `apps` - each a thin adapter over `internal/policy`, which
owns the registry and managed-policy-file work.

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
- **The Firefox family is Firefox alone here.** Zen, and the fork discovery that
  covers Floorp/LibreWolf/Waterfox on Windows, both rest on a registry key named
  after the application. Linux has no equivalent: Mozilla's engine reads a fork's
  policies from the `distribution` directory inside the install, and where that
  is depends on how it was installed (distro package, tarball in a home
  directory, a flatpak the guard cannot write into at all). So the Linux build
  lists Firefox and nothing else, rather than showing rows for browsers nothing
  is written for — see `geckoBrowsers` in `internal/policy/policy_linux.go`.

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

## Browser settings

Locking an extension greys out its Remove button. What it does **not** do is put
the extension in a window it cannot run in — and Chrome's own documentation is
explicit about one: *extensions cannot be force-installed into Incognito, and the
remedy is to turn Incognito off*. A guest profile is worse, because it carries no
extensions at all.

So `Ctrl+Shift+N` was a bypass of every locked filter that needed no download, no
administrator and no rename, while the status window read *protection active* —
the same failure [`guard browsers`](#browsers-the-guard-cannot-manage) exists to
report one step further out.

**How wide that hole is depends on the browser**, and the answer is no longer the
same in all of them:

- **Firefox and Zen no longer have it.** Mozilla added `private_browsing` to
  `ExtensionSettings` in Firefox 136 and ESR 128.8, so the guard force-enables the
  add-on in private windows outright — no switch, and nothing for the user to
  agree to. It is written next to `installation_mode` by the extension enforcer
  rather than by a setting here, because it takes no feature away and so is part
  of force-installing rather than something to opt into.
- **Edge can be held up instead of shut down.** `MandatoryExtensionsForInPrivateNavigation`
  (Edge 139) lets InPrivate open but refuses to navigate in it until the user
  allows the locked extension there. That is `private-extensions` below.
- **Chrome and Brave still have it whole.** Google's equivalent policy exists but
  is declared for ChromeOS only, so writing it on a desktop would verify perfectly
  and enforce nothing — the exact half-truth this project refuses to ship. Turning
  Incognito off is still the only lever there.

Four settings close it, and they are pinned the way everything else here is
enforced: policy values in `HKLM\SOFTWARE\Policies`, which the tamper watcher
already watches, so a deleted one is restored within milliseconds for free.

```sh
guard hardening                        # what is pinned, where it reaches, and what is still open
guard harden private-browsing          # admin; no password - it only adds protection
guard harden private-extensions        # edge: keep InPrivate, but require the extension in it
guard harden safe-search               # strict by default
guard -level moderate harden safe-search
guard harden dns-filter                # resolve through a filtering resolver, pinned closed
guard unharden private-browsing        # password (unless protection is paused)
```

```json
{
  "hardening": {
    "privateBrowsing": true,
    "privateExtensions": true,
    "safeSearch": "strict",
    "dnsFilter": "cloudflare-family"
  }
}
```

| Setting | What it pins | Where |
|---|---|---|
| `private-browsing` | No Incognito or private windows, and no guest profiles. Brave's *private window with Tor* too, which the Chromium switch does not describe. | chrome, edge, brave, firefox, zen |
| `private-extensions` | InPrivate stays, but will not navigate until the locked extensions are allowed to run in it. The narrower alternative to the row above, for a machine where InPrivate is actually used. Needs Edge 139. | edge |
| `safe-search` | Google and Bing SafeSearch, and YouTube's restricted mode. `-level` takes `moderate` or `strict`. | chrome, edge, brave |
| `dns-filter` | Every browser's DNS, pinned to [Cloudflare for Families](https://developers.cloudflare.com/1.1.1.1/setup/) — malware and adult content — with no fallback, so it cannot be turned off by breaking it. | chrome, edge, brave, firefox, zen |

**The hole is reported whether or not you close it.** `guard verify`, `guard
hardening` and the status window all say so while any extension is being
force-installed and private browsing is still available. It is asked per browser
rather than once, because the answer stopped being the same everywhere: a machine
locking only Firefox has nothing to warn about, and neither does an Edge machine
with `private-extensions` on. It is deliberately not a
row in `verify`'s table, for the reason an unmanaged browser is not one: those are
enforcement facts, and a row that is present and can never be enforced would read
as permanent tamper and log a correction every thirty seconds. The warning is also
gated on an extension **actually** being locked — a config whose targets are still
`REPLACE_*` placeholders locks nothing, and a warning that is always on teaches you
to skip past it on the day it means something.

**Nothing here is turned on for you.** It would be defensible to argue that closing
the Incognito hole is part of what "lock this extension" already promised, and to
enable it for everybody on upgrade. It is refused for the reason in
`internal/policy/categories.go`: what is enforced has to keep living in the config,
where the person bound by it can read it, and an update that silently widened
enforcement would be this app's own premise pointed the wrong way.

**Ordinary profiles are left alone**, and need no blocking: a machine-wide
force-install reaches every named profile. It is only the two windows that carry no
extensions that had to be closed.

**Firefox has no SafeSearch policy** — not a preference to lock, not an
`ExtensionSettings` entry, nothing, and Zen inherits the gap it was forked from.
So that setting is not enforced in either, and `guard hardening` and the window
both say "not enforced in firefox, zen" rather than showing a row that looks
applied. `guard verify` reports `not available in firefox`
for the same reason, which is a different fact from `not configured`.

### Filtered DNS, and why it is not a list

`dns-filter` is the one setting here that blocks content, and the only one in the
whole guard that does it **without shipping a list**. That is the point of it.

The block list uses each browser's `URLBlocklist`, and Chromium silently ignores
entries past **1,000** — so a hand-curated set of adult domains is stale on
release day and can never be more than a gesture. A filtering resolver moves the
classification to someone who maintains it continuously, and the config stores one
readable line naming *who*, rather than a few dozen hostnames compiled into the
binary. Cloudflare for Families answers `0.0.0.0` for anything it filters.

What gets written, and it is fail-closed by construction:

| Family | Policy | Value |
|---|---|---|
| Chrome/Edge/Brave | `DnsOverHttpsMode` | `secure` — DoH only, **no** fallback to plaintext DNS |
| | `DnsOverHttpsTemplates` | `https://family.cloudflare-dns.com/dns-query` |
| Firefox/Zen | `DNSOverHTTPS\Enabled` | `1` |
| | `DNSOverHTTPS\ProviderURL` | the same endpoint |
| | `DNSOverHTTPS\Locked` | `1` — not changeable in `about:preferences` |
| | `DNSOverHTTPS\Fallback` | `0` — Firefox 124+ |

`automatic` mode is deliberately not used: it falls back to plaintext DNS on any
error, which turns *make the resolver unreachable* into a working bypass rather
than a broken browser. Same for Mozilla's `Fallback`.

**The costs are real, and you should decide before turning it on.** Fail-closed
means a resolver that cannot be reached is a browser that loads nothing:
captive-portal wifi (hotels, airports, some campuses) will not come up, a VPN or
corporate network with its own internal names will not resolve them in the
browser, and a Cloudflare outage is your outage. Turning it back off takes the
password, like every other weakening.

What it does **not** cover:

- **Any non-browser application.** DNS is pinned per browser, by browser policy.
  Everything else on the machine uses the machine's own resolver.
- **A browser the guard writes no policy for** — run
  [`guard browsers`](#browsers-the-guard-cannot-manage).
- **One page of a site.** DNS answers for whole hostnames, so this cannot do
  "YouTube but not that video". That stays `safe-search`'s and the extensions'
  job.
- **Firefox before 124**, which has no `Fallback` policy: the other three values
  still apply, and it reverts to the machine's resolver on error. Weaker than the
  Chromium half, and `guard harden dns-filter` says so when you turn it on.

So the honest division of labour: `dns-filter` is coverage, the locked extensions
catch the tail and the paths, `safe-search` handles search results, the block list
is a small set you chose by hand, and [allowed-sites-only](#allowed-sites-only) is
the airtight option when you want one.

**These are not schedulable.** A block narrows what is enforced during declared
windows; "Incognito is disabled on Tuesdays" is not worth the complexity, and a
setting that is off half the time is a setting that does nothing — the same reason
a limit that cannot be measured is refused outright.

### Adult content, as a category with nothing in it

Cold Turkey ships *block adult websites*. So does this, as `guard block-category
adult` — and it contains **no websites at all**:

```sh
guard categories adult          # read what it will change before agreeing to it
guard block-category adult      # admin; no password - it only adds protection
```

```
Adult content - 2 browser settings
none of it is in force yet

  entry                          state            covers
  Filtered DNS                   new              Cloudflare for Families - malware and adult content
  SafeSearch and restricted mode new              strict
```

That is the entire category. It turns on `dns-filter` and `safe-search`, and
stops.

**Why there is no list.** What counts as adult content is a question with
millions of answers that change daily. A few dozen hostnames compiled into this
binary would be out of date the week they shipped, and the failure mode is the
bad one: the block *looks* like it worked while the next site along loads fine,
so the person relying on it stops checking. Shipping a list here would be making
a promise the program cannot keep. A filtering resolver already answers that
question continuously, and keeping the answer current is somebody's full-time
job — which is the same argument [Filtered DNS](#filtered-dns-and-why-it-is-not-a-list)
makes one level down, applied to the feature that would most obviously have been
written as a blocklist.

`TestAdultCategoryShipsNoListAtAll` is the guardrail. Anybody who wants to add
hostnames has to delete that test first, and then argue with its name.

**No application rules either**, and that is not an omission. This content is
reached through a browser. Naming executables would be guessing at software
nobody has verified is installed anywhere, and a shipped rule is applied by
somebody who has not looked at it — the same reason `ValidateCatalog` refuses
window-title rules outright.

**`private-browsing` is deliberately not the third setting.** It is the right
knob for a locked extension, which cannot load in a Chromium Incognito window — but both
settings here are *browser policy*, and browser policy applies to Incognito too.
Adding it would take a feature away to buy nothing, under a switch that costs no
password.

#### What a category with no rules changes elsewhere

This is the first category that creates **no block**, and the wording follows the
thing rather than the habit: it is turned **on**, never *blocked*; the window
badges it `On` and offers `Turn on` rather than `Block`; there is nothing to put
on a schedule and nothing to lock. `policy.Category.BlocksAnything` is the single
place that decides which of the two shapes is in hand, and `Config.CategoryApplied`
is what *in force* means when there is no block to look for — without it, adult
would read `available` forever, having been applied.

Two rules hold the settings half to the same bar the rules half is held to:

- **A category can never lower a setting.** Applying one costs no password, so a
  category asking for `moderate` on a machine already set to `strict` would be
  the way around `HardenWeakens`. `ApplyCategory` skips any setting that would
  filter less than what is already in force.
- **A resolver you already chose is yours.** If filtered DNS is already on,
  applying this category leaves your resolver alone rather than swapping it for
  whichever one this program happens to name first. That is the same principle
  that leaves a hand-added rule unclaimed by the category that would have added
  it: a lateral move taken without a password is not protection.

Lifting it is `guard unharden dns-filter` and `guard unharden safe-search`, which
take the **password**, because those are the steps that weaken. There is no
`remove-block adult`, because there was never a block.

### The gate, and the one place it inverts

Pinning a setting only strengthens protection, so it costs **admin** and no
password, exactly like `block-domain`. Handing one back takes the **password**,
like `unblock-domain`.

The exception is a SafeSearch level going *down*: `harden safe-search -level
moderate` on a machine already set to `strict` is a request to filter **less**, so
it takes the password too. Without that it would be the only way to weaken
protection without one. `policy.Config.HardenWeakens` is the single place that
decides, and the elevated guard re-checks it, so it cannot be skipped from the
status window.

A pause lifts these along with everything else — protection being off has to mean
private windows work again, or a pause would be leaving something enforced. An
authorized uninstall clears them, which is why the guard only ever removes a value
that still holds one it wrote: the machine has to come back the way it was.

### What it does not cover

- **A browser the guard writes no policy for.** Opera's private window was never
  filtered in the first place — see
  [Browsers the guard cannot manage](#browsers-the-guard-cannot-manage).
- **The browser actually obeying.** The guard can verify that it wrote the policy,
  never that Chrome honoured it. That is true of every policy in this project;
  the defence is that only settings the browsers document are written, which is
  why the per-browser support table is maintained by hand in
  `internal/policy/hardening.go` rather than guessed at.
- **SafeSearch as a substitute for the block list.** It filters search results and
  YouTube. A site reached directly is unaffected.

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

## Allowed sites only

The block list read the other way round: **block every site**, then name the
exceptions. This is study mode, and it is the one thing Cold Turkey has that a
list of blocked domains cannot express.

```powershell
guard allowed                       # the mode, its timetable, and what it lets through
guard allow-only on                 # admin; no password - it blocks the whole web
guard allow wikipedia.org           # password while the mode is on - it opens something
guard unallow wikipedia.org         # admin; no password - it closes it again
guard allow-only off                # password - it unblocks the whole web
```

```json
{
  "allowlist": {
    "on": true,
    "sites": ["wikipedia.org", "github.com"],
    "windows": [{ "days": ["mon","tue","wed","thu","fri"], "start": "09:00", "end": "17:00" }]
  }
}
```

Same mechanism as [Blocked sites](#blocked-sites), pointed the other way:
Chromium's `URLBlocklist` takes `*`, which blocks every URL, and `URLAllowlist`
overrides it entry by entry; Firefox's `WebsiteFilter` takes `<all_urls>` in
`Block` with the same exceptions in `Exceptions`. So it costs no new enforcement
surface at all — two more values in the hive the tamper watcher already watches,
and it ships without waiting on the certificate.

An allowed site covers **every subdomain**, exactly as a blocked one does:
`wikipedia.org` lets `en.wikipedia.org` through.

### The gate inverts — twice

Read this slowly, because it is the opposite of the block list in **both** halves:

| Action | What it does | Costs |
|---|---|---|
| `allow-only on` | blocks the entire web | admin, no password |
| `allow-only off` | unblocks the entire web | **password** |
| `allow <site>` | opens something the mode had closed | **password** (while the mode is on) |
| `unallow <site>` | closes it again | admin, no password |

So on the block list *adding* is free and *removing* costs the password; here it is
the other way round. `policy.AllowNarrows` is the single place that decides, and
the elevated guard re-checks it, so the status window cannot skip it.

Allowing a site while the mode is **off** is free, because the allowlist is
enforcing nothing and adding to it opens nothing — the same reasoning that makes
creating a windowless block free.

### A timetable, for the study-mode shape

`windows` are when the mode applies, and mean exactly what they mean on a
[scheduled block](#scheduled-blocks) — including `end` before `start` running past
midnight. Empty means around the clock.

Outside its window the mode reads as **waiting**, not off. That distinction is the
point: "off" would say somebody turned it off. Crossing the boundary is picked up by
the same 5s schedule check a block's window is, because the mode is part of the
resolved config and therefore part of the signature the service compares.

Giving a mode that is currently on a timetable **narrows** enforcement — it takes
something applied all day and applies it only sometimes — so it costs the password,
the same inverted gate `add-block` with a window has. One window from the CLI; a
second is a config-file job plus `guard commit`.

### Guardrails

**A site cannot be on both lists.** Chromium gives an allowlist entry precedence
over a blocklist entry of the same specificity, so accepting both would make
`guard domains` report a site as blocked while the browser let it through — a true
statement doing the work of a false one. `guard allow` refuses it, naming the
blocklist entry that covers it and what to do about it, and `Validate` refuses it
again for a config edited by hand. It covers subdomains too: with `gambling.example`
blocked, allowing `sports.gambling.example` is refused.

**A bare `*` is still refused as a site.** `NormalizeDomain` has always turned it
down, because reaching "block every URL" through the box you type `reddit.com` into
would take the whole web out by typo. That refusal stays — this mode is the
deliberate door, and it is deliberately somewhere else.

**An empty allowlist with the mode on is allowed, and said out loud.** Every page in
every managed browser is refused; that is what "block the entire internet" means and
it is a legitimate thing to want. The CLI prints it in as many words and the status
window shows a warning box, because it is also the state somebody reaches by
accident.

**Turning it off is reconciled, not forgotten.** The `*` entry and every exception
are pruned when the mode goes off, and cleared outright on an authorized
uninstall — a teardown that left the block-all entry behind would leave a machine
with no web and no guard to lift it. `RemoveDomains` therefore checks the allowlist
as well as the block list before deciding there is nothing to undo, since a config
that only ever used this mode has no blocked domains at all.

### What it does not cover

- **A browser the guard writes no policy for.** This is the feature where that gap
  goes from a leak to the whole roof: every site blocked in Chrome, Edge, Brave and
  Firefox is every site reachable through Opera. `guard allow-only on` prints the
  unmanaged-browser warning underneath for exactly that reason. See
  [Browsers the guard cannot manage](#browsers-the-guard-cannot-manage).
- **Anything that is not a browser.** The URL filter is a browser policy; an
  application reaching the network on its own account is unaffected. Block the
  *application* instead.
- **Sign-in and captive-portal pages.** Blocking everything blocks those too. Allow
  what you need, or turn the mode off for the minute it takes.
- **Per-browser rows in `verify`.** The mode folds into each browser's existing
  `domains` row rather than adding one of its own, tallied together so a partial
  count stays meaningful — half of this mode applied is not the mode, and it must
  not read as `ok`.

## Blocked apps

Games and other distracting applications are blocked alongside sites. A blocked
application **does not start** — and is closed if it is already running.

There are four kinds of rule, because "the app I want gone" is not one thing:

| `-kind` | What you give it | What it blocks |
|---|---|---|
| `exe` (default) | A full path (`C:\Games\Steam\steam.exe`) or a bare name (`steam.exe`) | That copy — or, for a bare name, that executable wherever it is installed, **including after it is renamed** ([why](#renaming-the-one-bypass-nothing-corrected)) |
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

## Browsers the guard cannot manage

Everything above works by writing policy that **Chrome, Edge, Brave, Firefox and
Zen read** — and, since the guard asks each Firefox fork what it is called, any
fork installed here as well (see [below](#zen-and-firefox-forks-generally)). A
browser outside that reads none of it: no locked extension, no blocked site, no
filtering at all. Install Opera and every entry on the block list is one click
away, while the status window still says protection is active — a true statement
doing the work of a false one.

So the guard looks for them and says so:

```sh
guard browsers     # every browser here, and what the guard can do about each
```

```
  browser                            state      executable
  Internet Explorer                  reachable  C:\Program Files\Internet Explorer\iexplore.exe
  Opera Stable                       reachable  C:\Users\kid\AppData\Local\Programs\Opera\opera.exe
  Google Chrome                      filtered   C:\Program Files\Google\Chrome\Application\chrome.exe
  Microsoft Edge                     filtered   C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
  Mozilla Firefox                    filtered   C:\Program Files\Mozilla Firefox\firefox.exe
  Zen Browser                        filtered   C:\Program Files\Zen Browser\zen.exe
```

| state | meaning |
|---|---|
| `filtered` | the guard writes policy this browser reads, so the locked extensions and blocked sites apply inside it |
| `blocked` | the guard cannot filter it, so it is on the block list and will not run |
| `idle` | on the block list, but outside its block's window right now |
| `reachable` | neither filtered nor blocked — every blocked site is reachable through it |
| `gone` | registered as a browser, but the executable it names is not there — see [Renaming](#renaming-the-one-bypass-nothing-corrected) |

`guard verify` prints a one-line warning when anything is `reachable`, and the
status window grows an **Other browsers here** section under the
Browsers list, with the same four states as badges. Reading any of it needs
neither admin nor the password, like `guard activity`: a gap only the parent can
see is one the household argues about instead of closing.

Blocking them is an ordinary category:

```sh
guard categories browsers          # see all 16 applications and 10 sites first
guard block-category browsers      # admin; no password - it only adds protection
```

### Where the list comes from

Windows already keeps one, because the Default Apps screen needs it:
`SOFTWARE\Clients\StartMenuInternet`, a subkey per registered browser naming the
executable to open a page with. The guard reads it from `HKLM`, from
`WOW6432Node` (a 32-bit browser on 64-bit Windows), and from `HKCU` — that last
one matters most, because a per-user install needs no administrator and is
therefore exactly the install a standard account can perform for itself.

The scan does one more read than that. A registration the executable name does
not identify is looked up in its own install directory — `application.ini`, next
to the exe — so a Firefox fork can be classified by what it calls itself. That is
what moves a fork out of this list and into the filtered ones; see
[Zen, and Firefox forks generally](#zen-and-firefox-forks-generally).

This is a different question from `guard detect`, and both are worth having.
`detect` asks *is Chrome here*, from a fixed list of four, to know whether a
policy has anything to act on. `browsers` asks *what is here*, from no list at
all, to find what no policy covers — which is why it finds browsers the built-in
category has never heard of. Both of the `reachable` rows in the example above
were found that way on a real machine before either was in the catalog.

The finding is **reported, never auto-enforced**. What is blocked has to keep
living in the config where the person bound by it can read it (see the top of
`internal/policy/categories.go`); a guard that closed a browser because a list
inside the binary named it would be enforcing a rule nobody agreed to, and that
list would widen on every update. It is also deliberately not a row in `verify`'s
table: those are enforcement facts, and the service counts the enforced ones to
decide whether a re-apply corrected anything — a row that is present and can
never be enforced would read as permanent tamper and log a correction every 30
seconds for as long as Opera stayed installed.

### Zen, and Firefox forks generally

Zen was on that block list until it stopped needing to be. Mozilla's policy
engine does not read one shared key: it reads
`SOFTWARE\Policies\Mozilla\<application name>` — `...\Mozilla\Firefox` in
Firefox, `...\Mozilla\Zen` in Zen. Write the same `ExtensionSettings`,
`WebsiteFilter` and `DisablePrivateBrowsing` values under Zen's own root and it
honours every one of them, from the same add-on on addons.mozilla.org — so
`extension-ids.json` needs no `zen` block at all: Zen force-installs the
`firefox` target exactly as written, and a config from before this still encodes
byte for byte the way it did.

If you blocked the **Unmanaged browsers** category before this, your config
still carries the `zen.exe` rule it expanded into — a category becomes ordinary
rules at the moment it is added, and nothing rewrites them later. Zen is then
filtered *and* closed on sight, which is not wrong so much as pointless: turn
that rule off with `guard unblock-app zen.exe` (it needs the password, since it
takes protection away) if you would rather have the filtering than the block.

The other forks — Floorp, LibreWolf, Waterfox, and whatever ships next year —
are covered without being named anywhere, because the guard asks instead of
guessing. Every Gecko install ships an `application.ini` beside its executable
with the name in it:

```ini
[App]
Name=LibreWolf

[Gecko]
MinVersion=145.0
```

So when the browser scan finds a registration it does not recognise, it reads
that file. A browser that declares a name **and** a `[Gecko]` section gets
`SOFTWARE\Policies\Mozilla\<that name>` written for it, a row in `guard verify`,
and every policy Firefox gets. One that declares neither stays in the unmanaged
list, where `guard browsers` reports it as a hole to block.

What that buys is that the guess is never made. A wrong policy key does not fail
loudly: the write succeeds, verification passes — it verifies that the policy was
*written*, which it was — and the browser reads a different key and carries none
of it. `filtered` over a browser enforcing nothing is worse than the block the
category already applies, so the name has to come from the browser itself.

The name is refused unless it is a plain application name — no separators, no
control characters, nothing over 40 characters. It arrives from a file inside the
browser's own directory, which for a per-user install is a directory the person
being filtered can write, and it ends up as part of a registry path under HKLM.

Two limits, stated here rather than discovered later:

| Limit | Why |
|---|---|
| **Only what is installed** | Firefox and Zen get their keys whether or not they are on the machine, so the lock is already waiting the day one is installed. A discovered fork gets its key on the first reconcile *after* it appears. |
| **Per-machine installs, from the service** | The registration scan reads the calling user's `HKCU`, so the service — running as LocalSystem — sees per-machine installs and not a per-user one. The window and the CLI run as the person whose machine it is and see both, so a per-user fork shows up there and an elevated `guard apply` writes its key. |

Blocking is still available and still means something stronger: a filtered
browser runs, a blocked one does not. The **Unmanaged browsers** category still
names Floorp, LibreWolf, Waterfox and the rest, and a browser that is both shows
as `blocked` in `guard browsers`, because that is what the person in front of it
sees.

### What the category covers, and what it cannot

It names browsers that install under **their own executable name** — Opera and
Opera GX, Vivaldi, Floorp, LibreWolf, Waterfox, Pale Moon, Basilisk, the
Avast/AVG/CCleaner browsers, Naver Whale, Maxthon, UC Browser, Slimjet, and
Internet Explorer. Most entries also block the vendor's download page, since
blocking the program alone leaves installing it again open.

What it cannot name, plainly:

| Not covered | Why |
|---|---|
| A raw Chromium build, ungoogled-chromium, Cent Browser | They ship as `chrome.exe`. Blocking that name takes the real Chrome — and its locked extensions — with it. |
| **Tor Browser**'s own window | It ships as `firefox.exe`, same problem. Covered instead by `tor.exe`, the daemon: the window may open, but no page loads. |
| **Yandex** | Ships `browser.exe`, too common a name to block by name alone. `guard browsers` still *finds* it, so block it by the path shown. |
| A per-user install under **another** account | The `HKCU` half of the scan reads the calling user's hive. Run `guard browsers` from each account. |
| A portable copy that registers nothing | Nothing registered it as a browser, so nothing lists it. It is still blocked if its executable — or the name compiled into it — is in the category. |
| A **repacked** binary with its version resource stripped | Neither name matches any more. See [Renaming](#renaming-the-one-bypass-nothing-corrected) for where that leaves things. |

### Renaming: the one bypass nothing corrected

Every rule kind here is keyed on a name or a path, so renaming `opera.exe` to
`chess.exe` used to walk out of all of them — the sweep compares image names, and
the launch block is an IFEO key named after the file. It needs no privilege beyond
writing to a directory you already own.

That made it a different class of problem from everything else in this document.
A deleted policy key is rewritten within milliseconds, an edited config loses to
the trusted copy, a stopped service is restarted by the watchdog. **A rename is
not tampering with the guard at all**, so nothing was correcting it: it is done
once and it holds.

Two things close most of it.

**Rules match the name built into the program.** Every executable carries a
version resource, and `OriginalFilename` in it is what the author called the
file — compiled in, not on the filesystem, so renaming the file does not change
it. A rule naming a bare executable now matches either name, so `opera.exe`
still catches Opera after a rename. This applies to **every existing rule and
every category** with no config change: it is the same rule, matched on one more
name.

It is only ever *consulted*. Software with no version resource, or a file that
cannot be read, is matched on its file name exactly as before — a rule that
stopped working because a resource was missing would be a worse bug than the one
this closes. A **full-path** rule is deliberately not widened: renaming makes it
a different path, and the bare-name form is how you say "wherever it is".

Windows' own binaries are the awkward case, and the reason this is tested against
real files: their strings live in a side-by-side MUI resource, so `notepad.exe`
reports `NOTEPAD.EXE.MUI`. That suffix is stripped, without which the
protected-image list would have recognised none of them.

**The protected list checks all three names.** A rule that can now fire on a
version resource has to be refusable on one, or a copy of `lsass.exe` renamed to
`harmless.exe` would be a way to make the guard shoot the machine.

**`guard browsers` flags the fingerprint.** Renaming a browser's executable does
not touch the registration that pointed at it, so the machine is left claiming a
browser at a path with no file. A browser **on the block list** whose executable
has gone is reported as `gone`, and `guard verify` warns about it. It is gated on
being blocked deliberately: a browser nobody blocked whose file went missing was
almost certainly uninstalled, and warning about that would put a permanent
warning on any machine that ever removed a browser — which teaches the reader to
ignore this warning on the day it matters.

**What this is worth, plainly.** It turns a right-click-rename into a job needing
a resource editor. A repacked or resource-stripped binary still wins, as does a
browser compiled from source. That is the same bar the watchdog sets — casual and
impulsive, not determined — and the honest ceiling in
[`docs/pc-version.md`](docs/pc-version.md) has not moved. The structural answer
is to restrict *where* executables may run from rather than *what they are
called*, which is a much larger feature and is not built.

**What it costs.** Reading a version resource needs the image path, so a
bare-name rule now asks the sweep for paths, which it did not before. Measured on
a 325-process Windows 11 desktop, per sweep: **8.6ms** for names alone, **12ms**
once paths are resolved, **19ms** with compiled-in names warm (31ms on the first
pass, while the cache fills). So roughly 2% of one core, once a second, for the
sweep as a whole.

The resource read itself is cached per image and keyed on the file's size and
modification time, which are **confirmed on every lookup**. That stat is the bulk
of the 12ms→19ms step and it is paid deliberately: an earlier version of this
trusted a cached entry for a minute before re-checking, and that was a repeatable
bypass — put a harmless executable at a path, let it be cached, replace it with
the blocked program renamed, and for the next minute the guard believed the
harmless name. Only the resource read is ever cached, never the identity of the
file at a path. A test writes two different programs to the same path in
succession to hold that line.

`ValidateCatalog` **refuses** any category naming a browser the guard manages, and
a test holds it to that. This is the one guardrail here that is not advisory:
"block Tor Browser" is a change somebody will one day try to make by adding
`firefox.exe` to this category, and that would close the machine's real Firefox
and take every locked extension with it. A user may still block `chrome.exe` by
hand — that is a coherent thing to want — but nobody should be able to do it by
accepting a category, least of all under a block they then lock.

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
- **The clock, in both directions.** Going back does not un-spend time: the ledger
  remembers the latest day it has recorded and refuses to serve an earlier one.
  Going *forward* no longer rolls into a fresh day either — the service anchors the
  wall clock to a monotonic reading when it starts, and counts limits against the
  day real elapsed time says it is, not the day the clock claims. Winding the clock
  past the reset hour was the cheapest bypass in the program: no password, no
  admin, one trip to the date settings. It is recorded as `clock.changed`.
- **A long gap between observations** is capped, so a machine that slept for eight
  hours is not charged for them.

An ordinary correction is still believed. A clock that steps by up to 90 seconds —
NTP after a suspend, a virtual machine resuming — is accepted and re-anchored to,
because a guard strict enough to freeze the day boundary on a machine doing nothing
wrong is one that gets turned off. Putting a moved clock *back* is believed
immediately too, so correcting the mistake works rather than needing a restart.

Three things it still cannot do:

- An administrator can **delete** the file, and a missing ledger is
  indistinguishable from a fresh install. Same class of hole as stopping the
  service, answered the same way: the watchdog, and having to do it again every
  day.
- **The anchor is taken when the service starts.** Stop it — or reboot — change the
  clock, and start again, and it anchors to whatever the clock now says. That is a
  materially higher bar than changing the date while the machine runs, and it is
  as far as user space reaches: closing it properly needs a time source the person
  being limited cannot rewrite, which this program does not have.
- **Nudges under the tolerance accumulate.** Ninety seconds at a time, repeatedly,
  eventually reaches a boundary. That is dozens of deliberate trips to the date
  settings rather than one, which is the same bar
  [the typing challenge](#the-typing-challenge) sets, arrived at from the other
  side.

One thing worth knowing about the display rather than the enforcement: `guard
limits` and the status window read the day from the machine's clock, because they
are separate processes with no anchor of their own. While a clock is wound
forward they can therefore show a budget the service is not honouring. The service
is the only thing that enforces, and it is counting the real day — but the two can
disagree on screen until the clock is put back.

## Time used

A limit answers *how much is left*. This answers *where the time actually went* —
per application, today and over the past weeks.

```powershell
guard usage         # the last 7 days
guard usage 30      # reach further back (the record keeps 60 days)
```

```
  application                  today      7 days
  Steam                        1h30m      4h20m
  Discord                      25m        40m
  Solitaire                    4m         4m

  time with any of them open   1h42m      4h40m

  2026-08-26  1h42m      ##################
  2026-08-25  2h33m      ############################
  2026-08-24  5m         #
  2026-08-23  0m
```

Needs **no admin and no password**, like `guard limits` and `guard activity`, and
for the same reason: the record is about the person using the machine, and one
they cannot read is one they can only argue with. The status window shows the same
thing as a **Time used** section, capped at the busiest eight rules.

**It cost almost nothing to add.** The sweep already walks the process list once a
second and matches every rule against it, and the ledger has kept sixty days of
counters since limits shipped — the comment on `keepDays` has said all along that
*"how much did I actually use this week" is the obvious next question*. What was
missing was only that the answer was filed per **limited block** and then never
read. There is **no config change**: nothing new in `extension-ids.json`, nothing
to turn on.

### Two totals, because they answer different questions

An hour with Steam and Discord both open is **two hours of rules** and **one hour
of the afternoon**. Both are printed rather than choosing one: the per-rule rows
answer *what cost me the most*, and `time with any of them open` answers *how much
of the day went*. The second is counted once per second however many rules matched,
so it never exceeds the day.

### What is counted, and what is not

- **Every enabled application rule**, not only the ones a limit covers. Otherwise
  a machine that blocks Steam outright — the common case — would have no record at
  all, which is exactly where "how much is this actually being used" is worth
  knowing.
- **Out-of-window time counts.** A limit refuses to charge time outside its window
  because it is a budget for those hours; this is a record of use, and an hour
  spent at an hour the block does not cover is still an hour spent. So the two
  numbers legitimately differ, and `guard limits` remains the one that says what is
  left.
- **It keeps counting while protection is paused.** That is the same choice the
  activity log makes — it records what happens *during* a pause — and it fails the
  right way: a record that went quiet during exactly the window usage runs highest
  would be worse than no record. The pause is in the log next to it, so an unusual
  evening is explainable rather than mysterious. A **budget** is still never
  charged during a pause.
- **Running, not focused**, and per rule rather than per process — the same two
  properties limits have, for the same reasons (see [Time limits](#time-limits)).
  Two copies of the same game are not two hours of it.
- **A rule you later unblock keeps its history**, marked `*` in the CLI and
  `unblocked` in the window. Dropping those rows would make last week's total
  change when a rule was deleted.
- **Applications only.** A blocked *site* is enforced by handing the browser a
  policy and trusting it; nothing comes back, so there is no browsing time to
  report. That is the same wall that stops a limit covering a domain, and closing
  it needs the browser to talk back — see the extension bridge in the roadmap.

### What it deliberately does not do

It does not watch the whole machine. Cold Turkey's statistics screen finds
distractions you had not thought to name, because it records every process; this
records the rules the config already names. That is a real capability difference
and it is chosen rather than overlooked — a full history of every program somebody
ran is a different product from a guard whose record is readable by the person it
is about, and [PRIVACY.md](PRIVACY.md) is the promise being kept.

### What it costs

Measuring used to happen only when a limit was configured. It now happens whenever
any application rule is, because the record comes from the same sample — so a
machine with rules and no limits pays for a second walk of the process list per
second, which it did not before. The sweep's own walk is the reference for what
that is: **8.6ms** for names alone and **19ms** with compiled-in names warm, on a
325-process desktop. A machine with **no** application rules — every install that
only locks extensions and blocks sites — pays nothing at all, and a test holds
that.

### Where it lives

The same ledger as the limits, `C:\ProgramData\ExtensionGuard\usage.json`
(`/var/lib/extension-guard` on Linux), under a separate `apps` key so the counters
a limit reads keep meaning exactly one thing. Retention went from 14 days to
**60** now that something reads the older days.

A damaged record here does **not** fail closed. A limit treats an unreadable
ledger as every budget spent, because the alternative makes "corrupt the file" mean
"reset my limits"; there is no budget in this half, so there is nothing to fail
closed *to*, and refusing to show today because last Tuesday is corrupt would help
nobody. Both the CLI and the window say the history is missing rather than showing
zeroes as if they were measurements.

## The typing challenge

The password answers whether you are *allowed* to weaken protection. It does not
answer whether you still *mean* to — and for a tool somebody installs to bind
their own future self, that is the question that matters. A password you chose
yourself is one keystroke away at the exact moment you least want it to be.

So there is a second gate, off by default, that costs minutes instead of
seconds: a string of random characters, printed on screen, that has to be typed
out by hand.

```sh
guard friction                    # is it on, and how long
guard friction on                 # admin; no password - it only adds protection
guard -chars 512 friction on      # longer
guard friction off                # goes through the challenge itself
```

```
Pausing protection is gated behind a typing challenge.
Type these 256 characters exactly. Spaces and line breaks are ignored,
and it has to be typed - pasting is refused.

  7xfw52ks r9pymzqf zddjxjdy vh69s83f euxz9dva 875bx5r9
  kxrvsfp6 gn9sv89k vrjxpaeu x5mzg5uv zpxaq6sj 4783j8kb
  yp99spbk csqh8ard gfcpu3tv jdb8tj45 uyakwk7c at9yfjf2
  pe8s37ct dwvzdct9 kbma2ngt qdv8hyrb xpamdnpn 6mcgkxaq
  5b6qt5jc 9gxxedef hb5dqmfj ke774g6f e2payxdx guk3yq8n
  e5x4qc6m rs3gkzmw
```

Nothing about the challenge is secret — it is printed in full, and the whole cost
is the typing. At the two to three characters a second that careful copying of
random text actually runs at, 256 characters is a few minutes of deliberate work.

**This is friction, not a lock, and the distinction is the design.** Anybody
willing to spend the minutes gets through, on purpose: the person holding the
password is the person the tool belongs to, and a gate they could never pass
would just get the program uninstalled instead. What it buys is that weakening
protection stops being something that can happen faster than the decision to do
it.

### Where it applies

Everywhere the password already applies. All twelve of those paths funnel through
one function, so there is one place this was added and no list to keep in step:
unblocking a site or an application, turning off a hardened setting, lowering a
SafeSearch level, taking a site off the allowlist, removing or scheduling a
block, committing an edited config, turning off an extension lock, pausing
protection, and uninstalling.

The password is asked for **first**, because it is the cheap one. Asking for
minutes of typing and then refusing the password would spend the expensive gate
on somebody who was never getting through, and a gate that punishes the wrong
person is the one the right person asks to have removed.

The two are independent settings. A machine may have the password, the challenge,
both, or neither — and a machine that installed the guard before this existed
reads as *challenge off*, which is the only safe default. A challenge nobody was
told about appearing in front of an uninstall is a support call, not protection.

### The gate on the gate

Turning the challenge on, or making it longer, only strengthens protection, so it
costs **admin** and nothing more — the same trade as `block-domain`.

Turning it **off, or making it shorter, goes through the challenge itself**, at
the length currently in force. This is load-bearing rather than tidy: without it
the whole feature would be one `guard friction off` away from gone, which is
exactly the impulse it exists to outlast.

The length lives next to the password hash in `HKLM\SOFTWARE\ExtensionGuard`, not
in `extension-ids.json`. A number in the config file would be editable by anybody
who can open Notepad, and the one thing this gate must not be is adjustable by
the person it is there to slow down. The config is reconciled continuously and
would put it back — but "wrong for a second" is enough when the action being
gated takes a second.

### Pasting

A terminal cannot be stopped from pasting; the clipboard belongs to the terminal,
not to this program. So the guard watches the clock instead: characters that
arrive faster than fingers can move were not typed, and a sustained run of gaps
under 20ms fails the attempt and is written to the activity log. One fast pair, or
a key repeat, is not enough — `friction.PasteWatch` requires a run, so a fast
typist is never accused.

**The status window comes through the same path.** It normally runs the elevated
guard with no window at all, which is fine until the guard needs to ask
something; with a challenge configured it opens a real console instead and the
guard asks there. So the timing test is the only paste defence in either place.

Blocking the clipboard outright would be stronger, and would mean the window
collecting the answer itself — which needs somewhere admin-only to keep a pending
challenge, so that the process verifying an answer is not the process that was
told what to accept. That is not built. What is claimed here is that **a pasted
answer is refused**, not that pasting is impossible.

### What it does not cover

- **Uninstalling from Add or Remove Programs.** The installer runs
  `guard uninstall-service` with a hidden window, so there is no console to type
  in and the guard refuses rather than waving the gate through. The message says
  to run the same command from an elevated terminal. Closing this properly means
  a challenge page in the Inno Setup script, which is not built.
- **A determined person with the password and a few minutes.** By design; see
  above. If you want an unlock that cannot simply be waited out, the shape for
  that is a delay rather than a longer string, and the held-pause machinery
  already does most of it.
- **Anything the password did not already gate.** This is a second gate on the
  same doors, not a new door.

### Details worth knowing

The alphabet is lowercase letters and digits with every ambiguous glyph removed —
no `i`, `l` or `1`, no `o` or `0` — and case is not mixed. That is a usability
decision doing security work: a glyph the reader cannot tell from another one
produces failures that have nothing to do with intent, and teaches them the gate
is broken rather than that it is serious. Length is where the cost comes from, and
length is free.

Whitespace is ignored on both sides, so the groups and rows the challenge is
displayed in are not part of the answer. A failed attempt says which character it
first diverged at, and leaves the same challenge standing — nothing is given away,
since the answer is on the screen, and discovering at character 256 that something
broke at character 12 with no idea which is what makes somebody conclude the
feature is broken.

Failed attempts are recorded (`challenge.failed`), and a pasted one is recorded as
pasted. Like a wrong password, it is the one kind of attempt that otherwise leaves
no trace at all.

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
| `allowlist.on` `.off` | every site was blocked except the allowlist, or that was lifted |
| `site.allowed` `.unallowed` | a site was let through the allowlist mode, or closed again |
| `app.blocked` `.unblocked` | an application rule was added or lifted |
| `extension.enabled` `.disabled` | an extension started or stopped being locked |
| `hardening.enabled` `.disabled` | a browser setting started or stopped being pinned |
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

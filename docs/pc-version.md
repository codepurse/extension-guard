# Extension Guard — how uninstall protection works

## The core idea

A browser extension **cannot** prevent its own uninstall — both Chrome and
Firefox guarantee the user can always remove extensions, and any extension that
tries to block this gets pulled from the stores. So self-protection has to live
*above* the browser.

Extension Guard is a small native app installed with admin rights. It uses the
browsers' **enterprise "force-install" policy** to lock every configured
extension:

- **Chromium** (Chrome, Edge, Brave): `ExtensionInstallForcelist` under
  `HKLM\SOFTWARE\Policies\<vendor>\<browser>`.
- **Firefox family** (Firefox, Zen): `ExtensionSettings` with
  `installation_mode = force_installed` and `private_browsing = 1` under
  `HKLM\SOFTWARE\Policies\Mozilla\<application name>` — that is
  `...\Mozilla\Firefox` and `...\Mozilla\Zen`. A fork reads the same policies
  from a key named after itself, and installs the same add-on from
  addons.mozilla.org, so it needs no target of its own in the config. Forks the
  guard has never heard of are covered by reading the name out of the
  `application.ini` in their install directory rather than from a list in the
  binary — see `internal/policy/gecko.go`.

A force-installed extension shows **no Remove or Disable button** in the browser.

`private_browsing` is the Firefox family's alone, and it is what makes the lock
cover private windows as well as ordinary ones — Mozilla added it in Firefox 136
and ESR 128.8, and older builds ignore the member rather than rejecting the entry.
Chromium has no equivalent: an extension cannot be force-installed into Incognito
there at all, which is what the `private-browsing` and `private-extensions`
settings in the README exist to answer.

## Why a registry key alone isn't enough

Anyone with admin can delete that key in seconds. The protection is the
**running guard** that owns the key:

1. **Policy writer** — writes the keys. *(milestone 1, done)*
2. **Tamper watcher** — re-applies them instantly if changed/deleted.
3. **Windows service (LocalSystem)** — so a standard user can't stop it.
4. **Watchdog** — restarts the service if it's killed.
5. **Password gate** — uninstall requires a password held by the parent /
   accountability partner, not the person being blocked.

Registry = the lock. The guard = what stops someone picking the lock.

## Consent & legitimacy

This must be installed by the device owner or with clear consent (a parent on a
child's device, or someone binding themselves). The setup screen requires an
explicit consent checkbox. Software that prevents its own removal *without*
consent is what antivirus flags as stalkerware — transparency is what keeps this
a legitimate accountability tool.

## Distribution prerequisites

- Stable Chrome/Edge store IDs (publish each extension).
- A Mozilla-signed Firefox `.xpi` hosted at a reachable URL.
- A **code-signing certificate** for the guard `.exe` (free for open source via
  the [SignPath Foundation](https://about.signpath.io/product/open-source));
  an unsigned tamper-resistant service will be quarantined by antivirus.

## Per-browser publishing requirements

Force-install only works for an extension hosted in **that browser's own store**,
so each browser is published and configured separately, per extension, in
`extension-ids.json`.

| Browser | Where to publish | Update URL | Cost | Notes |
|---------|------------------|-----------|------|-------|
| Chrome | Chrome Web Store | `clients2.google.com/service/update2/crx` | $5 once | |
| Brave | (uses Chrome Web Store) | same as Chrome | — | reuses the Chrome listing/ID |
| Edge | Microsoft Edge Add-ons | `edge.microsoft.com/extensionwebstorebase/v1/crx` | free | **separate ID** from Chrome |
| Firefox | AMO (addons.mozilla.org) | the signed `.xpi` URL | free | must be Mozilla-signed |

### Edge gotcha — unmanaged devices
On a device that **isn't enrolled in org management (MDM)**, Edge will only
force-install extensions hosted in the **Microsoft Edge Add-ons** store. Pointing
Edge's policy at a Chrome Web Store URL is rejected (`[BLOCKED]` / "invalid
extension ID" in `edge://policy`). So Edge support **requires publishing to the
Edge Add-ons store** and using the `edge.microsoft.com` update URL. Chrome and
Brave have no equivalent restriction because the Chrome Web Store is their native
store. (On managed/enterprise devices Edge lifts this — that's how corporate IT
pushes Chrome extensions to Edge.)

### Firefox specifics
- The add-on must be **signed by Mozilla** (free via AMO — listed, or unlisted
  self-distribution which gives you a signed `.xpi` to host).
- `install_url` is only used for the **first install**; AMO-listed add-ons then
  auto-update through Firefox's normal channel.
- Use the version-independent URL so the config never needs editing on a version
  bump: `https://addons.mozilla.org/firefox/downloads/latest/<slug>/latest.xpi`.

### Version upgrades
All the update URLs above are "latest" endpoints, so existing installs
auto-update and new installs get the current version — the guard config never
changes on a version bump (only if an extension's **ID** changes).

## Blocking applications — what enforces it

Locking an extension is enforced *by the browser*: the guard writes a policy and
the browser honours it. There is no equivalent for an application. Nothing else
on the machine is going to refuse to start a program on our behalf, so the guard
has to do it itself, and the two ways it can are both above the kernel:

1. **Image File Execution Options** — the loader's "run this under a debugger"
   hook. `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution
   Options\<image>` with `Debugger` set to `"…\guard.exe" blocked` makes Windows
   start the guard *instead* of the program; it shows a message and exits.
   Keyed on the image's file name, with an optional `UseFilter` + `FilterFullPath`
   subkey to restrict it to one path. Not consulted for Store apps, which are
   activated through a broker.
2. **A process sweep** — enumerate processes (and, for window-title rules, the
   visible top-level windows), match against the rules, terminate what matches.
   Covers every rule kind, writes nothing, but acts after the process exists.

The guard runs both: the launch block so a blocked app never appears, the sweep
so anything the launch block cannot express - a folder, a Store app, a window
title - is still closed, and so a deleted launch block is not a bypass.

### What was ruled out, and why

| Option | Why not |
|---|---|
| **AppLocker** | Enterprise/Education only. The target user is on Home or Pro. |
| **Software Restriction Policies** | Absent from Home editions, and deprecated. |
| **A filesystem filter driver** | The only *real* block, and it needs an EV certificate plus WHQL signing - a different order of cost and process from an Authenticode certificate. |
| **`DisallowRun` (Explorer policy)** | Only blocks launches through Explorer. Trivially bypassed. |

So the honest ceiling is the same one this document describes for the registry
keys: a local administrator can stop the service, and while it is stopped nothing
is swept. What makes it hold in practice is the running guard - SYSTEM service,
watchdog, password gate - continuously correcting the machine, not the mechanism
being unbreakable.

### Why this one waits on the certificate

An **unsigned** LocalSystem service that terminates processes and writes IFEO
`Debugger` keys is a precise description of several malware families. Both
behaviours are what antivirus heuristics look for, and an unsigned binary has
nothing to weigh against them. The browser-policy features could ship before the
code-signing certificate because they only write policy keys; this one should not.

### The guardrail

A refuse-to-kill list for critical system processes is not optional. Blocking
`explorer.exe` takes the desktop away; `lsass.exe` or `csrss.exe` forces a
reboot; and a rule naming the guard's own binaries would let a block disarm the
guard from the inside. The list lives in `internal/policy/apps.go` and is checked
in two places - when a rule is added, and again in the sweep - so a rule that
reached the config by some other route still cannot fire.

### Session 0 and window titles

A Windows service runs in **session 0**, on its own window station. `EnumWindows`
there enumerates the service desktop - none of the user's windows - so a
window-title rule evaluated from the service matches nothing and enforces
nothing, without any error to notice.

The fix is a session helper: when a title rule exists, the service starts
`guard agent` in the console session with `WTSQueryUserToken` +
`CreateProcessAsUser`, and `STARTUPINFO.lpDesktop` set to `winsta0\default` (a
process created from session 0 with no desktop named lands back on the service
window station, which is the same blindness). The helper sweeps *only* title
rules; everything else is matched on the process list, which is
session-independent, and stays with the service - whose SYSTEM rights can close
processes the user cannot. A `Local\` mutex keeps it to one per session, and it
exits when the service stops, when protection is paused, or when the last title
rule goes away.

### Where guard.exe lives is load-bearing for the launch block

The `Debugger` value points at `guard.exe` in the directory the writing binary
ran from. Whoever launches a blocked image then executes that file **with their
own token** - which is the ordinary IFEO escalation shape. Writing the key needs
Administrator, and the same `guard.exe` is the service binary, so a directory a
standard user can write already means total compromise either way. But it does
mean the launch block must only ever be written from an install directory
standard users cannot write to: `%ProgramFiles%`, which is where the installer
puts it. A guard run out of a build tree (as during development) points the key
into that tree.

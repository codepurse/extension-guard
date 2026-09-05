# Extension Guard

Force-installs browser extensions on **Windows** and stops them being removed.

An extension cannot prevent its own uninstall. The Remove button is right there,
and a filter somebody can switch off in two clicks is not a filter. Extension
Guard runs as a privileged service *above* the browser, where enterprise-policy
rights let it force-install an extension into every profile and grey out both
Remove and Disable.

It does one thing. That is the point.

| | |
|---|---|
| **Extensions** | force-installed by enterprise policy, un-removable from the browser UI |
| **Private windows** | turned off, because a force-installed extension does not run in one |
| **Other browsers** | the ones it cannot reach are blocked, rather than left as a hole |

The last two rows are not extra features. They are the two ways a locked
extension stops being locked, and closing them is what makes the first row true
rather than nearly true.

## The two holes

**Private windows.** Chrome's own documentation is explicit: extensions cannot be
force-installed into Incognito, and a guest profile carries no extensions at all.
So `Ctrl+Shift+N` is a bypass of every locked extension that needs no download, no
administrator and no rename. Turning private and guest windows off closes it.

The Firefox family is the exception - Mozilla added `private_browsing` to
`ExtensionSettings` in Firefox 136 and ESR 128.8, so the add-on is force-enabled
in private windows there outright, with nothing to switch on.

**Browsers the guard cannot reach.** A browser it writes no policy for carries
none of the locked extensions. Installing Opera is a way round every lock at once.
The guard finds those browsers and can block them from starting.

## Which browsers

Chrome, Edge, Brave, Firefox and Zen are managed directly. Firefox forks are
discovered by reading the name out of their own `application.ini` rather than from
a list compiled in here, so a fork released next year is covered by code written
today - and a browser that does not say what it is called is reported as
unreachable rather than guessed at.

## Status

| # | Milestone | State |
|---|-----------|-------|
| 1 | Force-install **policy writer** (apply / verify / remove) | done |
| 2 | Run as a **Windows service** + tamper watcher (re-apply on delete) | done |
| 3 | **Watchdog** (survive being killed) | done |
| 4 | **Password-gated** uninstall, and an installer | done (unsigned until the certificate lands) |
| 5 | **Status window** | done |
| 6 | **Held pause** (protection off as a state, with a deadline it resumes at) | done |
| 7 | **In-app updater** (GitHub Releases) | done (silent apply gated on signing) |
| 8 | **Activity log** (append-only local record) | done |
| 9 | **Multi-extension** config | done |
| 10 | **Private-window hardening** | done |
| 11 | **Unreachable-browser blocking** | done |
| 12 | **Linux** port | partial - the policy writer builds, the browser block does not |

## Using it

The status window is the whole interface: a dial saying whether the lock is
holding, the extensions it holds, and the two switches. Everything below is the
same thing from a terminal.

```
guard verify              what is enforced, per browser
guard browsers            every browser here, and what the guard can do about it
guard hardening           the pinned settings, and whether private browsing is open
guard block-browsers      block the browsers the guard cannot reach
guard harden private-browsing
```

Turning something on needs administrator rights and nothing else - it only adds
protection. Turning something off needs the password, because that is the
direction somebody would take to get round it. `guard` on its own lists the rest.

## What it is not

It is not a content filter, a website blocker, a screen-time tool or a network
filter. It force-installs extensions and keeps them installed; what those
extensions do is theirs to decide. If you want the extension to block something,
that is a question for the extension.

It is also not a kernel-level block. Blocking a browser uses Image File Execution
Options, which is the loader's debugger hook - a real block, but one an
administrator can undo. What the guard has instead is a SYSTEM service, a watchdog
and a password gate, so getting round it has to survive continuous correction
rather than merely being done once.

## Building

```
powershell -ExecutionPolicy Bypass -File build.ps1
```

Produces `guard.exe`, the status window, an installer and `manifest.json` in
`release\`. A local build is unsigned.

## Licence

MIT. See LICENSE.

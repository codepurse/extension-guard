# Privacy Policy

_Last updated: 2026-08-21_

**Extension Guard collects no personal data.** There are no accounts, no
telemetry, no analytics, and no tracking of any kind. Nothing about you or your
browsing is sent anywhere.

## What stays on your device

Everything Extension Guard needs lives locally and never leaves your computer:

- **The uninstall password** is stored only as a bcrypt **hash** (in the Windows
  registry, or a root-owned state file on Linux). The password itself is never
  stored or transmitted.
- **The extension configuration** (`extension-ids.json`) — the list of
  extensions to lock — stays on disk next to the app.
- **The activity log** (`C:\ProgramData\ExtensionGuard\activity.jsonl`, or
  `/var/log/extension-guard/activity.jsonl` on Linux) records what the guard
  did and what was done to it: launches it refused, rules added and lifted,
  pauses, tamper it corrected, and wrong password attempts. It is a plain text
  file on your own machine, readable by every user of that machine — including
  the person being filtered, deliberately — and **it is never sent anywhere**.
  See the *Activity log* section of the README for exactly what is recorded.
- **The daily-usage ledger** (`C:\ProgramData\ExtensionGuard\usage.json`, or
  `/var/lib/extension-guard/usage.json` on Linux) exists only if you set a daily
  time limit. It records **how many seconds** each limited block was in use, per
  day, for the last 14 days - a number per block, nothing else: no window titles,
  no document names, no timestamps of individual sessions. It is readable by every
  user of the machine, deliberately, so the person a limit applies to can see how
  much of the day is left; only SYSTEM and administrators can change it. Like
  everything else here, **it is never sent anywhere**.

## The only network activity

The app makes exactly one kind of outbound request, and only for updates:

- It contacts **GitHub's public API** (`api.github.com`) to check whether a newer
  release exists, and — if you choose to update — downloads the new binaries from
  the GitHub release.
- These are ordinary public HTTPS requests. **No personal information, device
  identifier, or usage data is included.** GitHub may log the request IP as any
  web server would; that is governed by
  [GitHub's Privacy Statement](https://docs.github.com/site-policy/privacy-policies/github-general-privacy-statement).

You can turn this off entirely by setting `"autoUpdate": "off"` in
`extension-ids.json`, after which the app makes no network requests at all.

## No content filtering or data access

Extension Guard does **not** read, filter, or transmit your browsing history or
page content. The activity log records the guard's **own actions** — that a site
was added to the block list, that a blocked application was closed — never which
pages you visited or what was on them. A daily time limit counts how long an
application you chose to limit was **running**, which is the minimum the limit
needs in order to exist; it is not a record of what you did in that application,
and nothing is counted for programs no limit covers. It only writes the browsers' enterprise "force-install" policy so
the configured extensions cannot be removed. Any actual content filtering is done
by those extensions, under their own privacy policies.

## Contact

Questions? Open an issue at
<https://github.com/codepurse/extension-guard/issues>.

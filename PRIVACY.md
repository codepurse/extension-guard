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

## What it blocks, and what it never reads

Extension Guard installs extensions and keeps them installed. It does not watch.
It never reads, records, or transmits your browsing history or the contents of
any page — it has no mechanism to. Nothing here sits between your browser and the
web: what it writes is enterprise policy, which the browser then honours on its
own.

The activity log records the guard's **own actions** — that an extension was
locked or unlocked, that a browser launch was refused, that protection was
paused — never which pages you visited or what was on them.

Extensions that Extension Guard locks in place do their own filtering, under
their own privacy policies. What they see, and what they do with it, is described
by whoever publishes them and is not covered by this notice.

## Contact

Questions? Open an issue at
<https://github.com/codepurse/extension-guard/issues>.

# Privacy Policy

_Last updated: 2026-07-06_

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
page content. It only writes the browsers' enterprise "force-install" policy so
the configured extensions cannot be removed. Any actual content filtering is done
by those extensions, under their own privacy policies.

## Contact

Questions? Open an issue at
<https://github.com/codepurse/extension-guard/issues>.

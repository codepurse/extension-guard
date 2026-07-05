# Security Policy

Extension Guard is a security tool: it plants and defends an enterprise
force-install policy so protected browser extensions cannot be removed from the
browser UI, and it gates its own uninstall behind a password. Because of that,
vulnerabilities here are especially sensitive — a bypass can silently defeat the
protection a parent or accountability partner is relying on.

We take security reports seriously and appreciate responsible disclosure.

## Supported versions

This project is under active development and ships from `main`. Security fixes
are applied to the latest release only. Please make sure you can reproduce an
issue against the current `main` before reporting.

| Version | Supported          |
| ------- | ------------------ |
| latest (`main`) | ✅         |
| older builds    | ❌         |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, report privately using either of these channels:

1. **GitHub Security Advisories** — preferred. Go to the repository's
   **Security → Report a vulnerability** tab to open a private advisory.
2. **Email** — **alfon@navixhealth.com**. Please put `SECURITY` in the subject
   line.

Include as much of the following as you can:

- A clear description of the issue and its impact.
- The affected platform (Windows / Linux) and OS + browser versions.
- Step-by-step reproduction, proof-of-concept, or the relevant output of
  `guard verify` / `guard detect`.
- Any suggested remediation, if you have one.

## What to expect

- **Acknowledgement** within **3 business days**.
- An initial assessment and severity triage within **7 business days**.
- Regular updates as we work on a fix, and credit in the release notes once the
  fix ships (unless you prefer to remain anonymous).

Please give us a reasonable window to release a fix before any public
disclosure. We will coordinate a disclosure timeline with you.

## Scope

Reports we especially want to hear about:

- Bypassing the uninstall password gate.
- Removing or disabling a protected extension without the password.
- Stopping or removing the guard service / watchdog without authorization
  (beyond the documented ceiling — see below).
- Privilege-escalation or code-execution flaws in the guard, watchdog, or
  status UI.
- Weaknesses in how the uninstall password is stored or verified.

### Known limitations (not vulnerabilities)

These are documented, accepted trade-offs — see `docs/pc-version.md` for the
full "honest ceiling." Reports about them are not treated as vulnerabilities:

- A **determined administrator / `root` user** can ultimately remove the
  protection (Safe Mode, killing both processes at once, wiping the registry or
  policy files, `sudo`). The guard defeats casual and impulsive removal, not a
  privileged operator who knows the internals.
- **snap / flatpak browsers** on Linux are sandboxed and ignore managed policy
  files, so the lock does not apply to them.
- The two-process respawn (service + watchdog) pattern is expected to be flagged
  by some antivirus engines; code signing is the mitigation, not a security bug.

Thank you for helping keep Extension Guard and its users safe.

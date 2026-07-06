# Code signing & antivirus false positives

Extension Guard is a tamper-resistant service: it runs as `LocalSystem`, writes
browser enterprise policy, and a watchdog restarts it if it's killed. That
"won't stay dead" behavior is the whole point — but at the heuristic/ML level it
is *indistinguishable* from persistence malware. So on an **unsigned** build you
should expect:

- **SmartScreen** "unknown publisher" on first download-and-run, and
- a **small number** of heuristic engines flagging it on VirusTotal (e.g. Bkav,
  Elastic) — generic/ML verdicts, not named-threat signatures.

The only thing that reliably clears this is a **code signature from a verified
publisher**, plus reputation over time. This doc is the plan.

## The plan

1. **Now (free, already done):** the binary carries real version-info metadata
   (`cmd/guard/versioninfo.json` → publisher, product, description), we publish a
   **SHA-256 manifest** with every release, and `autoUpdate` defaults to
   `notify` — never silently pushing unsigned binaries.
2. **In progress:** a **free open-source code-signing certificate** from the
   [SignPath Foundation](https://about.signpath.io/product/open-source).
3. **When approved:** flip on the signing steps in
   [`.github/workflows/release.yml`](../.github/workflows/release.yml) (below).

## Applying to the SignPath Foundation

1. Make sure the repo qualifies: public, an OSI-approved license (this repo is
   MIT), and a **CI-based build** SignPath can trace to source — that's exactly
   what `release.yml` provides.
2. Apply at <https://about.signpath.io/product/open-source>. You'll register a
   SignPath **organization**, create a **project** (`extension-guard`), an
   **artifact configuration**, and a **signing policy** (e.g. `release-signing`).
3. SignPath signs on *their* infrastructure — the private key never touches your
   machine or CI. Your workflow uploads the built artifacts; SignPath signs and
   returns them.

## Turning signing on in CI (after approval)

In the repo's **Settings → Secrets and variables → Actions**, add:

| Kind | Name | Value |
|------|------|-------|
| Variable | `SIGNPATH_ENABLED` | `true` |
| Variable | `SIGNPATH_ORG_ID` | your SignPath organization id |
| Variable | `SIGNPATH_PROJECT_SLUG` | e.g. `extension-guard` |
| Variable | `SIGNPATH_POLICY_SLUG` | e.g. `release-signing` |
| Secret | `SIGNPATH_API_TOKEN` | a SignPath CI user API token |

Then push a tag (`git tag v1.0.0 && git push origin v1.0.0`). The workflow runs:

```
build binaries -> SignPath sign -> build installer (bundles signed binaries)
              -> write manifest.json (hashes the signed bytes) -> publish release
```

The signing → installer → manifest order matters: the installer must bundle the
*signed* binaries, and `manifest.json` must hash the exact bytes that ship, or
the in-app updater's integrity check will fail. (build.ps1's stages —
`binaries` / `installer` / `manifest` — exist so CI can slot signing in between.)

> Verify the `signpath/github-action-submit-signing-request` **input names**
> against the version you pin — SignPath has renamed them across releases
> (e.g. `github-artifact-id`). Their onboarding gives an exact snippet.

To also sign `Extension-Guard-Setup.exe`, repeat the SignPath step against
`release\Extension-Guard-Setup.exe` after the installer stage and before the
manifest stage.

## Reputation note

Even correctly signed, a **standard (OV) certificate builds SmartScreen
reputation over downloads/time** — early users may still see a warning until the
binary is seen enough. Only an **EV** certificate gets instant SmartScreen trust.
SignPath's Foundation cert is OV-class, so expect a short reputation ramp.

## Reporting false positives (interim, and for stragglers after signing)

If an engine flags a clean build, submit it — vendors whitelist:

- **Microsoft Defender:** <https://www.microsoft.com/wdsi/filesubmission> (submit
  as a suspected *false positive*; do this proactively before a release, too).
- **Bkav:** email `fpreport@bkav.com` (or the report form at <https://www.bkav.com>).
- **Elastic:** open an issue at
  <https://github.com/elastic/protections-artifacts/issues> with the file hash.
- Add a **comment on the VirusTotal report** linking this repo so the next person
  who scans it sees it's open-source with a known-benign explanation.

Provide the SHA-256 (from `manifest.json`), a link to this repo, and a one-line
explanation that the watchdog/respawn is a documented, consent-gated feature.

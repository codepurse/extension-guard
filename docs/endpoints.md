# Remote endpoints — why the guard does not name a repository

## The problem this solves

Every shipped binary carries its network endpoints compiled in. Before v1.1 those
endpoints named the GitHub repository directly:

| What | URL baked into every ≤1.0.1 binary |
|------|-----------------------------------|
| Update check | `api.github.com/repos/codepurse/extension-guard/releases/latest` |
| Announcement banner | `raw.githubusercontent.com/codepurse/extension-guard/main/announcement.json` |

An install already in the field cannot be repointed — there is no remote knob,
only a new binary. That makes the repository's *name* permanently load-bearing,
with two consequences:

1. **Renaming the repo kills the announcement banner.** `raw.githubusercontent.com`
   does not follow repository rename redirects the way the API does; it 404s.
   `announce.Fetch` fails soft, so the banner simply never appears again — no
   error, no log the user would see. The channel dies silently, and the only
   recovery is a manual reinstall.

2. **The old name becomes claimable.** GitHub keeps a rename redirect only while
   nothing occupies the old path. Whoever registers `codepurse/extension-guard`
   next owns the URL every existing install polls for updates — and because the
   SHA-256 manifest is served from the same release as the binaries, controlling
   the repo means controlling both the payload and its expected hash. That is
   arbitrary code delivered to a LocalSystem service. Today `AutoUpdate` defaults
   to `notify`, which blunts it; the plan to flip to `apply` after code signing
   would sharpen it again.

## The fix

`internal/endpoint` holds one `Base` URL. Both callers prefer it and fall back to
their original GitHub URLs when it is unset or unreachable:

- `updater.CheckLatest` → `{Base}/latest.json`, else the GitHub release API.
- `announce.Fetch` → `{Base}/announcement.json`, else the raw GitHub URL.

The fallback is deliberate. It means this build ships and starts propagating
**before** a domain exists, behaving exactly as today until the day `Base` is
filled in — at which point every build carrying it switches over with no further
code change. It also means a temporary outage of the endpoint host degrades to
the old behaviour instead of leaving installs with no update path.

## Cutover

1. Register the domain and point it at static hosting.
2. Serve `latest.json` and `announcement.json` (see formats below).
3. Set `endpoint.Base` in [`internal/endpoint/endpoint.go`](../internal/endpoint/endpoint.go)
   and remove the TODO. One line.
4. Release. From here, new installs never depend on the repository name.
5. Wait for uptake. Older builds still reach GitHub, so keep publishing releases
   there and keep `announcement.json` at the repo root.
6. **Only once ≤1.0.1 installs have aged out** is the repository name free. Until
   then it stays `codepurse/extension-guard`.

## `latest.json`

Same shape as the `manifest.json` already attached to releases, plus an optional
`url` per file. A bare name (or no `url`) resolves against the manifest's own
URL, so the document is copyable between hosts verbatim.

```json
{
  "version": "1.2.0",
  "notes": "What changed in this release.",
  "files": [
    { "name": "guard.exe", "sha256": "…" },
    { "name": "extension-guard-status.exe", "sha256": "…" }
  ]
}
```

With binaries served from elsewhere (GitHub release assets, a CDN), give each an
absolute `url`:

```json
{ "name": "guard.exe", "sha256": "…", "url": "https://github.com/…/guard.exe" }
```

Hosting the manifest separately from the binaries is worth doing: it means the
hash and the payload no longer come from the same place, which is the weakness
called out in the `updater` package docs. It is still not a substitute for
Authenticode signing.

## `announcement.json`

Unchanged — the same document already at the repo root. Serve it at
`{Base}/announcement.json` and keep the copy on `main` for older builds.

## Do not change these

The rebrand can rename anything a user sees. These are load-bearing for installs
already in the field and stay frozen regardless of what the product is called:

| Identifier | Where | Breaks if changed |
|---|---|---|
| `AppId={{6B2C9E4A-…}}` | `installer/Extension Guard.iss` | Installs side-by-side instead of upgrading |
| `ServiceName = "ExtensionGuard"` | `internal/guardsvc/service.go` | Old watchdog resurrects the old service |
| `SOFTWARE\ExtensionGuard` | `internal/scm/scm_windows.go` | Loses the password hash and trusted config |
| `guard.exe`, `extension-guard-status.exe` | release assets | ≤1.0.1 updaters download these names verbatim |
| `extension-ids.json` | config filename | The installed service passes this path back via its SCM launch arguments |

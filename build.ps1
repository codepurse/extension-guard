#requires -version 5
<#
  Builds all Extension Guard release artifacts into release\:
    - guard.exe              (CLI + service + watchdog)
    - extension-guard-status.exe   (Wails status window)
    - Extension-Guard-Setup.exe (Inno Setup installer that bundles both)

  Signing is intentionally skipped (see docs/pc-version.md for the SignPath plan).
  Run from anywhere:  powershell -ExecutionPolicy Bypass -File build.ps1
#>
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$root    = $PSScriptRoot                       # repo root
$release = Join-Path $root "release"

# Single source of truth for the version. Stamped into both binaries via ldflags
# (internal/buildinfo.Version), into the installer via ISCC /DAppVersion, and into
# the release manifest.json the updater reads.
$version = (Get-Content (Join-Path $root "VERSION") -Raw).Trim()
$ldflags = "-s -w -X github.com/codepurse/extension-guard/internal/buildinfo.Version=$version"
Write-Host "== version $version ==" -ForegroundColor Cyan

function Find-Tool($name, $candidates) {
  $cmd = Get-Command $name -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  foreach ($c in $candidates) { if (Test-Path $c) { return $c } }
  throw "Could not find '$name' on PATH or at: $($candidates -join ', ')"
}

$go    = Find-Tool "go"    @("C:\Program Files\Go\bin\go.exe")
$wails = Find-Tool "wails" @("$env:USERPROFILE\go\bin\wails.exe")
$iscc  = Find-Tool "ISCC"  @("$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe", "C:\Program Files (x86)\Inno Setup 6\ISCC.exe")

# Wails shells out to 'go' and to node/npm, so both must be on PATH.
$goDir = Split-Path $go
if ($env:PATH -notlike "*$goDir*") { $env:PATH = "$goDir;$env:PATH" }
$nodeDir = "C:\Program Files\nodejs"
if ((Test-Path $nodeDir) -and ($env:PATH -notlike "*$nodeDir*")) { $env:PATH = "$nodeDir;$env:PATH" }

Write-Host "== go test ==" -ForegroundColor Cyan
& $go -C $root test ./...; if ($LASTEXITCODE -ne 0) { throw "tests failed" }

Write-Host "== go vet ==" -ForegroundColor Cyan
& $go -C $root vet ./...; if ($LASTEXITCODE -ne 0) { throw "vet failed" }

Write-Host "== build guard.exe ==" -ForegroundColor Cyan
& $go -C $root build -ldflags $ldflags -o guard.exe ./cmd/guard; if ($LASTEXITCODE -ne 0) { throw "guard build failed" }

Write-Host "== build status UI (wails) ==" -ForegroundColor Cyan
Push-Location (Join-Path $root "statusui")
try { & $wails build -ldflags $ldflags; if ($LASTEXITCODE -ne 0) { throw "wails build failed" } } finally { Pop-Location }

Write-Host "== build installer (ISCC) ==" -ForegroundColor Cyan
& $iscc "/DAppVersion=$version" (Join-Path $root "installer\Extension-Guard.iss"); if ($LASTEXITCODE -ne 0) { throw "installer build failed" }

Write-Host "== collect release artifacts ==" -ForegroundColor Cyan
if (Test-Path $release) { Remove-Item $release -Recurse -Force }
New-Item -ItemType Directory -Path $release | Out-Null
Copy-Item (Join-Path $root "guard.exe") $release
Copy-Item (Join-Path $root "statusui\build\bin\extension-guard-status.exe") $release
Copy-Item (Join-Path $root "installer\output\Extension-Guard-Setup.exe") $release
# Ship the config next to the binaries so they find it without walking the tree.
Copy-Item (Join-Path $root "extension-ids.json") $release

Write-Host "== write update manifest ==" -ForegroundColor Cyan
# manifest.json is the asset the in-app updater reads: it pins the version and the
# SHA-256 of each binary so a download can be integrity-checked before it is
# swapped in. Upload it alongside guard.exe + extension-guard-status.exe on the
# GitHub release tagged "v$version".
$guardHash  = (Get-FileHash (Join-Path $release "guard.exe") -Algorithm SHA256).Hash.ToLower()
$statusHash = (Get-FileHash (Join-Path $release "extension-guard-status.exe") -Algorithm SHA256).Hash.ToLower()
$manifest = [ordered]@{
  version = $version
  notes   = "Extension Guard $version"
  files   = @(
    [ordered]@{ name = "guard.exe";                   sha256 = $guardHash  },
    [ordered]@{ name = "extension-guard-status.exe";  sha256 = $statusHash }
  )
}
$manifest | ConvertTo-Json -Depth 4 | Out-File (Join-Path $release "manifest.json") -Encoding utf8

Write-Host "`nRelease artifacts in $release :" -ForegroundColor Green
Get-ChildItem $release | ForEach-Object { "  {0,-32} {1,8:N0} KB" -f $_.Name, ($_.Length / 1KB) }
Write-Host "`nTo publish an update: create a GitHub release tagged v$version and attach" -ForegroundColor Cyan
Write-Host "  guard.exe, extension-guard-status.exe, and manifest.json (Setup.exe optional)." -ForegroundColor Cyan
Write-Host "NOTE: these binaries are UNSIGNED - keep autoUpdate at 'notify' until they are" -ForegroundColor Yellow
Write-Host "      code-signed (see docs/pc-version.md). Manual 'update' still works." -ForegroundColor Yellow

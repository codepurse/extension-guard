#requires -version 5
<#
  Builds all Extension Guard release artifacts into release\:
    - guard.exe                    (CLI + service + watchdog)
    - extension-guard-status.exe   (Wails status window)
    - Extension-Guard-Setup.exe    (Inno Setup installer that bundles both)
    - manifest.json                (version + SHA-256, read by the in-app updater)

  Stages (so CI can code-sign between building and hashing/bundling):
    binaries   go build guard + wails build status (+ version-info resource)
    installer  ISCC installer + collect artifacts into release\
    manifest   write release\manifest.json from whatever is in release\
    all        (default) all three in order - a normal local unsigned build

  The SignPath release workflow runs: binaries -> sign -> installer -> sign ->
  manifest, so the installer bundles signed binaries and manifest.json hashes the
  signed bytes. See docs/signing.md.

  Run from anywhere:  powershell -ExecutionPolicy Bypass -File build.ps1 [stage]
#>
param([ValidateSet('all', 'binaries', 'installer', 'manifest')][string]$Stage = 'all')

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$root    = $PSScriptRoot                       # repo root
$release = Join-Path $root "release"

# Single source of truth for the version. Stamped into both binaries via ldflags
# (internal/buildinfo.Version), into the installer via ISCC /DAppVersion, and into
# the release manifest.json the updater reads.
$version = (Get-Content (Join-Path $root "VERSION") -Raw).Trim()
$ldflags = "-s -w -X github.com/codepurse/extension-guard/internal/buildinfo.Version=$version"
Write-Host "== version $version (stage: $Stage) ==" -ForegroundColor Cyan

$doBinaries  = $Stage -in @('all', 'binaries')
$doInstaller = $Stage -in @('all', 'installer')
$doManifest  = $Stage -in @('all', 'manifest')

function Find-Tool($name, $candidates) {
  $cmd = Get-Command $name -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  foreach ($c in $candidates) { if (Test-Path $c) { return $c } }
  throw "Could not find '$name' on PATH or at: $($candidates -join ', ')"
}

$go = Find-Tool "go" @("C:\Program Files\Go\bin\go.exe")
$goDir = Split-Path $go
if ($env:PATH -notlike "*$goDir*") { $env:PATH = "$goDir;$env:PATH" }

if ($doBinaries) {
  # Wails shells out to 'go' and to node/npm, so both must be on PATH.
  $wails = Find-Tool "wails" @("$env:USERPROFILE\go\bin\wails.exe")
  $nodeDir = "C:\Program Files\nodejs"
  if ((Test-Path $nodeDir) -and ($env:PATH -notlike "*$nodeDir*")) { $env:PATH = "$nodeDir;$env:PATH" }

  Write-Host "== go test ==" -ForegroundColor Cyan
  & $go -C $root test ./...; if ($LASTEXITCODE -ne 0) { throw "tests failed" }

  Write-Host "== go vet ==" -ForegroundColor Cyan
  & $go -C $root vet ./...; if ($LASTEXITCODE -ne 0) { throw "vet failed" }

  Write-Host "== version-info resource for guard.exe ==" -ForegroundColor Cyan
  # A real publisher name + description on the (currently unsigned) console binary
  # lowers antivirus heuristic false positives and fills the Properties -> Details
  # tab. goversioninfo compiles cmd/guard/versioninfo.json into a .syso that
  # `go build` links automatically. Version numbers are overridden from VERSION.
  $gviPath = (Get-Command goversioninfo -ErrorAction SilentlyContinue).Source
  if (-not $gviPath) { $gviPath = "$env:USERPROFILE\go\bin\goversioninfo.exe" }
  if (-not (Test-Path $gviPath)) {
    Write-Host "   installing goversioninfo..." -ForegroundColor DarkGray
    & $go install github.com/josephspurrier/goversioninfo/cmd/goversioninfo@latest
    if ($LASTEXITCODE -ne 0) { throw "goversioninfo install failed" }
    $gviPath = "$env:USERPROFILE\go\bin\goversioninfo.exe"
  }
  $vp = @($version.Split('.')); while ($vp.Count -lt 3) { $vp += '0' }
  # -manifest embeds an asInvoker manifest so read-only commands run without
  # elevation and Windows' UAC installer-detection heuristic stays off.
  & $gviPath `
    -o (Join-Path $root "cmd\guard\resource_windows.syso") `
    -ver-major $vp[0] -ver-minor $vp[1] -ver-patch $vp[2] -ver-build 0 `
    -product-version $version -file-version $version `
    -manifest (Join-Path $root "cmd\guard\guard.exe.manifest") `
    (Join-Path $root "cmd\guard\versioninfo.json")
  if ($LASTEXITCODE -ne 0) { throw "goversioninfo failed" }

  Write-Host "== build guard.exe ==" -ForegroundColor Cyan
  & $go -C $root build -ldflags $ldflags -o guard.exe ./cmd/guard; if ($LASTEXITCODE -ne 0) { throw "guard build failed" }

  Write-Host "== build status UI (wails) ==" -ForegroundColor Cyan
  Push-Location (Join-Path $root "statusui")
  try { & $wails build -ldflags $ldflags; if ($LASTEXITCODE -ne 0) { throw "wails build failed" } } finally { Pop-Location }
}

if ($doInstaller) {
  $iscc = Find-Tool "ISCC" @("$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe", "C:\Program Files (x86)\Inno Setup 6\ISCC.exe")

  Write-Host "== build installer (ISCC) ==" -ForegroundColor Cyan
  # Bundles guard.exe (repo root) + extension-guard-status.exe (statusui\build\bin).
  # In the signed CI flow those have already been signed by the time this runs.
  & $iscc "/DAppVersion=$version" (Join-Path $root "installer\Extension-Guard.iss"); if ($LASTEXITCODE -ne 0) { throw "installer build failed" }

  Write-Host "== collect release artifacts ==" -ForegroundColor Cyan
  if (Test-Path $release) { Remove-Item $release -Recurse -Force }
  New-Item -ItemType Directory -Path $release | Out-Null
  Copy-Item (Join-Path $root "guard.exe") $release
  Copy-Item (Join-Path $root "statusui\build\bin\extension-guard-status.exe") $release
  Copy-Item (Join-Path $root "installer\output\Extension-Guard-Setup.exe") $release
  # Ship the config next to the binaries so they find it without walking the tree.
  Copy-Item (Join-Path $root "extension-ids.json") $release
}

if ($doManifest) {
  Write-Host "== write update manifest ==" -ForegroundColor Cyan
  & (Join-Path $root "installer\write-manifest.ps1") -Release $release -Version $version
}

if ($doManifest -or $doInstaller) {
  Write-Host "`nRelease artifacts in $release :" -ForegroundColor Green
  Get-ChildItem $release | ForEach-Object { "  {0,-32} {1,8:N0} KB" -f $_.Name, ($_.Length / 1KB) }
}

Write-Host "`nTo publish: create a GitHub release tagged v$version and attach guard.exe," -ForegroundColor Cyan
Write-Host "  extension-guard-status.exe, and manifest.json (Setup.exe optional)." -ForegroundColor Cyan
Write-Host "NOTE: a local build is UNSIGNED - keep autoUpdate at 'notify' until signing is" -ForegroundColor Yellow
Write-Host "      in place (see docs/signing.md). The release workflow signs via SignPath." -ForegroundColor Yellow

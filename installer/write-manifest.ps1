#requires -version 5
<#
  Writes <release>\manifest.json - the asset the in-app updater downloads to learn
  the latest version and the SHA-256 of each binary, so a download can be
  integrity-checked before it is swapped in.

  Split out from build.ps1 so it can run AFTER code signing: the hashes must match
  the exact bytes that ship, and signing changes them. build.ps1 calls this at the
  end of a local build; the release workflow calls it after the SignPath step.

  Usage: write-manifest.ps1 -Release <dir> -Version <x.y.z>
#>
param(
  [Parameter(Mandatory)][string]$Release,
  [Parameter(Mandatory)][string]$Version
)
$ErrorActionPreference = "Stop"

function Sha($path) {
  if (-not (Test-Path $path)) { throw "manifest: missing $path" }
  (Get-FileHash $path -Algorithm SHA256).Hash.ToLower()
}

$manifest = [ordered]@{
  version = $Version
  notes   = "Extension Guard $Version"
  files   = @(
    [ordered]@{ name = "guard.exe";                  sha256 = (Sha (Join-Path $Release "guard.exe")) },
    [ordered]@{ name = "extension-guard-status.exe"; sha256 = (Sha (Join-Path $Release "extension-guard-status.exe")) }
  )
}
# Write UTF-8 *without* a BOM: Windows PowerShell's Out-File -Encoding utf8 emits a
# BOM, and Go's encoding/json rejects a BOM-prefixed document, which would break
# the updater's manifest parse.
$json = $manifest | ConvertTo-Json -Depth 4
[System.IO.File]::WriteAllText((Join-Path $Release "manifest.json"), $json, (New-Object System.Text.UTF8Encoding($false)))
Write-Host "wrote $(Join-Path $Release 'manifest.json') (v$Version)"

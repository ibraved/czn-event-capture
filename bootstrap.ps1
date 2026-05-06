#Requires -Version 5.1
<#
.SYNOPSIS
  Fetch the current czn-event-capture scripts into %LOCALAPPDATA%\CZNEventCapture
  and invoke run.ps1.

.DESCRIPTION
  Entry point for the one-line install/run pattern documented in README.md.
  Downloads the latest release of each script + the zstd dictionary from the
  public GitHub repo into the user's per-user install directory, then hands
  off to run.ps1. Forwards any additional arguments verbatim so the user can
  pass -Pair, -Region, -Locale, etc., on the one-liner.

  Invoked by end users via the README's download-then-run bootstrap flow.

.NOTES
  Does NOT self-elevate; run.ps1 handles that once launched.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

try {
  [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
  $OutputEncoding = [System.Text.Encoding]::UTF8
} catch {}

# Self-pinned at publish time. Defaults to 'main' in unreleased working trees;
# publish-release.ps1 rewrites this to the publish commit's SHA so the bootstrap
# is self-contained. Env var CZN_RELEASE_REF still wins if set, for testing.
$DefaultReleaseRef = '02c2c8efcc2767112981f22782c53a5dbc418a3a'
$ReleaseRef = if ($env:CZN_RELEASE_REF) { $env:CZN_RELEASE_REF } else { $DefaultReleaseRef }
if ($ReleaseRef -notmatch '^[A-Za-z0-9._/-]+$') {
  Write-Host "Invalid CZN_RELEASE_REF value." -ForegroundColor Red
  throw "Invalid CZN_RELEASE_REF value: $ReleaseRef"
}
$RawBase = "https://raw.githubusercontent.com/ibraved/czn-event-capture/$ReleaseRef"
$InstallDir = "$env:LOCALAPPDATA\CZNEventCapture"

$files = @(
  'run.ps1',
  'locale.ps1',
  'czn_event_capture.py',
  '_czn_capture_lib.py',
  'requirements.txt',
  'zstd_dictionary.bin'
)

# Optional integrity manifest. Keep this in sync whenever release artifacts
# change. The bootstrap script itself is still trust-on-first-use when fetched
# with an iex/iwr one-liner; using a tagged release URL is the stronger path.
$ExpectedSha256 = @{
  'run.ps1' = '693f815120d0d9c75b37bd1c70532c5f1018f66bc4ac005e83a38d6f46fb194f'
  'locale.ps1' = '72ae8df69821cb05bd1495ff4d9ec4c554b1ae652622940c0893ed31d390e73b'
  'czn_event_capture.py' = '98a46cab09f5955e40d2fa2ec2252f89b3f2973fb0399d72db83f1247ce242ed'
  '_czn_capture_lib.py' = '322d9ff831e88a56efeebf8013b6ab04bcaaf5753caa96b4535709d9c77aecdf'
  'requirements.txt' = '4d7e04b6adf41622bfc04c1c01c1a1a5541a60c77edd61871a6aff648b6f7dc1'
  'zstd_dictionary.bin' = '8dba3653f67d5b555533c54c17470455d291ef78a3d8b127cd332e0de40383d7'
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

# Migration cleanup: older installs shipped a separate submit.ps1 that read
# capture.json from disk and POSTed it. The addon now submits directly, so
# leaving submit.ps1 behind would just be a confusing dead file.
$staleSubmit = Join-Path $InstallDir 'submit.ps1'
if (Test-Path $staleSubmit) {
  try { Remove-Item -LiteralPath $staleSubmit -Force -ErrorAction Stop } catch {}
}

$DisplayInstallDir = if ($env:LOCALAPPDATA -and $InstallDir.StartsWith($env:LOCALAPPDATA, [System.StringComparison]::OrdinalIgnoreCase)) {
  '%LOCALAPPDATA%' + $InstallDir.Substring($env:LOCALAPPDATA.Length)
} else { $InstallDir }
Write-Host "Fetching czn-event-capture scripts to $DisplayInstallDir..." -ForegroundColor Cyan
# raw.githubusercontent.com is content-addressed when CZN_RELEASE_REF is a
# commit SHA, so no cache-busting is needed. The branch fallback (main) may
# cache for up to 5 minutes; rerun if a freshly-pushed fix isn't picked up.
foreach ($name in $files) {
  $url = "$RawBase/$name"
  $dst = Join-Path $InstallDir $name
  try {
    Invoke-WebRequest -Uri $url -OutFile $dst -UseBasicParsing
    if ($ExpectedSha256.ContainsKey($name)) {
      $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $dst).Hash.ToLowerInvariant()
      $expected = [string]$ExpectedSha256[$name]
      if ($actual -ne $expected.ToLowerInvariant()) {
        Remove-Item -LiteralPath $dst -Force -ErrorAction SilentlyContinue
        throw "SHA256 mismatch for $name. Expected $expected, got $actual"
      }
    }
    Write-Host "  $name" -ForegroundColor Gray
  } catch {
    # Use throw, not exit. When this script is run via `iex (iwr ...)`, `exit`
    # closes the host PowerShell window before the user can read the error.
    # `throw` propagates to the iex caller and leaves the session alive.
    Write-Host "Failed to download $name from $url" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    throw "czn-event-capture bootstrap failed on $name"
  }
}

# Forward any args passed to bootstrap.ps1 through to run.ps1. The iex/iwr
# one-liner pattern cannot pass named args directly, so as an escape hatch
# the user can set CZN_SERVER_BASE / CZN_LOCALE env vars before invoking and
# we fold them in here.
$runScript = Join-Path $InstallDir 'run.ps1'
$extraArgs = $MyInvocation.BoundParameters.GetEnumerator() | ForEach-Object { "-$($_.Key)", "$($_.Value)" }
$extraArgs += $MyInvocation.UnboundArguments
if ($env:CZN_SERVER_BASE -and ($extraArgs -notcontains '-ServerBase')) {
  $extraArgs += @('-ServerBase', $env:CZN_SERVER_BASE)
}
if ($env:CZN_ALLOW_CUSTOM_SERVER_BASE -eq '1' -and ($extraArgs -notcontains '-AllowCustomServerBase')) {
  $extraArgs += '-AllowCustomServerBase'
}
if ($env:CZN_LOCALE -and ($extraArgs -notcontains '-Locale')) {
  $extraArgs += @('-Locale', $env:CZN_LOCALE)
}
Write-Host ""
Write-Host "Launching run.ps1..." -ForegroundColor Cyan
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $runScript @extraArgs

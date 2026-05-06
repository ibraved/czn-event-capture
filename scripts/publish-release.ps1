#Requires -Version 5.1
<#
.SYNOPSIS
  Pin SHA256 hashes of distributable files into bootstrap.ps1, then pin
  the install URL in README.md to the resulting commit SHA.

.DESCRIPTION
  Idempotent. Run twice on the same files = no-op for step 1.

  Steps:
    1. Compute SHA256 of run.ps1, locale.ps1, czn_event_capture.py,
       requirements.txt, zstd_dictionary.bin.
    2. Edit `$ExpectedSha256` table in bootstrap.ps1 in place.
    3. Commit the bootstrap.ps1 change (if anything changed).
    4. Capture the commit SHA.
    5. Edit README.md install one-liner + pinned-commit text to use that SHA.
    6. Commit the README change.
    7. Print the cznmetadecks-side bump instructions.

  Does NOT push. The user reviews and pushes manually.

.PARAMETER Tag
  If set with -TagName, also create an annotated git tag on the README commit.

.NOTES
  Run from any working dir; the script resolves paths relative to itself.
#>
[CmdletBinding()]
param(
  [switch]$Tag,
  [string]$TagName
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

$files = @(
  'run.ps1',
  'locale.ps1',
  'czn_event_capture.py',
  '_czn_capture_lib.py',
  'requirements.txt',
  'zstd_dictionary.bin'
)

# Step 1: Compute SHA256 of distributable files AS GIT WILL SERVE THEM.
# Get-FileHash on the working tree hashes CRLF on Windows; git normalizes to
# LF on commit (when core.autocrlf=true with no .gitattributes), so GitHub raw
# serves a different byte stream than what the working-tree hash describes.
# Hash the index/HEAD blob bytes to match what end users will actually fetch.
# Requires that all changes be committed first.
& git diff --quiet HEAD --
if ($LASTEXITCODE -ne 0) {
  Write-Host "Working tree has uncommitted changes. Commit them before running publish-release." -ForegroundColor Red
  exit 1
}

function Get-GitBlobSha256 {
  param([string]$Path)
  # Read the committed blob bytes directly via `git cat-file blob`. We must
  # bypass PowerShell's text pipeline (which would re-encode and corrupt
  # binaries) by reading the process's raw stdout stream.
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = 'git'
  $psi.Arguments = "cat-file blob HEAD:`"$Path`""
  $psi.RedirectStandardOutput = $true
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true
  $proc = [System.Diagnostics.Process]::Start($psi)
  $ms = New-Object System.IO.MemoryStream
  $proc.StandardOutput.BaseStream.CopyTo($ms)
  $proc.WaitForExit()
  if ($proc.ExitCode -ne 0) {
    throw "git cat-file blob HEAD:$Path failed with exit $($proc.ExitCode)"
  }
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $hashBytes = $sha.ComputeHash($ms.ToArray())
  } finally {
    $sha.Dispose()
    $ms.Dispose()
  }
  return [System.BitConverter]::ToString($hashBytes).Replace('-','').ToLowerInvariant()
}

$hashes = @{}
foreach ($name in $files) {
  $hashes[$name] = Get-GitBlobSha256 -Path $name
}

# Step 2: Read bootstrap.ps1 and rewrite the $ExpectedSha256 table.
$bootstrapPath = Join-Path $repoRoot 'bootstrap.ps1'
$utf8NoBom = New-Object System.Text.UTF8Encoding $false
$bootstrap = [System.IO.File]::ReadAllText($bootstrapPath, $utf8NoBom)

# Build replacement string. Use literal quoting; values are 64-char hex.
$tableLines = @('$ExpectedSha256 = @{')
foreach ($name in $files) {
  $tableLines += "  '$name' = '$($hashes[$name])'"
}
$tableLines += '}'
$newTable = ($tableLines -join "`n")

$pattern = '(?ms)\$ExpectedSha256\s*=\s*@\{[^}]*\}'
if ($bootstrap -notmatch $pattern) {
  Write-Host "Could not find `$ExpectedSha256 table in bootstrap.ps1" -ForegroundColor Red
  exit 1
}
$bootstrapNew = [regex]::Replace($bootstrap, $pattern, $newTable)

if ($bootstrap -eq $bootstrapNew) {
  Write-Host "bootstrap.ps1 SHA table already up to date." -ForegroundColor Green
} else {
  [System.IO.File]::WriteAllText($bootstrapPath, $bootstrapNew, $utf8NoBom)
  & git add bootstrap.ps1
  & git commit -m "Release: pin downstream SHA256 hashes"
  Write-Host "Committed updated bootstrap.ps1." -ForegroundColor Cyan
}

# Step 3: Capture the manifest commit SHA. The bootstrap will be rewritten to
# self-pin its $DefaultReleaseRef to THIS SHA, so downstream files are fetched
# from a commit where the manifest definitionally matches them.
$manifestSha = (& git rev-parse HEAD).Trim()
$manifestShort = $manifestSha.Substring(0, 7)
Write-Host "Manifest commit: $manifestSha" -ForegroundColor Cyan

# Step 4: Rewrite $DefaultReleaseRef in bootstrap.ps1 to the manifest commit.
# Without this, the bootstrap defaults to fetching files from `main`, which
# drifts and breaks integrity for users on older release URLs.
$bootstrap = [System.IO.File]::ReadAllText($bootstrapPath, $utf8NoBom)
$refPattern = "(?m)^\`$DefaultReleaseRef\s*=\s*'[^']*'"
if ($bootstrap -notmatch $refPattern) {
  Write-Host "Could not find `$DefaultReleaseRef in bootstrap.ps1" -ForegroundColor Red
  exit 1
}
$bootstrapNew = [regex]::Replace($bootstrap, $refPattern, "`$DefaultReleaseRef = '$manifestSha'")
if ($bootstrap -eq $bootstrapNew) {
  Write-Host "bootstrap.ps1 `$DefaultReleaseRef already points at $manifestShort." -ForegroundColor Green
} else {
  [System.IO.File]::WriteAllText($bootstrapPath, $bootstrapNew, $utf8NoBom)
  & git add bootstrap.ps1
  & git commit -m "Release: self-pin bootstrap to $manifestShort"
  Write-Host "Committed bootstrap self-pin." -ForegroundColor Cyan
}

# Step 5: Capture the bootstrap commit SHA. This is what the README install URL
# (and cznmetadecks's CAPTURE_RELEASE_SHA) point at.
$bootstrapCommitSha = (& git rev-parse HEAD).Trim()
$bootstrapShort = $bootstrapCommitSha.Substring(0, 7)
Write-Host "Bootstrap commit: $bootstrapCommitSha" -ForegroundColor Cyan

# Step 6: Update README install line + pinned-commit text to point at the
# bootstrap commit (which holds the self-pinned bootstrap).
$readmePath = Join-Path $repoRoot 'README.md'
$readme = [System.IO.File]::ReadAllText($readmePath, $utf8NoBom)

$urlPattern = 'https://raw\.githubusercontent\.com/ibraved/czn-event-capture/[A-Za-z0-9._/-]+/bootstrap\.ps1'
$replacement = "https://raw.githubusercontent.com/ibraved/czn-event-capture/$bootstrapCommitSha/bootstrap.ps1"
$readmeNew = [regex]::Replace($readme, $urlPattern, $replacement)

$readmeNew = [regex]::Replace($readmeNew, 'Pinned to commit `[a-f0-9]{4,40}`', "Pinned to commit ``$bootstrapShort``")
$readmeNew = $readmeNew.Replace('Pinned to commit `<short-sha>`', "Pinned to commit ``$bootstrapShort``")
$readmeNew = $readmeNew.Replace('<full-sha>', $bootstrapCommitSha)
$readmeNew = $readmeNew.Replace('<short-sha>', $bootstrapShort)

if ($readme -eq $readmeNew) {
  Write-Host "README.md already references $bootstrapCommitSha." -ForegroundColor Green
} else {
  [System.IO.File]::WriteAllText($readmePath, $readmeNew, $utf8NoBom)
  & git add README.md
  & git commit -m "Release: pin install URL to $bootstrapShort"
  Write-Host "Committed updated README.md." -ForegroundColor Cyan
}

# Step 7: Optional tag (on the README commit).
if ($Tag) {
  if (-not $TagName) {
    Write-Host "Provide -TagName when using -Tag (e.g. -TagName v2.2.0)." -ForegroundColor Red
    exit 1
  }
  & git tag -a $TagName -m "Release $TagName"
  Write-Host "Tagged $TagName." -ForegroundColor Cyan
}

# Step 8: Final report.
Write-Host ""
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host "Bootstrap install commit: $bootstrapCommitSha" -ForegroundColor Yellow
Write-Host "(downstream files fetched from manifest commit $manifestSha)"  -ForegroundColor DarkYellow
Write-Host ""
Write-Host "On cznmetadecks: open src/lib/events/capture-release.ts and update" -ForegroundColor Yellow
Write-Host "  CAPTURE_RELEASE_SHA = `"$bootstrapCommitSha`";" -ForegroundColor Yellow
Write-Host ""
Write-Host "Then commit and deploy. Push czn-event-capture when ready:" -ForegroundColor Yellow
Write-Host "  git push origin <branch>" -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Yellow

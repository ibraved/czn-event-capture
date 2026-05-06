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
  'requirements.txt',
  'zstd_dictionary.bin'
)

# Step 1: Compute SHA256 of distributable files.
$hashes = @{}
foreach ($name in $files) {
  $path = Join-Path $repoRoot $name
  if (-not (Test-Path $path)) {
    Write-Host "Missing: $name" -ForegroundColor Red
    exit 1
  }
  $hashes[$name] = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant()
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

# Step 3: Capture HEAD SHA.
$headSha = (& git rev-parse HEAD).Trim()
$shortSha = $headSha.Substring(0, 7)
Write-Host "HEAD is $headSha" -ForegroundColor Cyan

# Step 4: Update README install line + pinned-commit text.
$readmePath = Join-Path $repoRoot 'README.md'
$readme = [System.IO.File]::ReadAllText($readmePath, $utf8NoBom)

# Replace any /<ref>/ in the bootstrap.ps1 install URL with the new SHA.
$urlPattern = 'https://raw\.githubusercontent\.com/ibraved/czn-event-capture/[A-Za-z0-9._/-]+/bootstrap\.ps1'
$replacement = "https://raw.githubusercontent.com/ibraved/czn-event-capture/$headSha/bootstrap.ps1"
$readmeNew = [regex]::Replace($readme, $urlPattern, $replacement)

# Replace pinned-to-commit text with the new short SHA. Handle both filled
# (`Pinned to commit \`<7-or-40-hex>\``) and placeholder (`<short-sha>`/`<full-sha>`) forms.
$readmeNew = [regex]::Replace($readmeNew, 'Pinned to commit `[a-f0-9]{4,40}`', "Pinned to commit ``$shortSha``")
$readmeNew = $readmeNew.Replace('Pinned to commit `<short-sha>`', "Pinned to commit ``$shortSha``")
$readmeNew = $readmeNew.Replace('<full-sha>', $headSha)
$readmeNew = $readmeNew.Replace('<short-sha>', $shortSha)

if ($readme -eq $readmeNew) {
  Write-Host "README.md already references $headSha." -ForegroundColor Green
} else {
  [System.IO.File]::WriteAllText($readmePath, $readmeNew, $utf8NoBom)
  & git add README.md
  & git commit -m "Release: pin install URL to $shortSha"
  Write-Host "Committed updated README.md." -ForegroundColor Cyan
}

# Step 5: Optional tag.
if ($Tag) {
  if (-not $TagName) {
    Write-Host "Provide -TagName when using -Tag (e.g. -TagName v2.2.0)." -ForegroundColor Red
    exit 1
  }
  & git tag -a $TagName -m "Release $TagName"
  Write-Host "Tagged $TagName." -ForegroundColor Cyan
}

# Step 6: Final report.
Write-Host ""
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host "Pinned to $headSha" -ForegroundColor Yellow
Write-Host ""
Write-Host "On cznmetadecks: open src/lib/events/capture-release.ts and update" -ForegroundColor Yellow
Write-Host "  CAPTURE_RELEASE_SHA = `"$headSha`";" -ForegroundColor Yellow
Write-Host ""
Write-Host "Then commit and deploy. Push czn-event-capture when ready:" -ForegroundColor Yellow
Write-Host "  git push origin <branch>" -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Yellow

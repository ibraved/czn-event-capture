#Requires -Version 5.1
<#
.SYNOPSIS
  Chaos Zero Nightmare event data exporter.

.DESCRIPTION
  Self-elevates via UAC, sets up a per-user install under %LOCALAPPDATA%\CZNEventCapture\
  (Python venv + mitmproxy + zstandard), trusts the mitmproxy CA in the Windows Root
  store, redirects the game server to 127.0.0.1 via the hosts file, and runs mitmproxy
  to intercept the game's WebSocket traffic.

  The mitmproxy addon submits captured data directly to cznmetadecks.com over
  HTTPS as state changes — no intermediate JSON file is written or read. The
  pairing token (created by 'run.ps1 -Pair') is passed to the addon via env
  var, so there is no on-disk window where a captured payload could be edited
  before it reaches the server.

  Only a small status.json (live counters + last submission status) lives on
  disk during a session, and only if -DumpFrames is set is debug.jsonl kept.
  Both files are removed at the end of a session unless -DumpFrames is given.

.PARAMETER Region
  "global" or "asia". Prompted on first run and remembered in config.json.

.PARAMETER DumpFrames
  Also write every decoded WebSocket frame to debug.jsonl for diagnostics.
  Suppresses the post-submit snapshot cleanup so the log stays on disk.

.PARAMETER Pair
  Run only the device-pairing flow (no capture). Stores the resulting token
  at %LOCALAPPDATA%\CZNEventCapture\token.json for subsequent capture runs.

.PARAMETER ServerBase
  Base URL of the cznmetadecks server. Defaults to https://cznmetadecks.com.
  Override for local development.

.PARAMETER AllowCustomServerBase
  Required when ServerBase is not the official cznmetadecks.com origin.
  This prevents accidental bearer-token disclosure to a non-official server.

.PARAMETER UnsafeDumpFrames
  When used with DumpFrames, write full decoded WebSocket payloads to
  debug.jsonl. By default DumpFrames redacts account-identifying fields.

.PARAMETER Locale
  en | ko | ja | zht. Forces a prompt language; otherwise auto-detected from
  Windows culture.

.PARAMETER RestoreOnly
  Skip the capture flow and only undo any leftover hosts-file edits.

.PARAMETER KeepCert
  Keep the mitmproxy CA certificate installed across runs. By default the
  certificate is installed at session start and removed on exit so admin
  trust is short-lived. Use this if you want to skip the per-session
  install/remove cycle on repeat captures.

.PARAMETER UninstallCert
  Remove mitmproxy CA certificates from the Windows Root store and exit.
#>
[CmdletBinding()]
param(
  [ValidateSet('global', 'asia', '')]
  [string]$Region = '',
  [switch]$DumpFrames,
  [switch]$UnsafeDumpFrames,
  [string]$InstallDir = "$env:LOCALAPPDATA\CZNEventCapture",
  [string]$ServerBase = 'https://cznmetadecks.com',
  [switch]$AllowCustomServerBase,
  [ValidateSet('', 'en', 'ko', 'ja', 'zht')]
  [string]$Locale = '',
  [switch]$Pair,
  [switch]$RestoreOnly,
  [switch]$KeepCert,
  [switch]$UninstallCert
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Force UTF-8 console output so localized strings (Japanese, Korean,
# Traditional Chinese) render correctly regardless of the user's default code
# page. Harmless on systems already set to UTF-8.
try {
  [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
  $OutputEncoding = [System.Text.Encoding]::UTF8
} catch {}

# ------------------------------------------------------------ constants
$SCRIPT_DIR = $PSScriptRoot
if (-not $SCRIPT_DIR) { $SCRIPT_DIR = (Get-Location).Path }

# Locale setup. locale.ps1 exports Resolve-Locale + T. Falls back to English
# literals if the helper isn't shipped alongside (e.g. partial install).
$LocaleScript = Join-Path $SCRIPT_DIR 'locale.ps1'
if (Test-Path $LocaleScript) {
  . $LocaleScript
  Resolve-Locale -Override $Locale | Out-Null
}
function Loc {
  param([string]$Id, [string]$Fallback)
  if (Get-Command T -ErrorAction SilentlyContinue) {
    $v = T $Id
    if ($v -and $v -ne $Id) { return $v }
  }
  return $Fallback
}

$HOSTS = @{
  'global' = 'live-g-czn-gamemjc2n1x.game.playstove.com'
  'asia'   = 'live-czn-gamelksj2nmf.game.playstove.com'
}
$OFFICIAL_SERVER_BASE = 'https://cznmetadecks.com'
$GAME_PORT = 13701
$HOSTS_FILE = "$env:SystemRoot\System32\drivers\etc\hosts"
$MARKER_START = '# CZN-EVENT-START'
$MARKER_END   = '# CZN-EVENT-END'
$GAME_PROCESSES = @('ucldr_ChaosZeroNightmare_GL_loader_x64', 'ChaosZeroNightmare')

# ------------------------------------------------------------ helpers
function Say($msg, $color = 'White') { Write-Host $msg -ForegroundColor $color }
function Step($msg) { Write-Host ""; Write-Host "==> $msg" -ForegroundColor Cyan }
function Die($msg) { Write-Host "ERROR: $msg" -ForegroundColor Red; Read-Host "Press Enter to exit"; exit 1 }
function Info($msg) { Write-Host "  $msg" -ForegroundColor Gray }
function Warn($msg) { Write-Host "  [!] $msg" -ForegroundColor Yellow }
function Banner([string[]]$lines, [System.ConsoleColor]$color = 'Red') {
  $sep = '=' * 72
  Write-Host ""
  Write-Host $sep -ForegroundColor $color
  foreach ($line in $lines) { Write-Host ("  " + $line) -ForegroundColor $color }
  Write-Host $sep -ForegroundColor $color
  Write-Host ""
}

function Normalize-ServerBase {
  param([Parameter(Mandatory)][string]$Value)
  try {
    $uri = [System.Uri]::new($Value)
  } catch {
    Die "Invalid -ServerBase URL: $Value"
  }
  if (-not $uri.IsAbsoluteUri -or -not $uri.Host) {
    Die "Invalid -ServerBase URL: $Value"
  }
  $isLocalDev = $uri.Host -in @('localhost', '127.0.0.1', '::1')
  if ($uri.Scheme -ne 'https' -and -not ($AllowCustomServerBase -and $isLocalDev)) {
    Die "-ServerBase must use https. Plain http is only allowed for localhost when -AllowCustomServerBase is set."
  }
  $builder = [System.UriBuilder]::new($uri)
  $builder.Path = ''
  $builder.Query = ''
  $builder.Fragment = ''
  return $builder.Uri.AbsoluteUri.TrimEnd('/')
}

$ServerBase = Normalize-ServerBase $ServerBase
if ($ServerBase -ne $OFFICIAL_SERVER_BASE -and -not $AllowCustomServerBase) {
  Die "Refusing custom -ServerBase '$ServerBase' without -AllowCustomServerBase. This protects your pairing token from being sent to an unintended server."
}
if ($UnsafeDumpFrames -and -not $DumpFrames) {
  Die "-UnsafeDumpFrames only applies when -DumpFrames is also set."
}
if ($AllowCustomServerBase -and $ServerBase -ne $OFFICIAL_SERVER_BASE) {
  Banner @(
    "DEVELOPER MODE: NON-OFFICIAL SERVER BASE",
    "",
    "Submissions + pairing checks will go to: $ServerBase",
    "NOT to cznmetadecks.com.",
    "",
    "Your bearer token (auth for your account) will be sent to that server.",
    "Only continue if this is YOUR development server. Stop now (Ctrl+C) if",
    "this was unexpected; check whether something set CZN_EVENT_SERVER_BASE",
    "in your environment without your knowledge."
  )
}
if ($UnsafeDumpFrames) {
  Banner @(
    "UNSAFE DEBUG MODE",
    "",
    "debug.jsonl will include UNREDACTED captured payloads:",
    "  user_id, nickname, stove_id, email, clerk_user_id, device_fingerprint",
    "",
    "Do NOT post or send the dump file. Anyone with it can identify you and",
    "your linked accounts."
  )
}

# Replace user-identifying path prefixes with environment-variable tokens so
# users sharing screenshots don't leak their Windows username. Display only
# — disk operations always use the real expanded path.
function Anon([string]$path) {
  if (-not $path) { return $path }
  $local = $env:LOCALAPPDATA
  $home = $env:USERPROFILE
  $appdata = $env:APPDATA
  if ($local -and $path.StartsWith($local, [System.StringComparison]::OrdinalIgnoreCase)) {
    return '%LOCALAPPDATA%' + $path.Substring($local.Length)
  }
  if ($appdata -and $path.StartsWith($appdata, [System.StringComparison]::OrdinalIgnoreCase)) {
    return '%APPDATA%' + $path.Substring($appdata.Length)
  }
  if ($home -and $path.StartsWith($home, [System.StringComparison]::OrdinalIgnoreCase)) {
    return '~' + $path.Substring($home.Length)
  }
  return $path
}

function Test-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p = [Security.Principal.WindowsPrincipal]::new($id)
  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Remove-MitMProxyCerts {
  $stores = @('Cert:\LocalMachine\Root', 'Cert:\CurrentUser\Root')
  $removed = 0
  foreach ($store in $stores) {
    try {
      $certs = Get-ChildItem -Path $store -ErrorAction Stop | Where-Object {
        $_.Subject -like '*mitmproxy*' -or $_.FriendlyName -like '*mitmproxy*'
      }
      foreach ($cert in $certs) {
        Remove-Item -LiteralPath $cert.PSPath -Force -ErrorAction Stop
        $removed += 1
      }
    } catch {}
  }
  return $removed
}

function Invoke-Silent {
  param([Parameter(Mandatory)][string]$Exe, [string[]]$Args = @())
  $prev = $ErrorActionPreference
  $ErrorActionPreference = 'SilentlyContinue'
  try {
    & $Exe @Args *> $null
    return $LASTEXITCODE
  } finally {
    $ErrorActionPreference = $prev
  }
}

# ------------------------------------------------------------ self-elevate
if (-not (Test-Admin)) {
  Say "Re-launching as Administrator..." 'Yellow'
  $ownPath = $PSCommandPath
  if (-not $ownPath) { Die "Could not self-elevate (unknown script path)." }
  $psArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $ownPath)
  if ($Region) { $psArgs += @('-Region', $Region) }
  if ($DumpFrames) { $psArgs += '-DumpFrames' }
  if ($UnsafeDumpFrames) { $psArgs += '-UnsafeDumpFrames' }
  if ($RestoreOnly) { $psArgs += '-RestoreOnly' }
  if ($KeepCert) { $psArgs += '-KeepCert' }
  if ($UninstallCert) { $psArgs += '-UninstallCert' }
  if ($Pair) { $psArgs += '-Pair' }
  if ($Locale) { $psArgs += @('-Locale', $Locale) }
  if ($AllowCustomServerBase) { $psArgs += '-AllowCustomServerBase' }
  if ($ServerBase -and $ServerBase -ne $OFFICIAL_SERVER_BASE) { $psArgs += @('-ServerBase', $ServerBase) }
  Start-Process powershell.exe -Verb RunAs -ArgumentList $psArgs
  exit
}

# ------------------------------------------------------------ install dir + config
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$ConfigFile = Join-Path $InstallDir 'config.json'
$VenvDir = Join-Path $InstallDir '.venv'
$VenvPy = Join-Path $VenvDir 'Scripts\python.exe'
$VenvMitm = Join-Path $VenvDir 'Scripts\mitmdump.exe'
$RequirementsDst = Join-Path $InstallDir 'requirements.txt'
$SnapshotsDir = Join-Path $InstallDir 'snapshots'
$LockFile = Join-Path $InstallDir 'hosts.lock'
$HostsBackup = Join-Path $InstallDir 'hosts.backup'
$CertSessionMarker = Join-Path $InstallDir 'cert.session-marker'
$TokenFile = Join-Path $InstallDir 'token.json'
New-Item -ItemType Directory -Force -Path $SnapshotsDir | Out-Null

try { Add-Type -AssemblyName System.Security } catch {}

function Protect-SecretText {
  param([Parameter(Mandatory)][string]$Text)
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
  $protected = [System.Security.Cryptography.ProtectedData]::Protect(
    $bytes,
    $null,
    [System.Security.Cryptography.DataProtectionScope]::CurrentUser
  )
  return [Convert]::ToBase64String($protected)
}

function Unprotect-SecretText {
  param([Parameter(Mandatory)][string]$CipherText)
  $bytes = [Convert]::FromBase64String($CipherText)
  $plain = [System.Security.Cryptography.ProtectedData]::Unprotect(
    $bytes,
    $null,
    [System.Security.Cryptography.DataProtectionScope]::CurrentUser
  )
  return [System.Text.Encoding]::UTF8.GetString($plain)
}

function Set-PrivateFileAcl {
  param([Parameter(Mandatory)][string]$Path)
  try {
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $false)
    $current = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $admins = 'BUILTIN\Administrators'
    foreach ($identity in @($current, $admins)) {
      $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
        $identity,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        [System.Security.AccessControl.AccessControlType]::Allow
      )
      $acl.SetAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
  } catch {
    Say "  WARN: Could not tighten ACL on $(Anon $Path): $($_.Exception.Message)" 'Yellow'
  }
}

function Write-TokenFile {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Token,
    [object]$SourcePayload,
    [Parameter(Mandatory)][string]$ServerBaseUrl
  )
  $payload = [ordered]@{
    protected  = $true
    tokenDpapi = Protect-SecretText $Token
    clerkUserId = $SourcePayload.clerkUserId
    deviceId    = $SourcePayload.deviceId
    pairedAt    = (Get-Date -Format o)
    serverBase  = $ServerBaseUrl
  }
  $json = $payload | ConvertTo-Json -Depth 4
  [System.IO.File]::WriteAllText($Path, $json, (New-Object System.Text.UTF8Encoding $false))
  Set-PrivateFileAcl -Path $Path
}

function Read-TokenFile {
  param([Parameter(Mandatory)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) { return $null }
  $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
  $parsed = $raw | ConvertFrom-Json
  if ($parsed.tokenDpapi) {
    return Unprotect-SecretText $parsed.tokenDpapi
  }
  # Backward-compatible read for v1/v2.0.0 token.json files.
  if ($parsed.token) { return [string]$parsed.token }
  return $null
}

function Test-TokenFileProtected {
  param([Parameter(Mandatory)][string]$Path)
  try {
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    $parsed = $raw | ConvertFrom-Json
    return [bool]$parsed.tokenDpapi
  } catch {
    return $false
  }
}

# ------------------------------------------------------------ pair mode
# Standard OAuth device-code flow:
#   1. Tool POSTs /device-code/request -> server returns an 8-character code
#      and records it as pending.
#   2. Tool displays the code and the URL where the user types it in.
#   3. User opens cznmetadecks.com/events/submit, signs in, clicks
#      "Pair this computer", enters the code, hits "Authorize device".
#      The website POSTs /device-code/confirm with the user's Clerk identity.
#   4. Tool polls /device-code/status; once the confirm has happened it
#      returns { status: "paired", token }, which is written to
#      %LOCALAPPDATA%\CZNEventCapture\token.json.
function Invoke-PairingFlow {
  param([string]$ServerBaseUrl, [string]$TokenOutputPath)

  Step (Loc 'pair.header' 'Device pairing')

  $requestUrl = "$($ServerBaseUrl.TrimEnd('/'))/api/events/device-code/request"
  $fingerprint = "$env:COMPUTERNAME / Windows"
  $code = $null
  try {
    $body = @{ deviceFingerprint = $fingerprint } | ConvertTo-Json -Compress
    $resp = Invoke-WebRequest -Uri $requestUrl `
                              -Method POST `
                              -Headers @{ 'Content-Type' = 'application/json' } `
                              -Body $body `
                              -UseBasicParsing `
                              -ErrorAction Stop
    $parsed = $resp.Content | ConvertFrom-Json
    $code = $parsed.code
  } catch {
    Die ((Loc 'pair.unreachable' 'Could not reach server: {0}') -f $_.Exception.Message)
  }
  if (-not $code) {
    Die (Loc 'pair.requestFailed' 'Server did not return a pairing code.')
  }

  Say ""
  Say ((Loc 'pair.codeHeading' '  Your pairing code:') ) 'White'
  Say ""
  Say ("      $code") 'Yellow'
  Say ""
  Say ((Loc 'pair.enterAt' '  Enter this code at {0}/events/submit') -f $ServerBaseUrl) 'White'
  Say ((Loc 'pair.thenAuthorize' "  Sign in, click 'Pair this computer', paste the code, hit Authorize.") ) 'Gray'
  Say ""
  Say ((Loc 'pair.waiting' '  Waiting for you to authorize in the browser...') ) 'Cyan'

  $statusUrl = "$($ServerBaseUrl.TrimEnd('/'))/api/events/device-code/status?code=$code"
  $deadline = (Get-Date).AddMinutes(10)
  while ((Get-Date) -lt $deadline) {
    try {
      $resp = Invoke-WebRequest -Uri $statusUrl -UseBasicParsing -ErrorAction Stop
      $body = $resp.Content | ConvertFrom-Json
      switch ($body.status) {
        'pending' {
          Start-Sleep -Seconds 2
          Write-Host "." -NoNewline
          continue
        }
        'expired' {
          Write-Host ""
          Die (Loc 'pair.expired' 'Code expired before confirmation. Generate a new code and run -Pair again.')
        }
        'paired' {
          Write-Host ""
          if (-not $body.token) {
            Die (Loc 'pair.requestFailed' 'Server did not return a pairing code.')
          }
          Write-TokenFile -Path $TokenOutputPath -Token $body.token -SourcePayload $body -ServerBaseUrl $ServerBaseUrl
          Say ""
          Say ((Loc 'pair.success' ' [OK] Paired successfully. Token saved to {0}') -f (Anon $TokenOutputPath)) 'Green'
          return
        }
        default {
          Write-Host ""
          Die ((Loc 'pair.unexpected' 'Unexpected status response: {0}') -f $body.status)
        }
      }
    } catch [System.Net.WebException] {
      $httpResp = $_.Exception.Response
      if ($httpResp -and [int]$httpResp.StatusCode -eq 429) {
        $reader = New-Object System.IO.StreamReader($httpResp.GetResponseStream())
        $txt = $reader.ReadToEnd()
        $reader.Close()
        $retry = 2000
        try { $retry = ($txt | ConvertFrom-Json).retryAfterMs } catch {}
        Start-Sleep -Milliseconds ([Math]::Max(500, [int]$retry))
        continue
      }
      Write-Host ""
      Die ((Loc 'pair.unreachable' 'Could not reach server: {0}') -f $_.Exception.Message)
    }
  }
  Write-Host ""
  Die (Loc 'pair.timeout' 'Timed out after 5 minutes waiting for confirmation.')
}

if ($Pair) {
  Invoke-PairingFlow -ServerBaseUrl $ServerBase -TokenOutputPath $TokenFile
  Read-Host (Loc 'pair.closePrompt' 'Press Enter to close')
  exit 0
}

# First-run auto-pair: capture requires a bearer token. If none is on file,
# run the pairing flow inline BEFORE touching the hosts file or starting the
# proxy. Matches the website's Auto-tab copy ("when it asks for a pairing
# code, click Pair this computer").
# Validate an existing token against the server before starting the capture.
# If the server reports the token is missing/revoked/invalid, drop it and
# re-pair inline so the user doesn't lose a full capture to a stale token.
function Test-TokenValid {
  param([string]$ServerBaseUrl, [string]$TokenFilePath)
  if (-not (Test-Path -LiteralPath $TokenFilePath)) { return $false }
  try {
    $tok = Read-TokenFile -Path $TokenFilePath
    if (-not $tok) { return $false }
    $resp = Invoke-WebRequest -Uri "$($ServerBaseUrl.TrimEnd('/'))/api/events/device/whoami" `
                              -Headers @{ 'Authorization' = "Bearer $tok" } `
                              -UseBasicParsing -ErrorAction Stop
    return $resp.StatusCode -eq 200
  } catch [System.Net.WebException] {
    $r = $_.Exception.Response
    if ($r -and [int]$r.StatusCode -eq 401) { return $false }
    # Network blip / server down: don't punish the user — treat as valid,
    # the later submit will surface the real failure.
    return $true
  } catch {
    return $true
  }
}

if (-not $RestoreOnly) {
  $hasToken = Test-Path -LiteralPath $TokenFile
  $tokenValid = if ($hasToken) { Test-TokenValid -ServerBaseUrl $ServerBase -TokenFilePath $TokenFile } else { $false }
  if (-not $tokenValid) {
    if ($hasToken) {
      Write-Host ""
      Write-Host " Stored token is no longer valid (revoked, expired, or the device was removed)." -ForegroundColor Yellow
      Write-Host " Re-pairing now before starting the capture." -ForegroundColor Yellow
      try { Remove-Item -LiteralPath $TokenFile -Force } catch {}
    } else {
      Write-Host ""
      Write-Host " No pairing token on file. Running the pairing step first..." -ForegroundColor Yellow
    }
    Invoke-PairingFlow -ServerBaseUrl $ServerBase -TokenOutputPath $TokenFile
    Write-Host ""
    Write-Host " Continuing to capture..." -ForegroundColor Cyan
  } elseif ($hasToken -and -not (Test-TokenFileProtected -Path $TokenFile)) {
    try {
      $tok = Read-TokenFile -Path $TokenFile
      if ($tok) {
        Write-TokenFile -Path $TokenFile -Token $tok -SourcePayload ([pscustomobject]@{}) -ServerBaseUrl $ServerBase
        Write-Host " Existing token migrated to DPAPI-protected storage." -ForegroundColor Gray
      }
    } catch {
      Write-Host " WARN: Could not migrate token.json to DPAPI-protected storage: $($_.Exception.Message)" -ForegroundColor Yellow
    }
  }
}

# ------------------------------------------------------------ safety helpers
function Read-HostsFile { try { return [System.IO.File]::ReadAllText($HOSTS_FILE, [System.Text.Encoding]::UTF8) } catch { return '' } }

function Write-TextFileAtomic {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Text
  )
  $dir = Split-Path -Parent $Path
  $tmp = Join-Path $dir ('.czn-event-' + [System.Guid]::NewGuid().ToString('N') + '.tmp')
  [System.IO.File]::WriteAllText($tmp, $Text, (New-Object System.Text.UTF8Encoding $false))
  Move-Item -LiteralPath $tmp -Destination $Path -Force
}

function Write-HostsFile($text) {
  Write-TextFileAtomic -Path $HOSTS_FILE -Text $text
  try { & ipconfig /flushdns | Out-Null } catch {}
}

function Remove-HostsMarkers {
  $content = Read-HostsFile
  if (-not $content) { return $false }
  $pattern = "(?s)\r?\n?$([regex]::Escape($MARKER_START)).*?$([regex]::Escape($MARKER_END))\r?\n?"
  $clean = [regex]::Replace($content, $pattern, '')
  if ($clean -ne $content) { Write-HostsFile $clean; return $true }
  return $false
}

function Restore-Hosts {
  $didSomething = $false
  if (Test-Path $HostsBackup) {
    try {
      $originalBytes = [System.IO.File]::ReadAllBytes($HostsBackup)
      $currentBytes = [System.IO.File]::ReadAllBytes($HOSTS_FILE)
      if ($originalBytes.Length -gt 0 -and [Convert]::ToBase64String($currentBytes) -ne [Convert]::ToBase64String($originalBytes)) {
        [System.IO.File]::WriteAllBytes($HOSTS_FILE, $originalBytes)
        try { & ipconfig /flushdns | Out-Null } catch {}
        $didSomething = $true
      }
    } catch {}
  }
  if (Remove-HostsMarkers) { $didSomething = $true }
  Remove-Item -Force -ErrorAction SilentlyContinue $LockFile
  Remove-Item -Force -ErrorAction SilentlyContinue $HostsBackup
  return $didSomething
}

function Invoke-OrphanRecovery {
  $needsRestore = $false
  if (Test-Path $LockFile) {
    try {
      $lock = Get-Content $LockFile -Raw | ConvertFrom-Json
      $owner = $null
      try { $owner = Get-Process -Id $lock.pid -ErrorAction Stop } catch {}
      if ($owner -and $owner.Id -ne $PID) {
        Die "Another czn-event-capture session (PID $($lock.pid)) is already running. Close it or reboot, then try again."
      }
      $needsRestore = $true
    } catch { $needsRestore = $true }
  }
  $content = Read-HostsFile
  if ($content -and $content -match [regex]::Escape($MARKER_START)) { $needsRestore = $true }
  if ($needsRestore) {
    Say "Detected leftover hosts entries from a prior run. Restoring..." 'Yellow'
    [void](Restore-Hosts)
    Say "  Restored cleanly." 'Gray'
  }

  # Cert orphan recovery: a marker remaining from a prior crashed session
  # means the cert was installed but we never cleaned up. Remove it now
  # unless that prior session was -KeepCert.
  if (Test-Path $CertSessionMarker) {
    try {
      $marker = Get-Content -Raw -LiteralPath $CertSessionMarker | ConvertFrom-Json
      $running = $false
      if ($marker.pid) {
        $running = [bool](Get-Process -Id $marker.pid -ErrorAction SilentlyContinue)
      }
      if (-not $running -and -not $marker.keep) {
        Say "Recovering: removing orphaned mitmproxy CA from previous session..." 'Yellow'
        [void](Remove-MitMProxyCerts)
      }
      if (-not $running) {
        Remove-Item -LiteralPath $CertSessionMarker -Force -ErrorAction SilentlyContinue
      }
    } catch {
      Say "Could not parse cert.session-marker; leaving in place." 'Yellow'
    }
  }
}

function Write-Lockfile {
  $lock = @{ pid = $PID; created_at = (Get-Date).ToString('o') } | ConvertTo-Json
  Set-Content -Path $LockFile -Value $lock -Encoding UTF8
}

$script:cleanupRan = $false
function Invoke-SafeCleanup {
  if ($script:cleanupRan) { return }
  $script:cleanupRan = $true
  try {
    if ($script:proxy -and -not $script:proxy.HasExited) {
      Stop-Process -Id $script:proxy.Id -Force -ErrorAction SilentlyContinue
    }
  } catch {}
  [void](Restore-Hosts)

  # Cert session cleanup: remove the cert we installed if -KeepCert wasn't set.
  if (Test-Path $CertSessionMarker) {
    try {
      $marker = Get-Content -Raw -LiteralPath $CertSessionMarker | ConvertFrom-Json
      if (-not $marker.keep) {
        Write-Host "Removing mitmproxy CA (session-only mode)..." -ForegroundColor Cyan
        [void](Remove-MitMProxyCerts)
      }
    } catch {
      Write-Host "Could not parse cert.session-marker; skipping cert cleanup." -ForegroundColor Yellow
    } finally {
      Remove-Item -LiteralPath $CertSessionMarker -Force -ErrorAction SilentlyContinue
    }
  }
}

# Register best-effort cleanup hooks FIRST.
Register-EngineEvent PowerShell.Exiting -Action { Invoke-SafeCleanup } | Out-Null
trap { Invoke-SafeCleanup; break }

Invoke-OrphanRecovery

if ($UninstallCert) {
  [void](Restore-Hosts)
  Step "Uninstalling mitmproxy certificate"
  Info "This is only for cleanup/uninstall. Normal capture runs do not remove the certificate."
  Info "If you run the capture again later, Windows may ask to trust the certificate again."
  $removed = Remove-MitMProxyCerts
  if ($removed -gt 0) {
    Say "Removed $removed mitmproxy CA certificate(s) from trusted Root stores." 'Green'
  } else {
    Say "No mitmproxy CA certificate was found in trusted Root stores." 'Gray'
  }
  Read-Host "Press Enter to close"
  exit 0
}

if ($RestoreOnly) {
  $did = Restore-Hosts
  if ($did) { Say "Hosts file restored." 'Green' } else { Say "Nothing to restore." 'Gray' }
  Read-Host "Press Enter to close"
  exit 0
}

$config = @{}
if (Test-Path $ConfigFile) {
  try { $config = Get-Content $ConfigFile -Raw | ConvertFrom-Json -AsHashtable } catch { $config = @{} }
}

# ------------------------------------------------------------ refuse while game is running
$runningGame = @($GAME_PROCESSES | ForEach-Object { Get-Process -Name $_ -ErrorAction SilentlyContinue }) | Where-Object { $_ }
if ($runningGame) {
  Write-Host ""
  Say "Chaos Zero Nightmare appears to be running already." 'Yellow'
  Say "The proxy must be up BEFORE the game connects, otherwise we can't intercept traffic." 'Yellow'
  Say "Close CZN completely, then run this tool again." 'Yellow'
  Read-Host "Press Enter to close"
  exit 1
}

# ------------------------------------------------------------ region
if (-not $Region) { $Region = $config.region }
while (-not $Region) {
  $ans = Read-Host "Select your server region [G]lobal or [A]sia"
  switch -Regex ($ans.ToLower()) {
    '^g' { $Region = 'global' }
    '^a' { $Region = 'asia' }
    default { Say "Enter G or A." 'Yellow' }
  }
}
$config.region = $Region
$config | ConvertTo-Json -Depth 5 | Set-Content -Path $ConfigFile -Encoding UTF8
$GameHost = $HOSTS[$Region]

# ------------------------------------------------------------ python
Step "Checking for Python"
$pythonExe = $null
foreach ($cmd in @('python', 'py')) {
  $candidate = Get-Command $cmd -ErrorAction SilentlyContinue
  if ($candidate) {
    if ((Invoke-Silent $candidate.Source @('-c', 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)')) -eq 0) {
      $pythonExe = $candidate.Source
      Say "  Found: $(Anon $pythonExe)" 'Gray'
      break
    }
  }
}
if (-not $pythonExe) { Die "Python 3.10+ not found on PATH. Install from https://www.python.org/downloads/ (tick 'Add to PATH'), then re-run." }

# ------------------------------------------------------------ venv + deps
if (-not (Test-Path $VenvPy)) {
  Step "Creating venv at $(Anon $VenvDir)"
  & $pythonExe -m venv $VenvDir
  if ($LASTEXITCODE -ne 0) { Die "venv creation failed" }
}

Step "Ensuring dependencies (mitmproxy, zstandard)"
$needInstall = (Invoke-Silent $VenvPy @('-c', 'import mitmproxy, zstandard')) -ne 0
if ($needInstall) {
  Say "  Installing into venv (first run only, ~60 seconds)..." 'Gray'
  $RequirementsSrc = Join-Path $SCRIPT_DIR 'requirements.txt'
  if (-not (Test-Path -LiteralPath $RequirementsSrc)) {
    $RequirementsSrc = $RequirementsDst
  }
  if ((Invoke-Silent $VenvPy @('-m', 'pip', 'install', '--upgrade', '--quiet', 'pip')) -ne 0) { Die "pip upgrade failed" }
  if (-not (Test-Path -LiteralPath $RequirementsSrc)) {
    Die "requirements.txt missing. Cannot proceed: hash-locked install requires it. Re-run the bootstrap one-liner."
  }
  # --require-hashes refuses to install any wheel whose archive hash is not
  # explicitly listed in requirements.txt. Protects against a compromised
  # PyPI dependency or a typo-squat substituting in for a transitive dep.
  if ((Invoke-Silent $VenvPy @('-m', 'pip', 'install', '--quiet', '--require-hashes', '--requirement', $RequirementsSrc)) -ne 0) { Die "pip install -r requirements.txt failed (hash mismatch or network)" }
}

# ------------------------------------------------------------ stage files
# When invoked via bootstrap.ps1, $SCRIPT_DIR and $InstallDir are the same
# folder (both %LOCALAPPDATA%\CZNEventCapture), so the copy is a no-op.
# When invoked from a dev clone, $SCRIPT_DIR points at the source checkout
# and the copy stages the current files into the install location.
Step "Staging capture files"
$AddonDst = Join-Path $InstallDir 'czn_event_capture.py'
$DictDst = Join-Path $InstallDir 'zstd_dictionary.bin'

function Copy-IfDifferent {
  param([string]$Src, [string]$Dst)
  $fullSrc = [System.IO.Path]::GetFullPath($Src)
  $fullDst = [System.IO.Path]::GetFullPath($Dst)
  if ($fullSrc -ieq $fullDst) { return }
  Copy-Item -Force $Src $Dst
}

Copy-IfDifferent (Join-Path $SCRIPT_DIR 'czn_event_capture.py') $AddonDst
Copy-IfDifferent (Join-Path $SCRIPT_DIR 'zstd_dictionary.bin') $DictDst
if (Test-Path -LiteralPath (Join-Path $SCRIPT_DIR 'requirements.txt')) {
  Copy-IfDifferent (Join-Path $SCRIPT_DIR 'requirements.txt') $RequirementsDst
}

# ------------------------------------------------------------ cert
Step "Ensuring mitmproxy CA cert is trusted"
Info "This certificate is required so the tool can read the game's encrypted connection during capture."
if ($KeepCert) {
  Info "Running with -KeepCert: the certificate will remain installed after this session."
} else {
  Info "The certificate will be removed automatically when this session ends (session-only mode)."
  Info "Use -KeepCert to keep it installed across runs, or -UninstallCert for manual removal."
}
$CertPath = Join-Path $env:USERPROFILE '.mitmproxy\mitmproxy-ca-cert.cer'
if (-not (Test-Path $CertPath)) {
  Say "  Generating CA cert (first run)..." 'Gray'
  $tmpProc = Start-Process -FilePath $VenvMitm -WindowStyle Hidden -PassThru
  $deadline = (Get-Date).AddSeconds(10)
  while (-not (Test-Path $CertPath) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }
  try { Stop-Process -Id $tmpProc.Id -Force -ErrorAction SilentlyContinue } catch {}
  if (-not (Test-Path $CertPath)) { Die "CA cert was not generated at $(Anon $CertPath)" }
}

$script:certInstallSkipped = $false
if ($KeepCert) {
  $alreadyTrusted = Get-ChildItem -Path 'Cert:\LocalMachine\Root' -ErrorAction SilentlyContinue |
    Where-Object { $_.Subject -like '*mitmproxy*' -or $_.FriendlyName -like '*mitmproxy*' } |
    Select-Object -First 1
  if ($alreadyTrusted) {
    Info "mitmproxy CA already trusted (-KeepCert). Skipping certutil call."
    $script:certInstallSkipped = $true
  }
}

if (-not $script:certInstallSkipped) {
  & certutil.exe -addstore -f Root $CertPath | Out-Null
  if ($LASTEXITCODE -ne 0) { Die "certutil -addstore failed" }
  Say "  Cert trusted." 'Gray'
}

# Write the session marker so crash-recovery and clean-exit cleanup know
# whether to remove the cert when this session ends.
$markerPayload = [ordered]@{
  pid = $PID
  installedAt = (Get-Date).ToString('o')
  keep = $KeepCert.IsPresent
} | ConvertTo-Json -Compress
Set-Content -LiteralPath $CertSessionMarker -Value $markerPayload -Encoding UTF8

# ------------------------------------------------------------ resolve real IP
Step "Resolving game server for region=$Region"
$realIp = $null
try {
  $realIp = (Resolve-DnsName -Name $GameHost -Type A -ErrorAction Stop | Where-Object { $_.IPAddress } | Select-Object -First 1).IPAddress
} catch {
  try { $realIp = [System.Net.Dns]::GetHostAddresses($GameHost)[0].IPAddressToString } catch {}
}
if (-not $realIp) { Die "Could not resolve $GameHost" }
Say "  $GameHost -> $realIp" 'Gray'

# ------------------------------------------------------------ hosts redirect
function Add-HostsRedirect {
  [void](Remove-HostsMarkers)
  $content = Read-HostsFile
  if (-not $content) { $content = '' }
  try {
    [System.IO.File]::WriteAllBytes($HostsBackup, [System.IO.File]::ReadAllBytes($HOSTS_FILE))
  } catch {
    [System.IO.File]::WriteAllText($HostsBackup, $content, (New-Object System.Text.UTF8Encoding $false))
  }
  Write-Lockfile
  $block = "`r`n$MARKER_START`r`n127.0.0.1 $GameHost`r`n$MARKER_END`r`n"
  Write-HostsFile ($content.TrimEnd() + $block)
}
Step "Editing hosts file (original backed up to $(Anon $HostsBackup))"
Add-HostsRedirect

# ------------------------------------------------------------ working files
$ts = Get-Date -Format 'yyyyMMdd_HHmmss'
$RunDir = Join-Path $SnapshotsDir $ts
New-Item -ItemType Directory -Force -Path $RunDir | Out-Null
$StatusFile  = Join-Path $RunDir 'status.json'

# ------------------------------------------------------------ load token (in memory only)
# Read the pairing token here so we can hand it to the mitmproxy subprocess
# via env var. The addon submits captured frames directly over HTTPS — the
# token never lands in any working file we generate.
$BearerToken = $null
try {
  $BearerToken = Read-TokenFile -Path $TokenFile
} catch {}
if (-not $BearerToken) {
  Die "Pairing token is missing or unreadable. Run 'run.ps1 -Pair' to re-pair."
}

# ------------------------------------------------------------ launch mitmdump
Step "Starting proxy"
$env:CZN_EVENT_OUTPUT_DIR = $RunDir
$env:CZN_EVENT_DICT_PATH = $DictDst
$env:CZN_EVENT_WORLD_ID = "world_live_$Region"
$env:CZN_EVENT_TOKEN = $BearerToken
$env:CZN_EVENT_SERVER_BASE = $ServerBase
if ($AllowCustomServerBase) { $env:CZN_EVENT_ALLOW_CUSTOM_SERVER_BASE = '1' } else { $env:CZN_EVENT_ALLOW_CUSTOM_SERVER_BASE = '0' }
if ($DumpFrames) { $env:CZN_EVENT_DEBUG = '1' } else { $env:CZN_EVENT_DEBUG = '0' }
if ($UnsafeDumpFrames) { $env:CZN_EVENT_UNSAFE_DEBUG = '1' } else { $env:CZN_EVENT_UNSAFE_DEBUG = '0' }

$mitmArgs = @(
  '--mode', "reverse:https://$($realIp):$GAME_PORT/",
  '--listen-host', '127.0.0.1',
  '--listen-port', $GAME_PORT,
  '--ssl-insecure',
  '--set', 'upstream_cert=false',
  '--set', 'keep_host_header=true',
  '--set', 'connection_strategy=lazy',
  '-q',
  '-s', $AddonDst
)
$mitmLog = Join-Path $RunDir 'mitm.log'
$script:proxy = Start-Process -FilePath $VenvMitm -ArgumentList $mitmArgs `
  -WindowStyle Hidden -PassThru `
  -RedirectStandardOutput $mitmLog -RedirectStandardError (Join-Path $RunDir 'mitm.err')

Start-Sleep -Seconds 2
if ($script:proxy.HasExited) {
  Invoke-SafeCleanup
  Die "mitmdump failed to start. See $(Anon $mitmLog)"
}

try {
  Write-Host ""
  Write-Host "============================================================" -ForegroundColor Green
  Write-Host " Capture is LIVE. Now do this in the game:"                   -ForegroundColor Green
  Write-Host ""                                                             -ForegroundColor Green
  Write-Host "   1. Launch Chaos Zero Nightmare and log in."                -ForegroundColor Green
  Write-Host "   2. Open the event menu and enter the event."               -ForegroundColor Green
  Write-Host "   3. For EACH boss:"                                         -ForegroundColor Green
  Write-Host "        - Open the boss, tap Start / Battle."                 -ForegroundColor Green
  Write-Host "        - Let combat begin, then retreat or escape."          -ForegroundColor Green
  Write-Host "        - Back out to the boss list."                         -ForegroundColor Green
  Write-Host "   4. (Optional) Re-open the event summary screen once more." -ForegroundColor Green
  Write-Host "   5. Press Enter here when the counter below looks right."   -ForegroundColor Green
  Write-Host "============================================================" -ForegroundColor Green
  Write-Host ""
  Write-Host "  [!] Do NOT force-close this window while the capture is live." -ForegroundColor Yellow
  Write-Host "      Press Enter (or Q / Esc) to stop cleanly."                 -ForegroundColor Yellow
  Write-Host "      If the window crashes, re-run the install command -"       -ForegroundColor Yellow
  Write-Host "      it auto-detects the orphaned state and restores cleanly."  -ForegroundColor Yellow
  Write-Host "      Do not edit files in %LOCALAPPDATA%\CZNEventCapture while this runs." -ForegroundColor Yellow
  Write-Host ""

  $lastStatusJson = ''
  while ($true) {
    if (Test-Path $StatusFile) {
      try {
        $raw = Get-Content $StatusFile -Raw
        if ($raw -and $raw -ne $lastStatusJson) {
          $lastStatusJson = $raw
          $s = $raw | ConvertFrom-Json
          $evs = if ($s.events_captured) { @($s.events_captured).Count } else { 0 }
          $atts = if ($s.attempts_captured) { @($s.attempts_captured).Count } else { 0 }
          $sent = if ($s.submissions_sent) { [int]$s.submissions_sent } else { 0 }
          $line = "  captured: $evs event(s), $atts battle attempt(s), submissions: $sent"
          Write-Host ("`r" + $line.PadRight(90)) -NoNewline -ForegroundColor Cyan
        }
      } catch {}
    }

    if ([Console]::KeyAvailable) {
      $k = [Console]::ReadKey($true)
      if ($k.Key -eq 'Enter' -or $k.Key -eq 'Q' -or $k.Key -eq 'Escape') { break }
    }
    if ($script:proxy.HasExited) {
      Write-Host ""
      Say "Proxy exited unexpectedly. Check $(Anon $mitmLog)" 'Yellow'
      break
    }
    Start-Sleep -Milliseconds 300
  }
  Write-Host ""

  Step "Stopping capture"
  # Wait briefly so any in-flight submission completes before we kill the
  # proxy. The addon debounces submits 3 seconds after each meaningful
  # frame, so the latest state was POSTed at most ~3 seconds before the
  # user pressed Enter; this grace period lets that final POST land.
  if ($script:proxy -and -not $script:proxy.HasExited) {
    Start-Sleep -Seconds 4
    if (-not $script:proxy.HasExited) {
      try { Stop-Process -Id $script:proxy.Id -Force } catch {}
      try { $script:proxy.WaitForExit(3000) | Out-Null } catch {}
    }
  }
} finally {
  # Clear the bearer token from this process's env so it isn't visible to
  # any child this PowerShell may spawn after we're done with the proxy.
  Remove-Item Env:\CZN_EVENT_TOKEN -ErrorAction SilentlyContinue
  Remove-Item Env:\CZN_EVENT_ALLOW_CUSTOM_SERVER_BASE -ErrorAction SilentlyContinue
  Remove-Item Env:\CZN_EVENT_UNSAFE_DEBUG -ErrorAction SilentlyContinue
  Invoke-SafeCleanup
}

# ------------------------------------------------------------ handoff
# The addon submitted state directly while capture was running. Read the
# final status.json to report the outcome to the user.
$status = $null
if (Test-Path $StatusFile) {
  try { $status = Get-Content -LiteralPath $StatusFile -Raw -Encoding UTF8 | ConvertFrom-Json } catch {}
}

$eventCount = if ($status -and $status.events_captured) { @($status.events_captured).Count } else { 0 }
$attemptCount = if ($status -and $status.attempts_captured) { @($status.attempts_captured).Count } else { 0 }
$submissions = if ($status -and $status.submissions_sent) { [int]$status.submissions_sent } else { 0 }
$lastStatus = if ($status) { $status.last_submit_status } else { $null }
$lastMessage = if ($status) { $status.last_submit_message } else { $null }

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " [OK] Capture complete: $eventCount event(s), $attemptCount battle attempt(s)" -ForegroundColor Green

if ($eventCount -eq 0 -and $attemptCount -eq 0) {
  Write-Host " No event frames were intercepted. Did you open the event and run any bosses?" -ForegroundColor Yellow
} elseif ($submissions -gt 0 -and $lastStatus -eq 'success') {
  Write-Host (" Server accepted $submissions submission(s).") -ForegroundColor Green
  if ($lastMessage) { Write-Host ("   $lastMessage") -ForegroundColor Gray }
} elseif ($lastStatus -eq 'unauthorized') {
  Write-Host " Pairing was rejected by the server. Run 'run.ps1 -Pair' to re-pair." -ForegroundColor Yellow
} elseif ($lastStatus -eq 'rate_limited') {
  Write-Host " The server is rate-limiting. Wait a bit and try a smaller session." -ForegroundColor Yellow
} elseif ($lastStatus -eq 'error' -or $submissions -eq 0) {
  Write-Host " No successful submission was confirmed." -ForegroundColor Yellow
  if ($lastMessage) { Write-Host ("   $lastMessage") -ForegroundColor Gray }
}

# Clean up the run directory unless the user asked to keep diagnostics. The
# only files in there are status.json and (with -DumpFrames) debug.jsonl /
# mitm.log. We keep the snapshots/ root itself.
if (-not $DumpFrames) {
  try {
    Remove-Item -LiteralPath $RunDir -Recurse -Force -ErrorAction Stop
    Write-Host "  Local session files cleaned up." -ForegroundColor Gray
  } catch {
    Write-Host "  Could not clean up $(Anon $RunDir) (continuing)." -ForegroundColor Gray
  }
} else {
  Write-Host "  Diagnostic files kept at $(Anon $RunDir)" -ForegroundColor Gray
}

Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Read-Host "Press Enter to close"

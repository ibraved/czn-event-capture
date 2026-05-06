# czn-event-capture

Event-data exporter for **Chaos Zero Nightmare**. Captures rank, per-boss score, deployed team, and the full materialised build snapshot for every boss you start. The mitmproxy addon submits captured frames directly to your [cznmetadecks.com](https://cznmetadecks.com) account over HTTPS.

This script runs on your machine and is fully auditable. Read the source before running it.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE) · [Source on GitHub](https://github.com/ibraved/czn-event-capture) · [Security policy](./SECURITY.md)

> **Pinned to commit `5fc9993`.** The install command below points at this exact commit, not a branch. The `bootstrap.ps1` script itself pins SHA256 hashes of every downstream file. Verify by clicking the commit link above and reading the script before running it.

## Quick start

Open Windows PowerShell **as Administrator** and run:

```powershell
irm 'https://raw.githubusercontent.com/ibraved/czn-event-capture/5fc99936976114558ee86ea17db65204f32a9bf4/bootstrap.ps1' | iex
```

**Why admin?** Two reasons: (1) hosts file edit so the proxy can intercept the game's HTTPS traffic, reverted on exit. (2) Local TLS cert install so the game trusts the proxy's certificate. That's it.

That single command:

1. Downloads the current scripts into `%LOCALAPPDATA%\CZNEventCapture\`.
2. Creates a Python virtual environment and installs pinned `mitmproxy` + `zstandard` from `requirements.txt` (first run only, ~60 s).
3. Trusts the mitmproxy CA in the Windows Root store.
4. Prompts for your server region (Global or Asia, remembered between runs).
5. Edits `hosts` to redirect the game server to `127.0.0.1`, launches the proxy, then steps you through the in-game capture.
6. The proxy addon submits captured frames to cznmetadecks.com directly using your stored pairing token.

## Pair the tool (one-time)

Pairing connects the tool to your cznmetadecks.com account. Once per machine.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\run.ps1 -Pair
```

The tool prints an 8-character code. Open `https://cznmetadecks.com/events/submit`, click **Pair this computer**, paste the code, and authorise. The tool stores a DPAPI-protected bearer token at `%LOCALAPPDATA%\CZNEventCapture\token.json` that only your Windows user can decrypt.

**What this token does:** submits FSO event captures for THIS account only. It cannot read your private data and cannot sign you out. Revocable from Paired PCs at any time.

## Capturing event data

1. **Close the game fully.**
2. Run the tool (one-liner above, or `.\run.ps1` if already installed).
3. When the tool prints *Capture is LIVE*, launch the game and log in.
4. For each boss: open the prep screen, hit Start/Battle, retreat, back out.
5. Re-open the event summary once.
6. Press **Enter** to stop. The proxy flushes a final submission.

If the network drops mid-session, the addon retries on the next captured frame. If the final flush fails, just run the tool again.

## What changes on your machine

- **`hosts` file**: single block bracketed by `# CZN-EVENT-START` / `# CZN-EVENT-END`, redirects the game server to `127.0.0.1:13701`. Reverted on exit. If interrupted, rerun the install command and it self-heals.
- **Windows Root certificate store**: installs the mitmproxy CA at session start, removes it at session end. Pass `-KeepCert` if you'd rather not be prompted on every run. Remove an installed cert manually via `.\run.ps1 -UninstallCert` or `certmgr.msc` (search for "mitmproxy").
- **`%LOCALAPPDATA%\CZNEventCapture\`**: the install dir. Delete the folder to fully uninstall.

## What data leaves your machine

- Capture data (event ranks, scores, deployed teams, build snapshots, login user state) goes **only** to `cznmetadecks.com` over HTTPS.
- No telemetry. No third-party endpoints. No usage analytics.
- Payload tied to your bearer token (see `token.json` above). Token is account-scoped; cannot read your private data; revocable any time.

Full payload schema: [`docs/payload-schema.md`](./docs/payload-schema.md).

## Uninstall

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "$env:LOCALAPPDATA\CZNEventCapture\run.ps1" -UninstallCert
Remove-Item -Recurse -Force "$env:LOCALAPPDATA\CZNEventCapture"
```

The first command removes the mitmproxy CA from your trust store. The second deletes everything else.

## Requirements

- Windows 10 or 11.
- Python 3.10+ on `PATH` (install from <https://www.python.org/downloads/> with *"Add to PATH"* ticked).
- A paired cznmetadecks.com account.

## Troubleshooting

If your antivirus flags the script, file a false-positive report with the vendor and let us know via support@cznmetadecks.com (see [SECURITY.md](./SECURITY.md)). For capture failures, open an issue with `mitm.log` from `%LOCALAPPDATA%\CZNEventCapture\`. Run with `-DumpFrames` to also keep a redacted `debug.jsonl`. Do **not** share `-UnsafeDumpFrames` logs publicly.

<details>
<summary>Advanced flags</summary>

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\run.ps1 [flags]
```

| Flag | Effect |
|---|---|
| `-Pair` | Run the device-pairing flow only. |
| `-Region <global\|asia>` | Skip the region prompt. |
| `-Locale <en\|ko\|ja\|zht>` | Force a prompt language; auto-detected from Windows culture. |
| `-DumpFrames` | Keep a redacted `debug.jsonl` for diagnostics. |
| `-UnsafeDumpFrames` | **Local debugging only.** With `-DumpFrames`, writes full unredacted payloads (user_id, nickname, email, device_fingerprint, etc.) to `debug.jsonl`. Never share the file. |
| `-ServerBase <url>` | Override the cznmetadecks base URL. Requires `-AllowCustomServerBase`. **If anything other than `https://cznmetadecks.com` ends up in this flag without your intent, your bearer token is being sent to that server, not us.** |
| `-AllowCustomServerBase` | Allow a non-official server base. Plain `http` only for localhost. |
| `-RestoreOnly` | Skip capture; restore any leftover hosts edits and exit. |
| `-UninstallCert` | Remove mitmproxy CA, restore hosts edits, exit. |

Auto-detects Windows language; pass `-Locale` to override.

</details>

## License

MIT. Includes a compression dictionary (`zstd_dictionary.bin`) extracted from the Chaos Zero Nightmare game client and used for zstd-decoding the game's WebSocket frames.

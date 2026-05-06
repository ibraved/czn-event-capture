# Changelog

## v2.1.0 - 2026-04-25

### Security hardening

- Pairing tokens are now stored with Windows DPAPI protection and a tightened
  file ACL instead of plain JSON.
- Custom `-ServerBase` values now require `-AllowCustomServerBase`; non-HTTPS
  custom origins are refused except localhost development.
- `-DumpFrames` now writes redacted frame payloads by default. Full payload
  dumps require the explicit `-UnsafeDumpFrames` opt-in.
- Added `-UninstallCert` to remove mitmproxy CA certificates from trusted Root
  stores and restore any leftover hosts-file edits.
- Hosts-file backup/restore now preserves the original bytes where possible
  and writes changes through a temporary file before replacing the hosts file.
- README install instructions keep the website-friendly one-line bootstrap
  flow while the bootstrap verifies downloaded release files with SHA-256.

### Quality

- Added pinned `requirements.txt` for reproducible dependency installs.
- Added GitHub Actions CI for Python syntax compilation and PowerShell
  PSScriptAnalyzer checks.
- Added optional bootstrap SHA-256 verification hooks for release artifacts.

## v2.0.0 - 2026-04-25

Tightened the submission loop to remove the on-disk tampering window.

### Changes

- The mitmproxy addon now POSTs captured frames directly to
  `cznmetadecks.com/api/events/submissions` over HTTPS as state changes,
  debounced 3 seconds after each meaningful frame and flushed once more on
  shutdown. The previous two-step pipeline (addon writes `capture.json`,
  separate PowerShell script reads + POSTs) is gone: there is no longer
  any on-disk JSON the user could edit between capture and submit.
- The bearer token is read by `run.ps1` once and passed to the addon via
  the `CZN_EVENT_TOKEN` environment variable on the proxy subprocess. The
  variable is cleared from the parent shell when the proxy exits.
- `submit.ps1` removed. Anyone who installed `v1.x` will have it deleted
  automatically the next time they run the bootstrap one-liner.
- Locale strings under the `submit.*` namespace removed.
- Session folder is `%LOCALAPPDATA%\CZNEventCapture\snapshots\<timestamp>\`
  and contains only `status.json` (live counters + last submission status)
  and, if `-DumpFrames` is set, `debug.jsonl` and `mitm.log`. The folder
  is removed when the session ends unless `-DumpFrames` is given.

### Migration

- Re-run the install one-liner. It will replace `run.ps1`,
  `czn_event_capture.py`, `locale.ps1` and delete the stale `submit.ps1`.
- Existing pairing tokens remain valid; no re-pair is needed.

## v1.0.0 - 2026-04-23

Initial public release.

### Features

- mitmproxy-based capture of FSO event summary frames, battle return frames,
  and the user's login state (characters, savedata, team presets).
- Self-elevating PowerShell entry point. Per-user install under
  `%LOCALAPPDATA%\CZNEventCapture\`: Python venv, mitmproxy + zstandard,
  trusted mitmproxy CA, layered hosts-file restore.
- Device pairing flow (`run.ps1 -Pair`): user generates an 8-character code on
  cznmetadecks.com/events/submit, enters it in the tool, and the tool polls
  the status endpoint until the browser confirms. Bearer token is stored at
  `%LOCALAPPDATA%\CZNEventCapture\token.json`.
- Direct submit to `cznmetadecks.com/api/events/submissions` after every
  capture. Requires pairing; unpaired runs exit with a clear instruction.
- Local snapshot is deleted after a successful submit so no capture data
  lingers on disk. On submit failure the snapshot is kept at
  `%LOCALAPPDATA%\CZNEventCapture\snapshots\<timestamp>\` so the user can
  retry via `submit.ps1`. `-Report` and `-DumpFrames` suppress the cleanup
  for local inspection.
- Standalone `submit.ps1` to re-send an existing `capture.json` using the
  stored token. Mirrors the same post-success cleanup, scoped to the
  install's snapshots folder.
- Localized prompts for the pairing flow, submit flow, and the highest-
  visibility capture-flow strings in English, Korean, Japanese, and
  Traditional Chinese. System culture is auto-detected; override with
  `-Locale en|ko|ja|zht`.
- `world_id` propagated from the selected region (`-Region global` or `asia`)
  and populated at the capture payload root so server-side validation passes.
- `user_id` hoisted from event entities as a fallback when the capture
  session starts after login and no login frame is seen.

### Known limitations

- Non-English localization currently covers the pairing flow, submit flow,
  and the highest-visibility capture banner + post-capture messages. The
  intermediate prompts in `run.ps1` (venv setup, cert trust, hosts-file
  edit) remain in English and will be localized in a follow-up release.
- Tested on: Windows 11 Pro, Global region. Asia region path compiles and
  should work but has not been tested end-to-end.

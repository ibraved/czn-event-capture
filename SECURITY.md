# Security policy

## Reporting a vulnerability

Email **support@cznmetadecks.com** with subject prefix `[security]`. We respond within 7 days.

## Scope

In scope:

- **Token leakage**: the bearer token stored at `%LOCALAPPDATA%\CZNEventCapture\token.json`.
- **Supply-chain compromise**: any file fetched by the bootstrap script.
- **Action expansion**: any way to make the script perform an action other than the documented hosts edit, certificate install, and POST to cznmetadecks.com.
- **Cross-account submission**: any way to obtain or manipulate another user's submissions.

Out of scope:

- **Score forgery or build forgery**: submitting fabricated data is a moderation issue, not a security vulnerability.
- **The compression dictionary** (`zstd_dictionary.bin`): derived from the game and redistributed under the upstream MIT terms.

## Antivirus false positives

PowerShell installers occasionally trigger heuristic AV flags. If your AV vendor flags a release:

1. File a false-positive report with the vendor (Microsoft Defender submission portal, Bitdefender, etc.).
2. Email **support@cznmetadecks.com** with a copy of the report so we can coordinate.

We do not currently run a paid bug-bounty programme.

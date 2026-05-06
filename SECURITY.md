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

## Known limitations

### Upstream TLS verification disabled in the reverse proxy

The capture proxy is launched with `--ssl-insecure` because `run.ps1`
hosts-redirects the game host to `127.0.0.1` and forwards from there to
the game server's resolved IP. mitmproxy's TLS verification cannot match
the cert hostname when the upstream is an IP, and there is no granular
"verify chain but skip hostname" option in mitmproxy 12.

Threat: an attacker who can DNS-spoof or ARP-poison the local network at
session start could MITM the upstream and feed crafted game frames into
the addon, causing inflated or fabricated scores to land on the user's
cznmetadecks account.

Out of scope for this issue:
- The bearer token is **not** routed through this proxy. The Python
  addon POSTs directly to `cznmetadecks.com` over a normal verified
  HTTPS connection, so token theft via upstream MITM is not possible.
- Inflated scores are caught by server-side moderator review.

If you capture only on networks you control, this is irrelevant. On
public Wi-Fi or any network you do not trust, treat captured submissions
as untrusted until you re-capture from a trusted network.

A future release may add cert-fingerprint pinning (TOFU) to close this
gap. Tracked but not yet shipped.

## Antivirus false positives

PowerShell installers occasionally trigger heuristic AV flags. If your AV vendor flags a release:

1. File a false-positive report with the vendor (Microsoft Defender submission portal, Bitdefender, etc.).
2. Email **support@cznmetadecks.com** with a copy of the report so we can coordinate.

We do not currently run a paid bug-bounty programme.

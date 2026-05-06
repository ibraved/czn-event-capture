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

## Upstream TLS handling

The capture proxy is launched with `--ssl-insecure` because `run.ps1`
hosts-redirects the game host to `127.0.0.1` and forwards from there to
the game server's resolved IP. mitmproxy can't verify a hostname against
an IP-typed upstream, and mitmproxy 12 has no granular skip-hostname-only
option.

Defense in depth: the addon (`_czn_capture_lib.UpstreamCertPinner`) hooks
mitmproxy's `tls_established_server`, hashes the leaf cert SHA-256, and
compares it against a per-region pin in `cert-pins.json`. First connection
records the pin (TOFU); subsequent sessions verify. On mismatch the
pinner refuses to submit any captured frames for the rest of the session.
If the upstream cert legitimately rotates, delete `cert-pins.json` next
to `status.json` and rerun.

The bearer token is **not** routed through this proxy. The addon POSTs
directly to `cznmetadecks.com` over a normal verified HTTPS connection
(via `ssl.create_default_context()`), so token theft via upstream MITM
is not possible.

## Antivirus false positives

PowerShell installers occasionally trigger heuristic AV flags. If your AV vendor flags a release:

1. File a false-positive report with the vendor (Microsoft Defender submission portal, Bitdefender, etc.).
2. Email **support@cznmetadecks.com** with a copy of the report so we can coordinate.

We do not currently run a paid bug-bounty programme.

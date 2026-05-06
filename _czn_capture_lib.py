"""
Internal helpers for czn_event_capture.py.

Classes (each with one responsibility):
  Config, FrameDecoder, UserState, CaptureState, FrameRouter,
  Submitter (+ SubmitResult, SubmissionHistory),
  StatusWriter, DebugLogger.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Literal

try:
    import zstandard as zstd
    HAS_ZSTD = True
except ImportError:
    zstd = None  # type: ignore
    HAS_ZSTD = False


# Dedicated logger so we don't fight mitmproxy's root configuration. The
# `[czn-event] ...` prefix is what run.ps1 scrapes from stdout.
logger = logging.getLogger("czn_event")
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("[czn-event] %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False


OFFICIAL_SERVER_BASE = "https://cznmetadecks.com"

# Debounce: a normal session of 5–10 bosses + summary refreshes collapses
# to one or two POSTs, well under the server's 10/hour per-token cap.
SUBMIT_DEBOUNCE_SECONDS = 3.0

# Real CZN game frames sit comfortably under 1 MB even for full login
# payloads. 16 MB cap stops zip-bombs from a malicious upstream from
# expanding to arbitrary memory while leaving headroom for unexpected
# but legitimate growth.
MAX_DECOMPRESSED_BYTES = 16 * 1024 * 1024

SENSITIVE_DEBUG_KEYS = frozenset({
    "account_id",
    "authorization",
    "clerk_user_id",
    "clerkuserid",
    "device_fingerprint",
    "device_id",
    "deviceid",
    "email",
    "nickname",
    "stove_id",
    "token",
    "user_id",
    "userid",
})

_SENSITIVE_SUBSTRINGS = ("token", "authorization", "fingerprint")


def is_sensitive_debug_key(key: str) -> bool:
    lowered = key.lower()
    if lowered in SENSITIVE_DEBUG_KEYS:
        return True
    return any(needle in lowered for needle in _SENSITIVE_SUBSTRINGS)


@dataclass(frozen=True)
class Config:
    output_dir: Path
    dict_path: Path
    debug: bool
    unsafe_debug: bool
    world_id_default: str | None
    submit_token: str | None
    server_base: str
    allow_custom_server_base: bool

    @classmethod
    def from_env(cls) -> "Config":
        here = Path(__file__).resolve().parent
        output_dir = Path(os.environ.get("CZN_EVENT_OUTPUT_DIR", str(here)))
        output_dir.mkdir(parents=True, exist_ok=True)

        allow_custom = os.environ.get("CZN_EVENT_ALLOW_CUSTOM_SERVER_BASE") == "1"
        raw_base = (os.environ.get("CZN_EVENT_SERVER_BASE") or OFFICIAL_SERVER_BASE).rstrip("/")
        server_base = _validate_server_base(raw_base, allow_custom=allow_custom)

        dict_path = _validate_dict_path(
            configured=os.environ.get("CZN_EVENT_DICT_PATH"),
            install_dir=here,
            output_dir=output_dir,
        )

        return cls(
            output_dir=output_dir,
            dict_path=dict_path,
            debug=os.environ.get("CZN_EVENT_DEBUG") == "1",
            unsafe_debug=os.environ.get("CZN_EVENT_UNSAFE_DEBUG") == "1",
            world_id_default=os.environ.get("CZN_EVENT_WORLD_ID") or None,
            submit_token=os.environ.get("CZN_EVENT_TOKEN") or None,
            server_base=server_base,
            allow_custom_server_base=allow_custom,
        )

    @property
    def submit_url(self) -> str:
        return f"{self.server_base}/api/events/submissions"

    @property
    def is_official_server_base(self) -> bool:
        return self.server_base == OFFICIAL_SERVER_BASE

    @property
    def status_file(self) -> Path:
        return self.output_dir / "status.json"

    @property
    def debug_file(self) -> Path:
        return self.output_dir / "debug.jsonl"


def _validate_server_base(value: str, *, allow_custom: bool) -> str:
    parsed = urllib.parse.urlparse(value)
    if not parsed.scheme or not parsed.hostname:
        raise RuntimeError(f"Invalid CZN_EVENT_SERVER_BASE: {value!r}")
    is_localhost = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "https" and not (allow_custom and is_localhost):
        raise RuntimeError(
            "CZN_EVENT_SERVER_BASE must use https unless explicitly using localhost development."
        )
    normalized = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
    if normalized != OFFICIAL_SERVER_BASE and not allow_custom:
        raise RuntimeError(
            "Refusing custom CZN_EVENT_SERVER_BASE without CZN_EVENT_ALLOW_CUSTOM_SERVER_BASE=1."
        )
    return normalized


def _validate_dict_path(*, configured: str | None, install_dir: Path, output_dir: Path) -> Path:
    # Restrict dict_path to install_dir / output_dir so a malicious env var
    # can't read arbitrary file contents into memory and (when combined
    # with a custom server base) exfiltrate them.
    default = install_dir / "zstd_dictionary.bin"
    if not configured:
        return default
    candidate = Path(configured).resolve()
    allowed_roots = [install_dir.resolve(), output_dir.resolve()]
    for root in allowed_roots:
        try:
            candidate.relative_to(root)
            return candidate
        except ValueError:
            continue
    raise RuntimeError(
        f"CZN_EVENT_DICT_PATH must be under {install_dir} or {output_dir}; got {candidate}"
    )


class FrameDecoder:
    """Tries decoders in order: utf-8 raw, zstd-with-dict, zstd-bare, gzip, zlib (4 wbits variants)."""

    def __init__(self, config: Config) -> None:
        self._zstd_dctx: Any = self._load_zstd_dict(config.dict_path)
        self._chain = self._build_chain()

    @staticmethod
    def _load_zstd_dict(dict_path: Path) -> Any:
        if not HAS_ZSTD or not dict_path.exists():
            logger.warning("zstandard=%s, dict_exists=%s", HAS_ZSTD, dict_path.exists())
            return None
        try:
            raw = dict_path.read_bytes()
            d = zstd.ZstdCompressionDict(raw)
            dctx = zstd.ZstdDecompressor(dict_data=d)
            logger.info("Loaded zstd dictionary (%d bytes)", len(raw))
            return dctx
        except Exception:
            logger.exception("failed to load zstd dictionary")
            return None

    def _build_chain(self) -> list[Callable[[bytes], bytes]]:
        cap = MAX_DECOMPRESSED_BYTES
        chain: list[Callable[[bytes], bytes]] = [lambda b: b]  # already utf-8
        if self._zstd_dctx is not None:
            chain.append(lambda b: self._zstd_dctx.decompress(b, max_output_size=cap))
        if HAS_ZSTD:
            chain.append(lambda b: zstd.ZstdDecompressor().decompress(b, max_output_size=cap))
        # zlib.decompressobj(...).decompress(data, max_length) caps OUTPUT
        # bytes per call. wbits=47 auto-detects gzip vs zlib; -15 covers
        # raw-deflate streams. Two attempts span the formats the previous
        # one-shot chain handled (gzip + zlib + 4 wbits variants) with the
        # crucial difference that a zip-bomb is rejected mid-inflation,
        # not after the full buffer has already allocated.
        for wbits in (47, -15):
            chain.append(lambda b, w=wbits: _bounded_streaming_zlib(b, w))
        return chain

    def decode(self, raw: bytes) -> str | None:
        if not raw:
            return None
        if len(raw) > MAX_DECOMPRESSED_BYTES:
            logger.warning("Dropping oversize raw frame: %d bytes", len(raw))
            return None
        for decoder in self._chain:
            try:
                return decoder(raw).decode("utf-8")
            except Exception:
                continue
        return None


def _bounded_streaming_zlib(raw: bytes, wbits: int) -> bytes:
    cap = MAX_DECOMPRESSED_BYTES
    d = zlib.decompressobj(wbits=wbits)
    out = d.decompress(raw, cap)
    if d.unconsumed_tail:
        # More compressed input remains but we already produced `cap` output
        # bytes — refusing to continue. unconsumed_tail is a *bytes* slice,
        # not a re-allocation; checking its truthiness is cheap.
        raise ValueError(f"decompressed payload exceeds cap ({cap}+ bytes)")
    tail = d.flush()
    if len(out) + len(tail) > cap:
        raise ValueError(f"decompressed payload exceeds cap ({len(out) + len(tail)} > {cap})")
    return out + tail


def _normalize_id(value: Any) -> str | None:
    # Accept str / int / float; reject dicts, lists, None. Always return
    # a string so dict keys are uniformly comparable for sorted() in
    # StatusWriter, regardless of whether the wire format gave us "123"
    # or 123.
    if isinstance(value, bool):
        return None  # bool is a subclass of int in Python; reject explicitly
    if isinstance(value, (str, int, float)):
        s = str(value)
        # Cap length so a multi-MB string id can't bloat the events/attempts
        # dict's keys.
        return s if len(s) <= 256 else None
    return None


@dataclass
class UserState:
    """Login-payload aggregate. Each field is overwritten wholesale on the next login frame."""
    characters: list[dict[str, Any]] = field(default_factory=list)
    savedata: list[dict[str, Any]] = field(default_factory=list)
    savedata_slot_entities: dict[str, Any] = field(default_factory=dict)
    savedata_teams: dict[str, Any] = field(default_factory=dict)
    team_presets: list[dict[str, Any]] = field(default_factory=list)
    teams: list[dict[str, Any]] = field(default_factory=list)
    archive_supporters: list[dict[str, Any]] = field(default_factory=list)
    card_archive: list[dict[str, Any]] = field(default_factory=list)


# (frame_key, expected_type, require_truthy). frame_key matches UserState attribute name.
_LOGIN_FIELDS: list[tuple[str, type, bool]] = [
    ("characters", list, False),
    ("savedata", list, False),
    ("savedata_slot_entities", dict, True),
    ("savedata_teams", dict, True),
    ("team_presets", list, False),
    ("teams", list, False),
    ("archive_supporters", list, False),
    ("card_archive", list, False),
]


class CaptureState:
    """In-memory capture data. Mutated by FrameRouter; read by Submitter."""

    def __init__(self, world_id_default: str | None) -> None:
        self.events: dict[str, dict[str, Any]] = {}
        self.attempts: dict[str, dict[str, Any]] = {}
        self.user_state = UserState()
        self.user_id: str | None = None
        self.world_id: str | None = world_id_default

    def update_login_field(self, key: str, value: Any) -> None:
        setattr(self.user_state, key, value)

    def set_event_summary(self, define_id: Any, summary: dict[str, Any]) -> None:
        normalized = _normalize_id(define_id)
        if normalized is None:
            logger.warning("Dropping event summary with non-scalar define_id: %r", define_id)
            return
        self.events[normalized] = summary

    def set_attempt(self, stage_id: Any, attempt: dict[str, Any]) -> None:
        normalized = _normalize_id(stage_id)
        if normalized is None:
            logger.warning("Dropping battle return with non-scalar stage_id: %r", stage_id)
            return
        self.attempts[normalized] = attempt

    def set_identity(self, user_id: str | None, world_id: str | None) -> None:
        if user_id and not self.user_id:
            self.user_id = user_id
        if world_id:
            self.world_id = world_id

    def try_resolve_user_id(self) -> None:
        # Sessions starting after login miss the user frame. user_id also
        # appears on every character/savedata row and event entity, so we
        # fall back to those.
        if self.user_id:
            return
        for src in (self.user_state.characters, self.user_state.savedata):
            if src and isinstance(src[0], dict) and src[0].get("user_id"):
                self.user_id = src[0]["user_id"]
                return
        for ev in self.events.values():
            entities = ev.get("entities")
            if not isinstance(entities, dict):
                continue
            for entity in entities.values():
                if isinstance(entity, dict) and entity.get("user_id"):
                    self.user_id = entity["user_id"]
                    return


class FrameRouter:
    """Dispatches a parsed JSON frame into CaptureState. No I/O."""

    def __init__(self, state: CaptureState) -> None:
        self._state = state

    def handle(self, frame: dict[str, Any]) -> bool:
        touched = False
        if self._is_event_summary(frame):
            self._capture_event_summary(frame)
            touched = True
        if self._is_battle_return(frame):
            self._capture_battle_return(frame)
            touched = True
        if self._capture_login_fields(frame):
            touched = True
        self._capture_identity(frame)
        return touched

    @staticmethod
    def _is_event_summary(frame: dict[str, Any]) -> bool:
        return (
            "define_id" in frame
            and "entities" in frame
            and "rank_percent" in frame
            and isinstance(frame.get("entities"), dict)
        )

    def _capture_event_summary(self, frame: dict[str, Any]) -> None:
        define_id = frame["define_id"]
        self._state.set_event_summary(define_id, {
            "define_id": define_id,
            "rank": frame.get("rank"),
            "rank_percent": frame.get("rank_percent"),
            "reward_count": frame.get("reward_count"),
            "entities": frame["entities"],
            "captured_at": datetime.now(timezone.utc).isoformat(),
        })

    @staticmethod
    def _is_battle_return(frame: dict[str, Any]) -> bool:
        return (
            "return_info" in frame
            and "stage_chars" in frame
            and "stage_id" in frame
            and "deck" in frame
        )

    def _capture_battle_return(self, frame: dict[str, Any]) -> None:
        sid = frame.get("stage_id")
        self._state.set_attempt(sid, {
            "stage_id": sid,
            "stage_type": frame.get("stage_type"),
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "return_info": frame.get("return_info"),
            "stage_chars": frame.get("stage_chars"),
            "stage_supporters": frame.get("stage_supporters"),
            "deck": frame.get("deck"),
            "mvp": frame.get("mvp"),
            "player": frame.get("player"),
            "relics": frame.get("relics"),
            "psychosis_chars": frame.get("psychosis_chars"),
            "savedata_result": frame.get("savedata_result"),
            "monster_archives": frame.get("monster_archives"),
        })

    def _capture_login_fields(self, frame: dict[str, Any]) -> bool:
        touched = False
        for key, expected_type, require_truthy in _LOGIN_FIELDS:
            value = frame.get(key)
            if not isinstance(value, expected_type):
                continue
            if require_truthy and not value:
                continue
            self._state.update_login_field(key, value)
            touched = True
        return touched

    def _capture_identity(self, frame: dict[str, Any]) -> None:
        user = frame.get("user")
        if isinstance(user, dict):
            self._state.set_identity(user.get("user_id"), user.get("world_id"))
        self._state.try_resolve_user_id()


SubmitStatus = Literal["success", "error", "rate_limited", "unauthorized"]


@dataclass
class SubmitResult:
    status: SubmitStatus
    message: str


@dataclass
class SubmissionHistory:
    submissions_sent: int = 0
    last_submit_at: str | None = None
    last_submit_status: SubmitStatus | None = None
    last_submit_message: str | None = None


class Submitter:
    """Debounced, single-flight POST of CaptureState to the server."""

    def __init__(self, config: Config, state: CaptureState) -> None:
        self._config = config
        self._state = state
        self._lock = threading.Lock()
        self._timer: threading.Timer | None = None
        self._inflight = False
        self.history = SubmissionHistory()
        # External hook so StatusWriter can refresh after each submit
        # without the Submitter taking a dependency on it.
        self._after_submit: Callable[[], None] | None = None

    def set_after_submit(self, hook: Callable[[], None]) -> None:
        self._after_submit = hook

    def schedule(self) -> None:
        if not self._config.submit_token:
            return
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
            t = threading.Timer(SUBMIT_DEBOUNCE_SECONDS, self._do_submit)
            t.daemon = True
            self._timer = t
            t.start()

    def flush(self) -> None:
        if not self._config.submit_token:
            return
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
            if not self._state.events and not self._state.attempts:
                return
        self._do_submit()

    def _do_submit(self) -> None:
        with self._lock:
            if self._inflight:
                return
            self._inflight = True
        try:
            payload = self._build_payload()
            result = self._validate_then_send(payload)
            self._record_outcome(result)
        finally:
            with self._lock:
                self._inflight = False
            if self._after_submit:
                self._after_submit()

    def _build_payload(self) -> dict[str, Any]:
        # Snapshot under the lock so the request body matches a consistent
        # state; asdict deep-copies the dataclass tree.
        with self._lock:
            return {
                "captured_at": datetime.now(timezone.utc).isoformat(),
                "user_id": self._state.user_id,
                "world_id": self._state.world_id,
                "events": list(self._state.events.values()),
                "attempts": list(self._state.attempts.values()),
                "user_state": asdict(self._state.user_state),
            }

    def _validate_then_send(self, payload: dict[str, Any]) -> SubmitResult:
        if not payload.get("user_id"):
            return SubmitResult("error", "Waiting for login frame to identify the account.")
        if not payload.get("events") and not payload.get("attempts"):
            return SubmitResult("error", "No event or battle frames captured yet.")
        return self._send(payload)

    def _send(self, payload: dict[str, Any]) -> SubmitResult:
        body = json.dumps(payload).encode("utf-8")
        # Debug aid: persist the latest attempted payload outside the per-session
        # run dir so the user can inspect what was captured even when submits
        # fail. Overwritten on every attempt; survives run.ps1's cleanup.
        self._write_last_payload_dump(body)
        req = urllib.request.Request(
            self._config.submit_url,
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {self._config.submit_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "czn-event-capture/2.0",
            },
        )
        ctx = ssl.create_default_context()
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
                self.history.submissions_sent += 1
                accepted = _count_accepted(resp.read())
                logger.info("submitted (%d accepted)", accepted)
                noun = "y" if accepted == 1 else "ies"
                return SubmitResult("success", f"Server accepted {accepted} entr{noun}.")
        except urllib.error.HTTPError as e:
            return self._classify_http_error(e)
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            logger.warning("submit failed: %s", e)
            return SubmitResult("error", f"Network: {e}")
        except Exception as e:
            logger.exception("submit failed (unexpected)")
            return SubmitResult("error", f"Unexpected: {e}")

    def _write_last_payload_dump(self, body: bytes) -> None:
        try:
            # output_dir is the per-session run dir
            # (%LOCALAPPDATA%\CZNEventCapture\snapshots\<ts>); the install dir
            # is its grandparent. Writing there means run.ps1's RunDir cleanup
            # leaves this file alone.
            install_dir = self._config.output_dir.parent.parent
            if not install_dir.exists():
                return
            # Pretty-print so the file is human-readable; the wire body is
            # already minified above, so we redo with indent here.
            decoded = json.loads(body.decode("utf-8"))
            (install_dir / "last_capture.json").write_text(
                json.dumps(decoded, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except Exception as e:
            logger.warning("Could not write last_capture.json: %s", e)

    def _classify_http_error(self, e: urllib.error.HTTPError) -> SubmitResult:
        status = e.code
        try:
            err_body = e.read().decode("utf-8", errors="replace")
        except Exception:
            err_body = ""
        logger.warning("submit failed: HTTP %d", status)
        if status == 401:
            return SubmitResult("unauthorized", "Pairing expired or revoked. Re-pair from the website.")
        if status == 429:
            return SubmitResult("rate_limited", "Server is rate-limiting. Will retry on next state change.")
        short = err_body[:200] if err_body else f"HTTP {status}"
        return SubmitResult("error", f"HTTP {status}: {short}")

    def _record_outcome(self, result: SubmitResult) -> None:
        with self._lock:
            self.history.last_submit_at = datetime.now(timezone.utc).isoformat()
            self.history.last_submit_status = result.status
            self.history.last_submit_message = result.message


def _count_accepted(body: bytes) -> int:
    try:
        parsed = json.loads(body.decode("utf-8"))
    except Exception:
        return 0
    accepted = parsed.get("accepted") if isinstance(parsed, dict) else None
    return len(accepted) if isinstance(accepted, list) else 0


class StatusWriter:
    """Writes status.json (polled by run.ps1)."""

    def __init__(self, config: Config, state: CaptureState, submitter: Submitter) -> None:
        self._config = config
        self._state = state
        self._submitter = submitter

    def write(self) -> None:
        h = self._submitter.history
        status = {
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "user_id": self._state.user_id,
            "world_id": self._state.world_id,
            "server_base": self._config.server_base,
            "is_official_server_base": self._config.is_official_server_base,
            "events_captured": list(self._state.events.keys()),
            "attempts_captured": sorted(self._state.attempts.keys()),
            "has_savedata": len(self._state.user_state.savedata) > 0,
            "character_count": len(self._state.user_state.characters),
            "savedata_count": len(self._state.user_state.savedata),
            "submissions_sent": h.submissions_sent,
            "last_submit_at": h.last_submit_at,
            "last_submit_status": h.last_submit_status,
            "last_submit_message": h.last_submit_message,
        }
        self._config.status_file.write_text(json.dumps(status, indent=2), encoding="utf-8")


class UpstreamCertPinner:
    """TOFU pin for the reverse-proxy upstream cert.

    The proxy connects to upstream by IP after a hosts redirect, so
    mitmproxy can't verify the cert hostname and runs with --ssl-insecure.
    This pinner adds a second check: on tls_established_server it hashes
    the leaf cert (SHA-256 of DER) and compares against a per-region pin
    in cert-pins.json. First connection records the pin; subsequent
    connections verify. A mismatch flips `safe=False`, and the
    EventCapture facade then refuses to process any frame for the rest
    of the session.
    """

    def __init__(self, config: "Config") -> None:
        self._pin_file = config.output_dir / "cert-pins.json"
        self._region = config.world_id_default or "default"
        self._pins = self._load()
        self.safe = True

    def _load(self) -> dict[str, str]:
        if not self._pin_file.exists():
            return {}
        try:
            data = json.loads(self._pin_file.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except Exception:
            logger.warning("cert-pins.json is corrupt; treating as empty.")
            return {}

    def _save(self) -> None:
        self._pin_file.write_text(json.dumps(self._pins, indent=2), encoding="utf-8")

    def tls_established_server(self, data) -> None:
        try:
            chain = data.conn.certificate_list
            if not chain:
                raise RuntimeError("upstream presented no certificate")
            cert = chain[0]
            actual = hashlib.sha256(_cert_to_der(cert)).hexdigest()
        except Exception as e:
            logger.error("Could not extract upstream cert: %s. Refusing to submit captures.", e)
            self.safe = False
            return

        expected = self._pins.get(self._region)
        if expected is None:
            self._pins[self._region] = actual
            self._save()
            logger.warning(
                "Recorded upstream cert pin for region '%s': %s... "
                "Future sessions verify against this. If the cert legitimately "
                "rotates, delete %s and rerun.",
                self._region, actual[:16], self._pin_file.name,
            )
            return
        if expected == actual:
            logger.info("Upstream cert pin OK for '%s' (%s...).", self._region, actual[:16])
            return
        logger.error(
            "UPSTREAM CERT FINGERPRINT MISMATCH for region '%s'. Expected %s..., got %s.... "
            "Refusing to submit any captures this session. If the cert legitimately rotated, "
            "delete %s and rerun; otherwise your network may be MITM'd.",
            self._region, expected[:16], actual[:16], self._pin_file.name,
        )
        self.safe = False


def _cert_to_der(cert: Any) -> bytes:
    # mitmproxy.certs.Cert.to_cryptography() returns the underlying
    # cryptography.x509.Certificate, whose .public_bytes(DER) is a
    # stable byte representation suitable for hashing across mitmproxy
    # versions. Falls back to to_pem() if the API ever differs.
    from cryptography.hazmat.primitives import serialization

    to_crypto = getattr(cert, "to_cryptography", None)
    if callable(to_crypto):
        return to_crypto().public_bytes(encoding=serialization.Encoding.DER)
    to_pem = getattr(cert, "to_pem", None)
    if callable(to_pem):
        return to_pem()
    return bytes(cert)


class DebugLogger:
    """Writes debug.jsonl when CZN_EVENT_DEBUG=1; redacts sensitive keys unless CZN_EVENT_UNSAFE_DEBUG=1."""

    def __init__(self, config: Config) -> None:
        self._config = config
        self._fh = self._open()

    def _open(self):
        if not self._config.debug:
            return None
        fh = self._config.debug_file.open("w", encoding="utf-8")
        logger.info("DEBUG mode: writing %s", self._config.debug_file.name)
        return fh

    def write_frame(self, frame: dict[str, Any]) -> None:
        if not self._fh:
            return
        self._fh.write(json.dumps({
            "ts": datetime.now(timezone.utc).isoformat(),
            "keys": list(frame.keys()),
            "unsafe_unredacted": self._config.unsafe_debug,
            "data": self._redact(frame),
        }) + "\n")
        self._fh.flush()

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None

    def _redact(self, value: Any, depth: int = 0) -> Any:
        if self._config.unsafe_debug:
            return value
        if depth > 12:
            return "<redacted:depth>"
        if isinstance(value, dict):
            out: dict[str, Any] = {}
            for key, item in value.items():
                key_text = str(key)
                if is_sensitive_debug_key(key_text):
                    out[key_text] = "<redacted>"
                else:
                    out[key_text] = self._redact(item, depth + 1)
            return out
        if isinstance(value, list):
            return [self._redact(item, depth + 1) for item in value]
        return value


class ShutdownWatcher:
    """Watches for a shutdown.flag file and triggers a clean shutdown.

    run.ps1 cannot send Ctrl-Break to a hidden child process on Windows, and
    Stop-Process -Force terminates without running addon `done()`, dropping any
    in-flight or pending submissions. The watcher gives us a portable signal
    channel: PowerShell creates the flag file, this thread sees it and runs
    a final submit synchronously BEFORE asking mitmproxy to shut down.

    Why flush before shutdown instead of in `done()`: on mitmproxy 12 the
    `done()` hook runs during asyncio loop teardown, and outbound urllib
    POSTs from inside that window have been observed to fail with
    WinError 10053 ('an established connection was aborted by the software
    in your host machine') because the loop is closing process-level sockets.
    Doing the POST from this watcher thread, while the loop is still fully
    alive, keeps the submit on a stable network stack.
    """

    POLL_INTERVAL_SECONDS = 0.5

    def __init__(self, config: Config) -> None:
        self._flag_file = config.output_dir / "shutdown.flag"
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        # Best-effort: clear any stale flag from a prior run before starting.
        try:
            if self._flag_file.exists():
                self._flag_file.unlink()
        except OSError:
            pass

    def start(self, master: Any, submitter: "Submitter") -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._watch,
            args=(master, submitter),
            daemon=True,
            name="czn-shutdown-watcher",
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _watch(self, master: Any, submitter: "Submitter") -> None:
        while not self._stop.is_set():
            if self._flag_file.exists():
                logger.info("Shutdown flag detected; flushing then shutting down.")
                try:
                    submitter.flush()
                except Exception as e:
                    logger.warning("pre-shutdown flush failed: %s", e)
                try:
                    master.shutdown()
                except Exception as e:
                    logger.warning("master.shutdown failed: %s", e)
                return
            time.sleep(self.POLL_INTERVAL_SECONDS)

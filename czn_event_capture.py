"""
mitmproxy addon that captures Chaos Zero Nightmare event data from
WebSocket traffic and submits it directly to cznmetadecks.com over HTTPS.

Targets a specific shape of event frames:

  - Event summary frame (user opens the event UI or finishes an attempt):
      { res, define_id, rank_percent, rank, reward_count, entities, ... }
    entities = { list_id: { best_score, star_count, deployed_heroes, ... } }

  - Battle return frame (user starts then escapes/completes an attempt):
      { res, return_info, stage_chars, stage_supporters, deck, mvp, player,
        stage_id, ... }

  - Login payloads carrying the user's saved builds and characters.

The addon never persists the captured payload to disk. State is held in
memory and POSTed directly to /api/events/submissions on each meaningful
state change, debounced so a flurry of frames produces a single submit. A
final flush runs on shutdown. This closes the on-disk tampering window of
the previous read-then-submit design.

Files in OUTPUT_DIR:
  - status.json   live counters + last submit status (polled by run.ps1)
  - debug.jsonl   every decoded WS frame (only if CZN_EVENT_DEBUG=1)

Environment variables:
  CZN_EVENT_OUTPUT_DIR    where status.json + debug.jsonl land
  CZN_EVENT_DICT_PATH     path to zstd_dictionary.bin
  CZN_EVENT_WORLD_ID      world_live_global | world_live_asia
  CZN_EVENT_DEBUG         1 to enable debug.jsonl
  CZN_EVENT_UNSAFE_DEBUG  1 to keep unredacted debug payloads
  CZN_EVENT_TOKEN         bearer token from device pairing (required)
  CZN_EVENT_SERVER_BASE   server base URL (default https://cznmetadecks.com)
  CZN_EVENT_ALLOW_CUSTOM_SERVER_BASE 1 to permit a non-official server base
"""
from __future__ import annotations

import gzip
import json
import os
import ssl
import threading
import urllib.error
import urllib.parse
import urllib.request
import zlib
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import zstandard as zstd
    HAS_ZSTD = True
except ImportError:
    zstd = None  # type: ignore
    HAS_ZSTD = False


HERE = Path(__file__).resolve().parent
OUTPUT_DIR = Path(os.environ.get("CZN_EVENT_OUTPUT_DIR", str(HERE)))
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

DICT_PATH = Path(os.environ.get("CZN_EVENT_DICT_PATH", str(HERE / "zstd_dictionary.bin")))
DEBUG = os.environ.get("CZN_EVENT_DEBUG") == "1"
UNSAFE_DEBUG = os.environ.get("CZN_EVENT_UNSAFE_DEBUG") == "1"

# Runner passes the selected region via env var so world_id can be populated
# even when the capture session starts after login (no "user" frame on wire).
WORLD_ID_DEFAULT = os.environ.get("CZN_EVENT_WORLD_ID") or None

# Direct-submit credentials. Set by run.ps1 before launching mitmdump. Without
# a token the addon still captures + writes status.json, so dev/diagnostic
# runs without a paired account work, but no submission is attempted.
SUBMIT_TOKEN = os.environ.get("CZN_EVENT_TOKEN") or None
SUBMIT_SERVER_BASE = (os.environ.get("CZN_EVENT_SERVER_BASE") or "https://cznmetadecks.com").rstrip("/")
ALLOW_CUSTOM_SERVER_BASE = os.environ.get("CZN_EVENT_ALLOW_CUSTOM_SERVER_BASE") == "1"
OFFICIAL_SERVER_BASE = "https://cznmetadecks.com"


def _validate_submit_server_base(value: str) -> str:
    parsed = urllib.parse.urlparse(value)
    if not parsed.scheme or not parsed.hostname:
        raise RuntimeError(f"Invalid CZN_EVENT_SERVER_BASE: {value!r}")
    is_localhost = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "https" and not (ALLOW_CUSTOM_SERVER_BASE and is_localhost):
        raise RuntimeError("CZN_EVENT_SERVER_BASE must use https unless explicitly using localhost development.")
    normalized = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
    if normalized != OFFICIAL_SERVER_BASE and not ALLOW_CUSTOM_SERVER_BASE:
        raise RuntimeError("Refusing custom CZN_EVENT_SERVER_BASE without CZN_EVENT_ALLOW_CUSTOM_SERVER_BASE=1.")
    return normalized


SUBMIT_SERVER_BASE = _validate_submit_server_base(SUBMIT_SERVER_BASE)
SUBMIT_URL = f"{SUBMIT_SERVER_BASE}/api/events/submissions"

# Debounce window. After each meaningful frame, schedule a submit this far
# in the future; subsequent frames reset the timer. Keeps us under the
# server's 10/hour per-token rate limit during a normal session (5–10
# bosses + a few summary refreshes typically collapses to one or two
# submissions).
SUBMIT_DEBOUNCE_SECONDS = 3.0

STATUS_FILE = OUTPUT_DIR / "status.json"
DEBUG_FILE = OUTPUT_DIR / "debug.jsonl"

SENSITIVE_DEBUG_KEYS = {
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
}


class EventCapture:
    def __init__(self) -> None:
        # Latest seen event summary, keyed by define_id.
        self.events: dict[str, dict[str, Any]] = {}

        # Battle attempts keyed by stage_id; re-attempts overwrite so only the
        # freshest result per boss is preserved.
        self.attempts: dict[int, dict[str, Any]] = {}

        # Login-time user state that lets the website render builds.
        self.characters: list[dict[str, Any]] = []
        self.savedata: list[dict[str, Any]] = []
        self.savedata_slot_entities: dict[str, Any] = {}
        self.savedata_teams: dict[str, Any] = {}
        self.team_presets: list[dict[str, Any]] = []
        self.teams: list[dict[str, Any]] = []
        self.archive_supporters: list[dict[str, Any]] = []
        self.card_archive: list[dict[str, Any]] = []

        self.user_id: str | None = None
        self.world_id: str | None = WORLD_ID_DEFAULT

        self.zstd_dctx: Any = None
        self.debug_fh = None

        # Submission state — surfaced to run.ps1 via status.json.
        self._state_lock = threading.Lock()
        self._submit_timer: threading.Timer | None = None
        self._submit_inflight = False
        self.submissions_sent = 0
        self.last_submit_at: str | None = None
        self.last_submit_status: str | None = None  # success | error | rate_limited | unauthorized
        self.last_submit_message: str | None = None

        if HAS_ZSTD and DICT_PATH.exists():
            try:
                raw = DICT_PATH.read_bytes()
                d = zstd.ZstdCompressionDict(raw)
                self.zstd_dctx = zstd.ZstdDecompressor(dict_data=d)
                self._log(f"Loaded zstd dictionary ({len(raw)} bytes)")
            except Exception as e:
                self._log(f"WARN: failed to load zstd dictionary: {e}")
        else:
            self._log(f"WARN: zstandard={HAS_ZSTD}, dict_exists={DICT_PATH.exists()}")

        if DEBUG:
            self.debug_fh = DEBUG_FILE.open("w", encoding="utf-8")
            self._log(f"DEBUG mode: writing {DEBUG_FILE.name}")

        if not SUBMIT_TOKEN:
            self._log("WARN: CZN_EVENT_TOKEN not set; capture will run but nothing will be submitted.")

        self._write_status()
        self._log(f"CZN event capture ready. Output dir: {OUTPUT_DIR}")

    @staticmethod
    def _log(msg: str) -> None:
        print(f"[czn-event] {msg}", flush=True)

    def _decode(self, raw: bytes) -> str | None:
        if not raw:
            return None
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            pass
        if self.zstd_dctx is not None:
            try:
                return self.zstd_dctx.decompress(raw).decode("utf-8")
            except Exception:
                pass
        if HAS_ZSTD:
            try:
                return zstd.ZstdDecompressor().decompress(raw).decode("utf-8")
            except Exception:
                pass
        try:
            return gzip.decompress(raw).decode("utf-8")
        except Exception:
            pass
        for wbits in (15, -15, 31, 47):
            try:
                return zlib.decompress(raw, wbits).decode("utf-8")
            except Exception:
                pass
        return None

    def _redact_for_debug(self, value: Any, depth: int = 0) -> Any:
        if UNSAFE_DEBUG:
            return value
        if depth > 12:
            return "<redacted:depth>"
        if isinstance(value, dict):
            redacted: dict[str, Any] = {}
            for key, item in value.items():
                key_text = str(key)
                lowered = key_text.lower()
                if (
                    lowered in SENSITIVE_DEBUG_KEYS
                    or "token" in lowered
                    or "authorization" in lowered
                    or "email" in lowered
                    or "fingerprint" in lowered
                ):
                    redacted[key_text] = "<redacted>"
                else:
                    redacted[key_text] = self._redact_for_debug(item, depth + 1)
            return redacted
        if isinstance(value, list):
            return [self._redact_for_debug(item, depth + 1) for item in value]
        return value

    def websocket_message(self, flow) -> None:
        msg = flow.websocket.messages[-1]
        if msg.from_client:
            return
        text = msg.text if msg.is_text else self._decode(msg.content)
        if text is None:
            return
        try:
            parsed = json.loads(text)
        except ValueError:
            return

        frames = parsed if isinstance(parsed, list) else [parsed]
        touched = False
        for frame in frames:
            if not isinstance(frame, dict):
                continue
            if self.debug_fh:
                self.debug_fh.write(json.dumps({
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "keys": list(frame.keys()),
                    "unsafe_unredacted": UNSAFE_DEBUG,
                    "data": self._redact_for_debug(frame),
                }) + "\n")
                self.debug_fh.flush()
            if self._handle_frame(frame):
                touched = True

        if touched:
            self._schedule_submit()
        self._write_status()

    def _handle_frame(self, frame: dict[str, Any]) -> bool:
        touched = False

        # ---------------- event summary frame ----------------
        if (
            "define_id" in frame
            and "entities" in frame
            and "rank_percent" in frame
            and isinstance(frame.get("entities"), dict)
        ):
            define_id = frame["define_id"]
            self.events[define_id] = {
                "define_id": define_id,
                "rank": frame.get("rank"),
                "rank_percent": frame.get("rank_percent"),
                "reward_count": frame.get("reward_count"),
                "entities": frame["entities"],
                "captured_at": datetime.now(timezone.utc).isoformat(),
            }
            touched = True

        # ---------------- battle return frame ----------------
        if (
            "return_info" in frame
            and "stage_chars" in frame
            and "stage_id" in frame
            and "deck" in frame
        ):
            sid = frame.get("stage_id")
            self.attempts[sid] = {
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
            }
            touched = True

        # ---------------- login payload pieces ----------------
        if isinstance(frame.get("characters"), list):
            self.characters = frame["characters"]
            touched = True
        if isinstance(frame.get("savedata"), list):
            self.savedata = frame["savedata"]
            touched = True
        if isinstance(frame.get("savedata_slot_entities"), dict) and frame["savedata_slot_entities"]:
            self.savedata_slot_entities = frame["savedata_slot_entities"]
            touched = True
        if isinstance(frame.get("savedata_teams"), dict) and frame["savedata_teams"]:
            self.savedata_teams = frame["savedata_teams"]
            touched = True
        if isinstance(frame.get("team_presets"), list):
            self.team_presets = frame["team_presets"]
            touched = True
        if isinstance(frame.get("teams"), list):
            self.teams = frame["teams"]
            touched = True
        if isinstance(frame.get("archive_supporters"), list):
            self.archive_supporters = frame["archive_supporters"]
            touched = True
        if isinstance(frame.get("card_archive"), list):
            self.card_archive = frame["card_archive"]
            touched = True

        # ---------------- identity ----------------
        user = frame.get("user")
        if isinstance(user, dict):
            if not self.user_id and user.get("user_id"):
                self.user_id = user["user_id"]
            if user.get("world_id"):
                self.world_id = user["world_id"]

        # Fallbacks: user_id shows up on every character/savedata row, and — most
        # reliably — on every event entity. Capture sessions that start after
        # login won't see the login frame, so the event-entity path is the
        # canonical fallback.
        if not self.user_id:
            for src in (self.characters, self.savedata):
                if src:
                    first = src[0] if isinstance(src, list) else None
                    if isinstance(first, dict) and first.get("user_id"):
                        self.user_id = first["user_id"]
                        break
        if not self.user_id:
            for ev in self.events.values():
                entities = ev.get("entities")
                if not isinstance(entities, dict):
                    continue
                for entity in entities.values():
                    if isinstance(entity, dict) and entity.get("user_id"):
                        self.user_id = entity["user_id"]
                        break
                if self.user_id:
                    break

        return touched

    # ---------------- submission ----------------

    def _build_payload(self) -> dict[str, Any]:
        # Snapshot under the lock so the request body matches a consistent
        # state even if a new frame arrives mid-build.
        with self._state_lock:
            return {
                "captured_at": datetime.now(timezone.utc).isoformat(),
                "user_id": self.user_id,
                "world_id": self.world_id,
                "events": deepcopy(list(self.events.values())),
                "attempts": deepcopy(list(self.attempts.values())),
                "user_state": {
                    "characters": deepcopy(self.characters),
                    "savedata": deepcopy(self.savedata),
                    "savedata_slot_entities": deepcopy(self.savedata_slot_entities),
                    "savedata_teams": deepcopy(self.savedata_teams),
                    "team_presets": deepcopy(self.team_presets),
                    "teams": deepcopy(self.teams),
                    "archive_supporters": deepcopy(self.archive_supporters),
                    "card_archive": deepcopy(self.card_archive),
                },
            }

    def _schedule_submit(self) -> None:
        if not SUBMIT_TOKEN:
            return
        with self._state_lock:
            if self._submit_timer is not None:
                self._submit_timer.cancel()
            t = threading.Timer(SUBMIT_DEBOUNCE_SECONDS, self._do_submit)
            t.daemon = True
            self._submit_timer = t
            t.start()

    def _flush_submit(self) -> None:
        """Cancel any pending debounced submit and run one synchronously.

        Called from done() so the final state of a session is sent before
        the proxy exits. Skipped if no meaningful state was captured (no
        events and no attempts) — there's nothing the server can use.
        """
        if not SUBMIT_TOKEN:
            return
        with self._state_lock:
            if self._submit_timer is not None:
                self._submit_timer.cancel()
                self._submit_timer = None
            if not self.events and not self.attempts:
                return
        self._do_submit()

    def _do_submit(self) -> None:
        # Single-flight: if a submit is already running, skip; another submit
        # will be scheduled by the next touched frame anyway.
        with self._state_lock:
            if self._submit_inflight:
                return
            self._submit_inflight = True

        try:
            payload = self._build_payload()
            if not payload.get("user_id"):
                # Nothing to identify the player. Wait for a frame that does.
                self._record_submit_status("error", "Waiting for login frame to identify the account.")
                return
            if not payload.get("events") and not payload.get("attempts"):
                self._record_submit_status("error", "No event or battle frames captured yet.")
                return

            body = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                SUBMIT_URL,
                data=body,
                method="POST",
                headers={
                    "Authorization": f"Bearer {SUBMIT_TOKEN}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": "czn-event-capture/2.0",
                },
            )
            ctx = ssl.create_default_context()
            try:
                with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
                    self.submissions_sent += 1
                    try:
                        parsed = json.loads(resp.read().decode("utf-8"))
                    except Exception:
                        parsed = None
                    accepted = (parsed or {}).get("accepted") if isinstance(parsed, dict) else None
                    n = len(accepted) if isinstance(accepted, list) else 0
                    self._record_submit_status("success", f"Server accepted {n} entr{'y' if n == 1 else 'ies'}.")
                    self._log(f"submitted ({n} accepted)")
            except urllib.error.HTTPError as e:
                status = e.code
                try:
                    err_body = e.read().decode("utf-8", errors="replace")
                except Exception:
                    err_body = ""
                if status == 401:
                    self._record_submit_status("unauthorized", "Pairing expired or revoked. Re-pair from the website.")
                elif status == 429:
                    self._record_submit_status("rate_limited", "Server is rate-limiting. Will retry on next state change.")
                else:
                    short = err_body[:200] if err_body else f"HTTP {status}"
                    self._record_submit_status("error", f"HTTP {status}: {short}")
                self._log(f"submit failed: HTTP {status}")
            except (urllib.error.URLError, OSError, TimeoutError) as e:
                self._record_submit_status("error", f"Network: {e}")
                self._log(f"submit failed: {e}")
            except Exception as e:  # belt-and-suspenders against unexpected throws
                self._record_submit_status("error", f"Unexpected: {e}")
                self._log(f"submit failed (unexpected): {e}")
        finally:
            with self._state_lock:
                self._submit_inflight = False
            self._write_status()

    def _record_submit_status(self, status: str, message: str) -> None:
        with self._state_lock:
            self.last_submit_at = datetime.now(timezone.utc).isoformat()
            self.last_submit_status = status
            self.last_submit_message = message

    # ---------------- status file ----------------

    def _write_status(self) -> None:
        with self._state_lock:
            status = {
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "user_id": self.user_id,
                "world_id": self.world_id,
                "events_captured": list(self.events.keys()),
                "attempts_captured": sorted(self.attempts.keys()),
                "has_savedata": len(self.savedata) > 0,
                "character_count": len(self.characters),
                "savedata_count": len(self.savedata),
                "submissions_sent": self.submissions_sent,
                "last_submit_at": self.last_submit_at,
                "last_submit_status": self.last_submit_status,
                "last_submit_message": self.last_submit_message,
            }
        STATUS_FILE.write_text(json.dumps(status, indent=2), encoding="utf-8")

    def done(self) -> None:
        # Final flush — sends the freshest captured state before the proxy
        # exits. mitmproxy invokes done() during graceful shutdown.
        try:
            self._flush_submit()
        finally:
            self._write_status()
            if self.debug_fh:
                self.debug_fh.close()
            self._log(
                f"Capture finished. {len(self.events)} events, {len(self.attempts)} attempts, "
                f"{len(self.characters)} characters, {len(self.savedata)} savedata entries, "
                f"{self.submissions_sent} submission(s)."
            )


addons = [EventCapture()]

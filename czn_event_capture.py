"""
mitmproxy addon. Captures Chaos Zero Nightmare event-summary, battle-return,
and login frames from WebSocket traffic and POSTs them to cznmetadecks.com.

Capture logic lives in `_czn_capture_lib.py` as focused classes; this file
is the thin entrypoint mitmproxy loads via `-s czn_event_capture.py`.

Outputs (in CZN_EVENT_OUTPUT_DIR, default = this dir):
  status.json   live counters + last submit status (run.ps1 polls this)
  debug.jsonl   redacted decoded WS frames, only when CZN_EVENT_DEBUG=1

Environment:
  CZN_EVENT_OUTPUT_DIR    where status.json + debug.jsonl land
  CZN_EVENT_DICT_PATH     path to zstd_dictionary.bin
  CZN_EVENT_WORLD_ID      world_live_global | world_live_asia
  CZN_EVENT_DEBUG         1 to enable debug.jsonl
  CZN_EVENT_UNSAFE_DEBUG  1 to keep unredacted debug payloads
  CZN_EVENT_TOKEN         bearer token from device pairing (required to submit)
  CZN_EVENT_SERVER_BASE   server base URL (default https://cznmetadecks.com)
  CZN_EVENT_ALLOW_CUSTOM_SERVER_BASE  1 to permit a non-official server base
"""
from __future__ import annotations

import json

from _czn_capture_lib import (
    CaptureState,
    Config,
    DebugLogger,
    FrameDecoder,
    FrameRouter,
    StatusWriter,
    Submitter,
    logger,
)


class EventCapture:
    def __init__(self) -> None:
        self._config = Config.from_env()
        self._state = CaptureState(world_id_default=self._config.world_id_default)
        self._decoder = FrameDecoder(self._config)
        self._router = FrameRouter(self._state)
        self._submitter = Submitter(self._config, self._state)
        self._status = StatusWriter(self._config, self._state, self._submitter)
        self._debug = DebugLogger(self._config)
        self._submitter.set_after_submit(self._status.write)

        if not self._config.submit_token:
            logger.warning(
                "CZN_EVENT_TOKEN not set; capture will run but nothing will be submitted."
            )
        if not self._config.is_official_server_base:
            logger.warning(
                "Non-official server base in use: %s. Captures + token will go to this server, "
                "NOT cznmetadecks.com. Stop now if this was not intended.",
                self._config.server_base,
            )
        self._status.write()
        logger.info("CZN event capture ready. Output dir: %s", self._config.output_dir)

    def websocket_message(self, flow) -> None:
        msg = flow.websocket.messages[-1]
        if msg.from_client:
            return
        text = msg.text if msg.is_text else self._decoder.decode(msg.content)
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
            self._debug.write_frame(frame)
            if self._router.handle(frame):
                touched = True

        if touched:
            self._submitter.schedule()
        self._status.write()

    def done(self) -> None:
        try:
            self._submitter.flush()
        finally:
            self._status.write()
            self._debug.close()
            self._log_finished()

    def _log_finished(self) -> None:
        s = self._state
        h = self._submitter.history
        logger.info(
            "Capture finished. %d events, %d attempts, %d characters, "
            "%d savedata entries, %d submission(s).",
            len(s.events),
            len(s.attempts),
            len(s.user_state.characters),
            len(s.user_state.savedata),
            h.submissions_sent,
        )


addons = [EventCapture()]

"""Wire protocol helpers for the ZeroShield daemon.

The daemon speaks newline-delimited JSON over a Unix stream socket::

    request   {"id": 1, "method": "status", "params": {}}
    response  {"id": 1, "ok": true,  "result": {...}}
              {"id": 1, "ok": false, "error": "..."}
    event     {"event": {...}}

Responses and events may be interleaved on the same connection.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional, Union


def encode_request(
    request_id: int, method: str, params: Optional[Dict[str, Any]] = None
) -> bytes:
    """Serialize a request frame (newline terminated)."""
    payload = {"id": request_id, "method": method, "params": params or {}}
    return (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")


def parse_frame(line: Union[str, bytes]) -> Dict[str, Any]:
    """Parse one newline-delimited frame into a dict."""
    if isinstance(line, bytes):
        line = line.decode("utf-8")
    return json.loads(line)


def classify(frame: Dict[str, Any]) -> str:
    """Return ``"event"``, ``"response"`` or ``"unknown"`` for a frame."""
    if "event" in frame:
        return "event"
    if "id" in frame and ("ok" in frame or "error" in frame):
        return "response"
    return "unknown"

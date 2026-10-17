"""ZeroShield daemon client (pure Python).

Mirrors the socket resolution used by the Rust CLI so scripts and, later,
plugins can talk to ``zeroshieldd`` without shelling out.
"""

from __future__ import annotations

import itertools
import os
import socket
from typing import Any, Dict, Iterator, Optional

from .protocol import classify, encode_request, parse_frame


class ZeroShieldError(RuntimeError):
    """Raised when the daemon answers with an error frame."""


class DaemonUnavailable(ZeroShieldError):
    """Raised when the daemon socket cannot be reached."""


def default_socket_path() -> str:
    """Resolve the daemon socket the same way the Rust client does.

    Order: ``$ZS_SOCKET`` > ``$XDG_RUNTIME_DIR/zeroshield/zeroshieldd.sock``
    > ``/run/zeroshield/zeroshieldd.sock`` (root)
    > ``/tmp/zeroshield-$UID/zeroshieldd.sock``.
    """
    explicit = os.environ.get("ZS_SOCKET")
    if explicit:
        return explicit
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if runtime and os.path.isabs(runtime):
        return os.path.join(runtime, "zeroshield", "zeroshieldd.sock")
    if os.geteuid() == 0:
        return "/run/zeroshield/zeroshieldd.sock"
    return f"/tmp/zeroshield-{os.geteuid()}/zeroshieldd.sock"


class Client:
    """Blocking Unix-socket client for ``zeroshieldd``.

    Usage::

        with Client() as zs:
            print(zs.status())
    """

    def __init__(self, path: Optional[str] = None, timeout: float = 30.0):
        self.path = path or default_socket_path()
        self.timeout = timeout
        self._sock: Optional[socket.socket] = None
        self._ids = itertools.count(1)
        self._buffer = b""

    # ------------------------------------------------------------ lifecycle

    def connect(self) -> "Client":
        if self._sock is not None:
            return self
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self.path)
        except OSError as exc:
            sock.close()
            raise DaemonUnavailable(
                f"cannot reach zeroshieldd at {self.path}: {exc}"
            ) from exc
        self._sock = sock
        return self

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None
                self._buffer = b""

    def __enter__(self) -> "Client":
        return self.connect()

    def __exit__(self, *exc_info: Any) -> None:
        self.close()

    # -------------------------------------------------------------- framing

    def _read_frame(self) -> Dict[str, Any]:
        if self._sock is None:
            raise ZeroShieldError("client is not connected")
        while b"\n" not in self._buffer:
            chunk = self._sock.recv(65536)
            if not chunk:
                raise DaemonUnavailable("daemon closed the connection")
            self._buffer += chunk
        line, self._buffer = self._buffer.split(b"\n", 1)
        return parse_frame(line)

    # ------------------------------------------------------------------ api

    def call(self, method: str, params: Optional[Dict[str, Any]] = None) -> Any:
        """Send a request, skipping event frames, and return ``result``."""
        self.connect()
        request_id = next(self._ids)
        assert self._sock is not None
        self._sock.sendall(encode_request(request_id, method, params))
        while True:
            frame = self._read_frame()
            kind = classify(frame)
            if kind == "event":
                continue
            if kind != "response":
                continue
            if frame.get("ok"):
                return frame.get("result")
            raise ZeroShieldError(frame.get("error", "unknown daemon error"))

    def watch(self) -> Iterator[Dict[str, Any]]:
        """Start the event stream and yield raw event dicts until disconnect."""
        self.call("watch.start")
        while True:
            frame = self._read_frame()
            if "event" in frame:
                yield frame["event"]

    # ------------------------------------------------------------ shortcuts

    def status(self) -> Dict[str, Any]:
        return self.call("status")

    def modules(self) -> Dict[str, Any]:
        return self.call("modules")

    def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Run a scan and return the final report (events are skipped)."""
        params: Dict[str, Any] = {"target": target}
        if options:
            params["options"] = options
        return self.call("scan.run", params)

    def proc_list(self, min_score: int = 0) -> Dict[str, Any]:
        return self.call("proc.list", {"min_score": min_score})

    def quarantine_list(self) -> Dict[str, Any]:
        return self.call("quarantine.list")

    def quarantine_restore(self, entry_id: int) -> Dict[str, Any]:
        return self.call("quarantine.restore", {"id": entry_id})

    def quarantine_purge(self, entry_id: int) -> Dict[str, Any]:
        return self.call("quarantine.purge", {"id": entry_id})

    def events(self, limit: int = 20) -> Dict[str, Any]:
        return self.call("events.list", {"limit": limit})

    def findings(self, limit: int = 50) -> Dict[str, Any]:
        return self.call("findings.list", {"limit": limit})

    def rules_list(self) -> Dict[str, Any]:
        return self.call("rules.list")

    def net_status(self) -> Dict[str, Any]:
        return self.call("net.status")

    def net_audit(self, targets: list) -> Dict[str, Any]:
        return self.call("net.audit", {"targets": targets})

    def watch_fs_start(
        self,
        paths: list,
        quarantine: bool = False,
        recursive: bool = True,
        debounce_ms: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Start a real-time watch session (inotify) in the daemon."""
        params: Dict[str, Any] = {
            "paths": paths,
            "quarantine": quarantine,
            "recursive": recursive,
        }
        if debounce_ms is not None:
            params["debounce_ms"] = debounce_ms
        return self.call("watch.fs.start", params)

    def watch_fs_stop(self, paths: Optional[list] = None) -> Dict[str, Any]:
        """Stop watch sessions: every session, or only those covering ``paths``."""
        params: Dict[str, Any] = {}
        if paths:
            params["paths"] = paths
        return self.call("watch.fs.stop", params)

    def watch_fs_list(self) -> Dict[str, Any]:
        """List active real-time watch sessions."""
        return self.call("watch.fs.list")

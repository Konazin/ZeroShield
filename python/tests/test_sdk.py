"""Unit tests for the ZeroShield Python SDK (no daemon required)."""

from __future__ import annotations

import json
import os
import socket
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zeroshield_sdk import (  # noqa: E402
    Client,
    DaemonUnavailable,
    ZeroShieldError,
    classify,
    encode_request,
    parse_frame,
)
from zeroshield_sdk.client import default_socket_path  # noqa: E402


class ProtocolTests(unittest.TestCase):
    def test_encode_request_is_newline_terminated(self) -> None:
        raw = encode_request(7, "status", {"a": 1})
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(
            json.loads(raw.decode()),
            {"id": 7, "method": "status", "params": {"a": 1}},
        )

    def test_parse_frame_accepts_bytes(self) -> None:
        frame = parse_frame(b'{"event": {"type": "info"}}')
        self.assertEqual(classify(frame), "event")

    def test_classify_response(self) -> None:
        self.assertEqual(classify({"id": 1, "ok": True, "result": {}}), "response")
        self.assertEqual(classify({"id": 1, "ok": False, "error": "x"}), "response")
        self.assertEqual(classify({"weird": True}), "unknown")

    def test_socket_path_env_override(self) -> None:
        old = os.environ.get("ZS_SOCKET")
        os.environ["ZS_SOCKET"] = "/tmp/custom.sock"
        try:
            self.assertEqual(default_socket_path(), "/tmp/custom.sock")
        finally:
            if old is None:
                os.environ.pop("ZS_SOCKET", None)
            else:
                os.environ["ZS_SOCKET"] = old


class FakeDaemon(threading.Thread):
    """One-connection fake daemon replaying canned frames per request."""

    def __init__(self, path: str, script):
        super().__init__(daemon=True)
        self.path = path
        self.script = script
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(path)
        self.sock.listen(1)

    def run(self) -> None:
        try:
            conn, _ = self.sock.accept()
        except OSError:
            return
        with conn:
            stream = conn.makefile("rwb")
            for responder in self.script:
                line = stream.readline()
                if not line:
                    break
                request = json.loads(line)
                for frame in responder(request):
                    stream.write(json.dumps(frame).encode() + b"\n")
                stream.flush()
        self.sock.close()


class ClientTests(unittest.TestCase):
    def _serve(self, script):
        tmp = tempfile.TemporaryDirectory()
        path = os.path.join(tmp.name, "test.sock")
        daemon = FakeDaemon(path, script)
        daemon.start()
        self.addCleanup(tmp.cleanup)
        return path, daemon

    def test_call_returns_result_skipping_events(self) -> None:
        def responder(request):
            self.assertEqual(request["method"], "status")
            return [
                {"event": {"type": "info", "message": "noise"}},
                {"id": request["id"], "ok": True, "result": {"version": "0.1.0"}},
            ]

        path, daemon = self._serve([responder])
        with Client(path=path) as client:
            self.assertEqual(client.status(), {"version": "0.1.0"})
        daemon.join(timeout=5)

    def test_error_frame_raises(self) -> None:
        def responder(request):
            return [{"id": request["id"], "ok": False, "error": "boom"}]

        path, daemon = self._serve([responder])
        with Client(path=path) as client:
            with self.assertRaises(ZeroShieldError):
                client.status()
        daemon.join(timeout=5)

    def test_scan_sends_options(self) -> None:
        seen = {}

        def responder(request):
            seen["method"] = request["method"]
            seen["params"] = request["params"]
            return [
                {
                    "id": request["id"],
                    "ok": True,
                    "result": {"verdict": "clean", "findings": []},
                }
            ]

        path, daemon = self._serve([responder])
        with Client(path=path) as client:
            report = client.scan("/tmp/x", options={"recursive": True})
        self.assertEqual(report["verdict"], "clean")
        self.assertEqual(seen["method"], "scan.run")
        self.assertEqual(seen["params"]["target"], "/tmp/x")
        self.assertEqual(seen["params"]["options"], {"recursive": True})
        daemon.join(timeout=5)

    def test_watch_streams_events(self) -> None:
        def responder(request):
            if request["method"] == "watch.start":
                return [
                    {"id": request["id"], "ok": True, "result": {"watching": True}},
                    {"event": {"type": "proc_alert", "pid": 42}},
                    {"event": {"type": "scan_finished"}},
                ]
            return [{"id": request["id"], "ok": True, "result": {}}]

        path, daemon = self._serve([responder])
        with Client(path=path) as client:
            events = []
            for event in client.watch():
                events.append(event)
                if len(events) == 2:
                    break
        self.assertEqual(events[0]["type"], "proc_alert")
        self.assertEqual(events[1]["type"], "scan_finished")
        daemon.join(timeout=5)

    def test_unreachable_socket_raises(self) -> None:
        client = Client(path="/tmp/zeroshield-does-not-exist.sock")
        with self.assertRaises(DaemonUnavailable):
            client.connect()


if __name__ == "__main__":
    unittest.main()

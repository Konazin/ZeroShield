"""Small command line front-end for the Python SDK.

It is intentionally thin: the Rust ``zeroshield`` binary is the primary CLI.
This entry point exists so scripts and containers without the Rust toolchain
can still query ``zeroshieldd``.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict

from .client import Client, DaemonUnavailable, ZeroShieldError


def _print_status(result: Dict[str, Any]) -> None:
    print(
        "ZeroShield {version} (daemon pid {pid}, uptime {uptime}s)".format(
            version=result.get("version", "?"),
            pid=result.get("pid", "?"),
            uptime=result.get("uptime_secs", "?"),
        )
    )
    print(
        "  socket      {socket}".format(socket=result.get("socket", "?"))
    )
    print(
        "  scans       {scans}   threats {threats}   rules {rules}".format(
            scans=result.get("scans", 0),
            threats=result.get("threats", 0),
            rules=result.get("rules", 0),
        )
    )


def _print_scan(report: Dict[str, Any]) -> None:
    verdict = report.get("verdict", "?")
    print(
        "scan {target} — {files} files, verdict {verdict}".format(
            target=report.get("target", "?"),
            files=report.get("files_scanned", 0),
            verdict=verdict,
        )
    )
    for finding in report.get("findings", []):
        print(
            "  [{}] score {} {}".format(
                finding.get("severity", "?"),
                finding.get("score", 0),
                finding.get("path", "?"),
            )
        )
        for detection in finding.get("detections", []):
            print(
                "      - {} {} (+{})".format(
                    detection.get("name", "?"),
                    detection.get("description", ""),
                    detection.get("score", 0),
                )
            )


def cmd_status(client: Client, args: argparse.Namespace) -> int:
    result = client.status()
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        _print_status(result)
    return 0


def cmd_scan(client: Client, args: argparse.Namespace) -> int:
    report = client.scan(args.path)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        _print_scan(report)
    return 2 if report.get("verdict") == "malicious" else 0


def cmd_proc(client: Client, args: argparse.Namespace) -> int:
    result = client.proc_list(min_score=args.min_score)
    processes = result.get("processes", [])
    if args.json:
        print(json.dumps(processes, indent=2))
        return 0
    if not processes:
        print("no processes above the given score")
        return 0
    for proc in processes:
        print(
            "pid {} score {} {:<24} {}".format(
                proc.get("pid", "?"),
                proc.get("score", 0),
                proc.get("name", "?"),
                proc.get("exe") or "-",
            )
        )
    return 0


def cmd_events(client: Client, args: argparse.Namespace) -> int:
    if args.follow:
        print("streaming daemon events (Ctrl+C to stop)")
        try:
            for event in client.watch():
                print(json.dumps(event, separators=(",", ":")))
        except KeyboardInterrupt:
            return 0
        return 0
    result = client.events(limit=args.limit)
    events = result.get("events", [])
    if args.json:
        print(json.dumps(events, indent=2))
        return 0
    if not events:
        print("no events recorded yet")
        return 0
    for event in events:
        print(
            "{ts} [{sev}] {kind} {payload}".format(
                ts=event.get("ts", "?"),
                sev=event.get("severity", "?"),
                kind=event.get("kind", "?"),
                payload=json.dumps(event.get("payload", {})),
            )
        )
    return 0


def cmd_net_status(client: Client, args: argparse.Namespace) -> int:
    result = client.net_status()
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("netguard (IPS)")
        print("  mode      {}".format(result.get("mode", "?")))
        print("  rules     {}".format(result.get("rule_count", 0)))
        print(
            "  nftables  {nft} / {root}".format(
                nft="available" if result.get("nft_available") else "missing",
                root="root" if result.get("is_root") else "unprivileged",
            )
        )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="zeroshield-sdk",
        description="Talk to the ZeroShield daemon (Python SDK front-end).",
    )
    parser.add_argument(
        "--socket",
        help="daemon socket path (defaults to $ZS_SOCKET or the XDG path)",
    )
    parser.add_argument("--json", action="store_true", help="raw JSON output")
    sub = parser.add_subparsers(dest="command", required=True)

    status = sub.add_parser("status", help="daemon status")
    status.set_defaults(func=cmd_status)

    scan = sub.add_parser("scan", help="scan a file or directory")
    scan.add_argument("path")
    scan.set_defaults(func=cmd_scan)

    proc = sub.add_parser("proc", help="list scored processes")
    proc.add_argument("--min-score", type=int, default=0)
    proc.set_defaults(func=cmd_proc)

    events = sub.add_parser("events", help="recent events")
    events.add_argument("-n", "--limit", type=int, default=20)
    events.add_argument("-f", "--follow", action="store_true")
    events.set_defaults(func=cmd_events)

    net = sub.add_parser("net", help="network guard")
    net.add_argument("action", nargs="?", default="status", choices=["status"])
    net.set_defaults(func=cmd_net_status)

    return parser


def main(argv: list = None) -> int:
    args = build_parser().parse_args(argv)
    client = Client(path=args.socket)
    try:
        client.connect()
    except DaemonUnavailable as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    try:
        return args.func(client, args)
    except ZeroShieldError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())

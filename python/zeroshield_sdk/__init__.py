"""ZeroShield Python SDK.

The package talks to the ZeroShield daemon (``zeroshieldd``) over its Unix
socket using the same newline-delimited JSON protocol as the Rust clients::

    from zeroshield_sdk import Client

    with Client() as zs:
        print(zs.status())
        report = zs.scan("/tmp/suspect.bin")

It is the foundation for the planned plugins/automation layer.
"""

from .client import Client, DaemonUnavailable, ZeroShieldError, default_socket_path
from .protocol import classify, encode_request, parse_frame

__all__ = [
    "Client",
    "DaemonUnavailable",
    "ZeroShieldError",
    "default_socket_path",
    "classify",
    "encode_request",
    "parse_frame",
]

__version__ = "0.1.0"

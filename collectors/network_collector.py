
import socket

import psutil

from platform_support.detector import detect_platform


class NetworkCollectionUnsupported(Exception):
    """Raised when network inspection is unsupported for a process."""


def _normalize_address(address):
    """Convert a socket address into a consistent dictionary."""

    if not address:
        return None

    return {
        "ip": address[0],
        "port": address[1],
    }


def collect_process_network(pid: int) -> list[dict]:
    """
    Collect internet socket connections belonging to a process.

    Raises:
        ValueError: If PID is invalid.
        NetworkCollectionUnsupported: If network inspection is unsupported.
        psutil.NoSuchProcess: If the process does not exist.
        psutil.AccessDenied: If connection inspection is denied.
    """

    if isinstance(pid, bool) or not isinstance(pid, int) or pid < 0:
        raise ValueError("PID must be a non-negative integer")

    if pid == 0:
        operating_system = detect_platform()

        if operating_system == "windows":
            raise NetworkCollectionUnsupported(
                "Network inspection is unsupported for Windows PID 0 "
                "(System Idle Process)"
            )

        raise ValueError("PID must be a positive integer")

    process = psutil.Process(pid)
    connections = process.net_connections(kind="inet")

    results = []

    for connection in connections:
        results.append({
            "pid": pid,
            "family": socket.AddressFamily(
                connection.family
            ).name,
            "type": socket.SocketKind(
                connection.type
            ).name,
            "local_address": _normalize_address(
                connection.laddr
            ),
            "remote_address": _normalize_address(
                connection.raddr
            ),
            "status": connection.status,
        })

    return results

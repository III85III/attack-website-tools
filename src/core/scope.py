"""Local-only target policy shared by active scan adapters."""
from __future__ import annotations

import ipaddress
import socket
from typing import Set, Tuple


def _machine_addresses() -> Set[str]:
    addresses = {"127.0.0.1", "::1"}
    try:
        for item in socket.getaddrinfo(socket.gethostname(), None):
            addresses.add(item[4][0].split("%", 1)[0])
    except OSError:
        pass
    try:
        import psutil

        for records in psutil.net_if_addrs().values():
            for record in records:
                value = record.address.split("%", 1)[0]
                try:
                    addresses.add(str(ipaddress.ip_address(value)))
                except ValueError:
                    continue
    except Exception:
        pass
    return addresses


def validate_local_host(host: str) -> Tuple[bool, str]:
    """Allow loopback or an exact address assigned to this machine only.

    Hostnames are accepted only when every currently resolved address is local.
    Network ranges, wildcards, and arbitrary remote destinations are rejected.
    """
    candidate = str(host or "").strip().strip("[]").rstrip(".")
    if not candidate or any(ch.isspace() for ch in candidate) or any(ch in candidate for ch in "/\\@?#"):
        return False, "Enter a single local host or IP address; ranges and URL paths are not allowed."

    machine_addresses = _machine_addresses()
    try:
        address = str(ipaddress.ip_address(candidate.split("%", 1)[0]))
        if address in machine_addresses:
            return True, "Local address"
        return False, "Target IP is not assigned to this machine or a loopback interface."
    except ValueError:
        pass

    normalized = candidate.lower()
    local_names = {"localhost", socket.gethostname().lower(), socket.getfqdn().lower()}
    if normalized in local_names:
        try:
            resolved = {item[4][0].split("%", 1)[0] for item in socket.getaddrinfo(candidate, None)}
        except OSError:
            resolved = set()
        if resolved and resolved.issubset(machine_addresses):
            return True, "Local hostname"
        return False, "Local hostname did not resolve exclusively to this machine."

    try:
        resolved = {item[4][0].split("%", 1)[0] for item in socket.getaddrinfo(candidate, None)}
    except OSError:
        return False, "Hostname could not be resolved to a local address."
    if resolved and resolved.issubset(machine_addresses):
        return True, "Hostname resolves only to this machine."
    return False, "Target resolves outside this machine; Qolam Sentinel is configured for local-only scans."

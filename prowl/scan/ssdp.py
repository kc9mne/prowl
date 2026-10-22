"""SSDP (UPnP) discovery — one multicast M-SEARCH, collect who answers.

UPnP devices (routers, smart TVs, printers, media servers, IoT) answer an SSDP M-SEARCH with
a SERVER header (often naming the OS/product) and a LOCATION URL to their device description.
This is a single, standard discovery request — the same thing every OS does to find UPnP
devices — and it is read-only.

Returns {ip: {server, st, usn, location}} for everything that answered.
"""
from __future__ import annotations

import asyncio
import re
import socket

MCAST = ("239.255.255.250", 1900)
MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 1\r\n"
    "ST: ssdp:all\r\n"
    "USER-AGENT: Prowl/0.1\r\n\r\n"
).encode()


def _header(text: str, name: str) -> str | None:
    m = re.search(rf"(?im)^{re.escape(name)}\s*:\s*(.+)$", text)
    return m.group(1).strip() if m else None


def _collect(timeout: float, repeats: int) -> dict:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.settimeout(timeout)
    found: dict[str, dict] = {}
    try:
        for _ in range(repeats):
            try:
                sock.sendto(MSEARCH, MCAST)
            except OSError:
                break
        import time
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
            except (socket.timeout, OSError):
                break
            text = data.decode("latin-1", "replace")
            ip = addr[0]
            entry = found.setdefault(ip, {"server": None, "st": None, "usn": None, "location": None})
            entry["server"] = entry["server"] or _header(text, "SERVER")
            entry["st"] = entry["st"] or _header(text, "ST")
            entry["usn"] = entry["usn"] or _header(text, "USN")
            entry["location"] = entry["location"] or _header(text, "LOCATION")
    finally:
        sock.close()
    return found


async def discover(timeout: float = 2.0, repeats: int = 2) -> dict:
    """Multicast M-SEARCH; returns {ip: {server, st, usn, location}}. Empty if multicast is blocked."""
    try:
        return await asyncio.to_thread(_collect, timeout, repeats)
    except OSError:
        return {}

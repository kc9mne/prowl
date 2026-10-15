"""Low-level, unprivileged network helpers.

Prowl does not require root. Host discovery works by *priming the OS ARP/neighbour cache*
(a normal connect/ping does this) and then reading that cache with the platform's own tool.
No raw sockets, no special capabilities.
"""
from __future__ import annotations

import ipaddress
import platform
import re
import socket
import subprocess

try:
    import psutil
except ImportError:  # pragma: no cover - psutil is a declared dependency
    psutil = None

WINDOWS = platform.system() == "Windows"


def norm_mac(mac: str | None) -> str | None:
    """Normalize a MAC to lowercase colon form, or None if it isn't a real unicast MAC."""
    if not mac:
        return None
    hexchars = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(hexchars) != 12:
        return None
    mac = ":".join(hexchars[i:i + 2] for i in range(0, 12, 2)).lower()
    if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return None
    return mac


def primary_ipv4() -> str | None:
    """The source IP the OS would use to reach the internet — our address on the main LAN.

    Uses a UDP socket with no packets actually sent; just resolves the routing decision.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def local_networks() -> list[dict]:
    """Every usable IPv4 interface: {iface, ip, netmask, cidr, network}. Excludes loopback."""
    out = []
    if psutil is None:
        ip = primary_ipv4()
        if ip:
            net = ipaddress.ip_network(f"{ip}/24", strict=False)
            out.append({"iface": "default", "ip": ip, "netmask": "255.255.255.0",
                        "cidr": str(net), "network": net})
        return out
    stats = psutil.net_if_stats()
    for iface, addrs in psutil.net_if_addrs().items():
        if iface in stats and not stats[iface].isup:
            continue
        for a in addrs:
            if a.family != socket.AF_INET or not a.address or not a.netmask:
                continue
            if a.address.startswith("127."):
                continue
            try:
                net = ipaddress.ip_network(f"{a.address}/{a.netmask}", strict=False)
            except ValueError:
                continue
            out.append({"iface": iface, "ip": a.address, "netmask": a.netmask,
                        "cidr": str(net), "network": net})
    return out


def default_subnet() -> dict | None:
    """Pick the interface carrying the primary IP; fall back to the first usable one."""
    nets = local_networks()
    if not nets:
        return None
    ip = primary_ipv4()
    if ip:
        for n in nets:
            if n["ip"] == ip:
                return n
    return nets[0]


def read_arp_table() -> dict[str, str]:
    """Current OS ARP/neighbour cache as {ip: normalized_mac}. Best-effort, read-only."""
    table: dict[str, str] = {}
    cmd = (["arp", "-a"] if WINDOWS else ["ip", "neigh"])
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        if WINDOWS:
            return table
        try:  # mac / BSD, or Linux without iproute2
            out = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10).stdout
        except (OSError, subprocess.SubprocessError):
            return table
    for line in out.splitlines():
        ipm = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
        macm = re.search(r"([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})", line)
        if ipm and macm:
            mac = norm_mac(macm.group(1))
            if mac:
                table[ipm.group(1)] = mac
    return table


def default_gateway() -> str | None:
    """The default-route gateway IPv4 address, or None."""
    try:
        if WINDOWS:
            out = subprocess.run(["route", "print", "0.0.0.0"], capture_output=True, text=True, timeout=10).stdout
            m = re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", out)
            return m.group(1) if m else None
        out = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=10).stdout
        m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
        if m:
            return m.group(1)
    except (OSError, subprocess.SubprocessError):
        pass
    # Fallback heuristic: .1 of our subnet
    sub = default_subnet()
    if sub:
        hosts = list(sub["network"].hosts())
        return str(hosts[0]) if hosts else None
    return None


def reverse_dns(ip: str, timeout: float = 0.5) -> str | None:
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror):
        return None
    finally:
        socket.setdefaulttimeout(old)

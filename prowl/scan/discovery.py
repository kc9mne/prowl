"""Mode 1 host discovery, fully unprivileged.

Strategy for finding live hosts on-link without raw sockets or root:
  1. For every address in the subnet, try a quick TCP connect to a few common ports and
     a best-effort ICMP echo. Either reaching a host *or merely trying to* makes the OS
     resolve its MAC into the ARP/neighbour cache.
  2. Read the ARP/neighbour cache. Any address with a resolved MAC is alive on-link, even
     if it answered nothing — this is the most reliable signal on a LAN.
  3. A host is "live" if it answered a port, answered ping, or resolved a MAC.

Then decorate each host: vendor (OUI), gateway flag, self flag, optional reverse-DNS name.
"""
from __future__ import annotations

import asyncio
import os
import socket
import struct
import time

from . import net, oui, ports
from .model import Host

_ICMP_OK = True  # flipped off the first time unprivileged ICMP is unavailable


def _icmp_ping_once(ip: str, timeout: float = 0.6) -> float | None:
    """Best-effort unprivileged ICMP echo. Returns RTT ms, None on no reply, raises OSError if unsupported."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    sock.settimeout(timeout)
    try:
        ident = os.getpid() & 0xFFFF
        payload = struct.pack("!d", time.monotonic()) + b"prowl"
        header = struct.pack("!BBHHH", 8, 0, 0, ident, 1)
        checksum = _checksum(header + payload)
        packet = struct.pack("!BBHHH", 8, 0, checksum, ident, 1) + payload
        start = time.monotonic()
        sock.sendto(packet, (ip, 0))
        while time.monotonic() - start < timeout:
            try:
                data, _ = sock.recvfrom(1024)
            except socket.timeout:
                return None
            if len(data) >= 8 and data[0] == 0:
                return (time.monotonic() - start) * 1000
        return None
    finally:
        sock.close()


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


async def _probe_host(ip: str, sem: asyncio.Semaphore, timeout: float) -> tuple[bool, float | None]:
    """Return (alive_by_response, rtt_ms). Also primes the ARP cache as a side effect."""
    global _ICMP_OK
    async with sem:
        rtt = None
        if _ICMP_OK:
            try:
                rtt = await asyncio.to_thread(_icmp_ping_once, ip, timeout)
            except OSError:
                _ICMP_OK = False
        open_ports = await ports.scan_ports(ip, ports.PROBE_PORTS, timeout=timeout, concurrency=len(ports.PROBE_PORTS))
        alive = bool(open_ports) or rtt is not None
        return alive, rtt


async def discover(network, *, timeout: float = 0.6, concurrency: int = 256,
                   resolve_names: bool = True, progress=None, cancel=None) -> dict:
    """Discover live hosts on an ipaddress network. Returns {hosts, gateway, notes}."""
    targets = [str(ip) for ip in network.hosts()]
    self_ips = {n["ip"] for n in net.local_networks()}
    gateway_ip = net.default_gateway()
    notes: list[str] = []

    sem = asyncio.Semaphore(concurrency)
    responded: dict[str, float | None] = {}
    done = 0

    async def run(ip: str):
        nonlocal done
        if cancel is not None and cancel.is_set():
            return
        alive, rtt = await _probe_host(ip, sem, timeout)
        if alive:
            responded[ip] = rtt
        done += 1
        if progress:
            progress(done, len(targets), len(responded))

    await asyncio.gather(*(run(ip) for ip in targets))

    # The ARP cache now holds anything on-link we touched, answered or not.
    arp = net.read_arp_table()
    live_ips = set(responded) | {ip for ip in arp if ip in set(targets)}
    # Our own addresses are always "live".
    live_ips |= {ip for ip in self_ips if ip in set(targets)}

    hosts: list[Host] = []
    for ip in sorted(live_ips, key=lambda x: tuple(int(p) for p in x.split("."))):
        mac = arp.get(ip)
        src = []
        if ip in responded:
            src.append("icmp" if responded[ip] is not None else "tcp")
        if ip in arp:
            src.append("arp")
        h = Host(
            ip=ip,
            mac=mac,
            vendor=oui.lookup(mac),
            is_gateway=(ip == gateway_ip),
            is_self=(ip in self_ips),
            rtt_ms=round(responded[ip], 1) if responded.get(ip) is not None else None,
            sources=src or ["arp"],
        )
        hosts.append(h)

    if resolve_names:
        async def name(h: Host):
            h.hostname = await asyncio.to_thread(net.reverse_dns, h.ip)
        await asyncio.gather(*(name(h) for h in hosts))

    if not _ICMP_OK:
        notes.append("Unprivileged ICMP unavailable; relied on TCP probes + ARP cache.")
    if gateway_ip and gateway_ip not in live_ips:
        notes.append(f"Default gateway {gateway_ip} did not appear in discovery results.")

    return {"hosts": hosts, "gateway": gateway_ip, "notes": notes}

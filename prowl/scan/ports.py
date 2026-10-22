"""Async TCP connect scanning. No raw sockets; a plain connect() tells us the port is open.

Used two ways:
  * discovery: a few PROBE_PORTS to decide a silent host is alive,
  * deep mode (later): the curated CURATED set or a custom list, feeding fingerprinting.
"""
from __future__ import annotations

import asyncio

# Ports hit during discovery just to decide "is anything here?" for hosts that ignore ping.
PROBE_PORTS = (80, 443, 22, 445, 3389, 8080)

# Curated service set for deep mode. Grouped by what they usually tell you.
CURATED = (
    22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445, 446, 465, 500,
    515, 554, 587, 623, 631, 636, 873, 902, 993, 995, 1080, 1433, 1521, 1723, 1883,
    2000, 2049, 2082, 2083, 3000, 3306, 3389, 4443, 5000, 5060, 5432, 5555, 5601,
    5900, 5985, 5986, 5984, 6379, 7547, 8000, 8006, 8008, 8080, 8081, 8083, 8088, 8123,
    8443, 8530, 8728, 8729, 8883, 8888, 9000, 9090, 9100, 9200, 10000, 11211, 27017,
    32400, 49152,
)


async def check_port(ip: str, port: int, timeout: float = 1.0) -> bool:
    """True if a TCP connection to ip:port completes within timeout."""
    try:
        fut = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, asyncio.TimeoutError):
            pass
        return True
    except (OSError, asyncio.TimeoutError):
        return False


async def scan_ports(ip: str, ports, timeout: float = 1.0, concurrency: int = 100) -> list[int]:
    """Return the sorted list of open TCP ports on one host."""
    sem = asyncio.Semaphore(concurrency)
    open_ports: list[int] = []

    async def one(p: int):
        async with sem:
            if await check_port(ip, p, timeout):
                open_ports.append(p)

    await asyncio.gather(*(one(p) for p in ports))
    return sorted(open_ports)

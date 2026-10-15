"""Data shapes for a scan: Service, Host, ScanResult.

Everything is a plain dataclass with an `as_dict()` so the web API and the CSV/JSON
report share one serialization. Keep these JSON-friendly (no sets, no datetimes).
"""
from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field


@dataclass
class Service:
    """One open port on a host, plus whatever we could learn about it (filled in deep mode)."""
    port: int
    proto: str = "tcp"              # tcp | udp
    name: str | None = None        # best-guess service name, e.g. "http", "ssh"
    banner: str | None = None      # trimmed banner / fingerprint summary (deep mode)
    secure: bool = True            # False for cleartext/legacy (telnet, ftp, http login, snmp v1/v2c)

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class Host:
    ip: str
    mac: str | None = None
    vendor: str | None = None          # from OUI lookup
    hostname: str | None = None        # reverse-DNS / mDNS / NetBIOS if freely offered
    is_gateway: bool = False
    is_self: bool = False              # the machine running Prowl
    device_class: str | None = None    # guess: router/switch/ap/printer/nas/camera/server/... (deep)
    model: str | None = None           # make/model guess (deep)
    services: list[Service] = field(default_factory=list)
    default_creds: bool = False        # True => still accepts a documented default login (deep, opt-in)
    confidence: str = "observed"       # "observed" (facts) vs "guess" (inference) — honest provenance
    rtt_ms: float | None = None
    sources: list[str] = field(default_factory=list)  # how we found it: arp, icmp, tcp, dhcp, mdns...

    def as_dict(self) -> dict:
        d = asdict(self)
        d["services"] = [s.as_dict() for s in self.services]
        return d

    @property
    def ip_sort_key(self) -> tuple:
        try:
            return tuple(int(x) for x in self.ip.split("."))
        except ValueError:
            return (999, 999, 999, 999)


@dataclass
class ScanResult:
    mode: str                          # "discovery" | "deep"
    subnet: str                        # CIDR actually scanned
    started: float = field(default_factory=time.time)
    finished: float | None = None
    gateway: str | None = None
    hosts: list[Host] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "mode": self.mode,
            "subnet": self.subnet,
            "started": self.started,
            "finished": self.finished,
            "gateway": self.gateway,
            "hosts": [h.as_dict() for h in sorted(self.hosts, key=lambda h: h.ip_sort_key)],
            "notes": self.notes,
            "count": len(self.hosts),
        }

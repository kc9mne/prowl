"""Scan job orchestration: start a scan, track progress, allow cancel, hold the result.

Mode 1 (discovery) is implemented here. Mode 2 (deep) runs discovery and then, per host,
the port sweep / fingerprint / classify / (opt-in) default-cred steps — those modules are
stubbed for the next build slice and wired in where marked TODO(deep).
"""
from __future__ import annotations

import asyncio
import ipaddress
import random
import time
import uuid

from . import classify, discovery, fingerprint, net, oui, ports
from .model import Host, ScanResult, Service

# Refuse to enumerate anything bigger than this without an explicit override — a /16 is
# 65k hosts and almost never what you meant on a LAN baseline.
MAX_HOSTS_DEFAULT = 4096


class ScanJob:
    def __init__(self, mode: str, subnet: str, deep_opts: dict | None = None, demo: bool = False):
        self.id = uuid.uuid4().hex[:12]
        self.mode = mode
        self.subnet = subnet
        self.deep_opts = deep_opts or {}
        self.demo = demo
        self.status = "queued"          # queued | running | done | cancelled | error
        self.error: str | None = None
        self.started = time.time()
        self.progress = {"done": 0, "total": 0, "found": 0, "phase": "queued"}
        self.result: ScanResult | None = None
        self._cancel = asyncio.Event()
        self._task: asyncio.Task | None = None

    def cancel(self):
        self._cancel.set()

    def public(self) -> dict:
        return {
            "id": self.id,
            "mode": self.mode,
            "subnet": self.subnet,
            "demo": self.demo,
            "status": self.status,
            "error": self.error,
            "progress": self.progress,
            "result": self.result.as_dict() if self.result else None,
        }

    async def run(self):
        self.status = "running"
        try:
            if self.demo:
                await self._run_demo()
            else:
                await self._run_real()
            self.status = "cancelled" if self._cancel.is_set() else "done"
        except Exception as e:  # noqa: BLE001 - surface any failure to the UI
            self.status = "error"
            self.error = f"{type(e).__name__}: {e}"

    async def _run_real(self):
        network = ipaddress.ip_network(self.subnet, strict=False)
        allow_large = self.deep_opts.get("allow_large", False)
        if network.num_addresses > MAX_HOSTS_DEFAULT and not allow_large:
            raise ValueError(
                f"{self.subnet} has {network.num_addresses} addresses "
                f"(> {MAX_HOSTS_DEFAULT}); pass allow_large to scan it anyway.")

        self.progress["phase"] = "discovery"

        def prog(done, total, found):
            self.progress.update(done=done, total=total, found=found)

        disc = await discovery.discover(network, progress=prog, cancel=self._cancel)
        result = ScanResult(mode=self.mode, subnet=str(network), gateway=disc["gateway"])
        result.hosts = disc["hosts"]
        result.notes = disc["notes"]

        if self.mode == "deep" and not self._cancel.is_set():
            await self._deep(result)

        result.finished = time.time()
        self.result = result

    async def _deep(self, result: ScanResult):
        """Per host: curated port sweep -> fingerprint each open port -> classify."""
        self.progress["phase"] = "deep"
        hosts = [h for h in result.hosts if not h.is_self]
        port_set = self.deep_opts.get("ports") or ports.CURATED
        timeout = float(self.deep_opts.get("timeout", 1.0))
        host_conc = asyncio.Semaphore(int(self.deep_opts.get("host_concurrency", 24)))
        total = len(hosts)
        done = 0

        async def one(host: Host):
            nonlocal done
            if self._cancel.is_set():
                return
            async with host_conc:
                open_ports = await ports.scan_ports(host.ip, port_set, timeout=timeout)
                svcs = await asyncio.gather(*(fingerprint.fingerprint(host.ip, p, timeout * 2) for p in open_ports))
                host.services = sorted(svcs, key=lambda s: s.port)
                classify.classify(host)
            done += 1
            self.progress.update(done=done, total=total, found=done, phase="deep")

        self.progress.update(done=0, total=total, found=0, phase="deep")
        await asyncio.gather(*(one(h) for h in hosts))
        if self.deep_opts.get("check_default_creds"):
            # TODO(creds): opt-in default-credential check with its authorization gate + guardrails.
            result.notes.append("Default-credential check requested but not yet implemented (next slice).")
        result.notes.append(f"Deep scan fingerprinted {total} hosts across {len(port_set)} ports each.")

    async def _run_demo(self):
        """Fabricate a plausible small network so the UI and report can be exercised offline."""
        self.progress["phase"] = "discovery"
        fake = [
            ("192.168.1.1", "4c:5e:0c:11:22:33", True, "gateway.lan", [53, 80, 443]),
            ("192.168.1.2", "dc:9f:db:aa:bb:cc", False, "ap-office", [22, 80, 443]),
            ("192.168.1.10", "b8:27:eb:de:ad:01", False, "pi-dns", [22, 53, 80]),
            ("192.168.1.20", "00:17:88:ab:cd:ef", False, None, [80]),
            ("192.168.1.50", "00:80:77:12:34:56", False, "BRN123456", [80, 443, 515, 631, 9100]),
            ("192.168.1.77", "44:33:e1:99:88:77", False, None, [80, 554]),
            ("192.168.1.101", "f0:18:98:00:11:22", False, "macbook", []),
            ("192.168.1.150", "00:0c:29:0a:0b:0c", False, "fileserver", [22, 139, 445, 3389]),
        ]
        total = len(fake)
        hosts: list[Host] = []
        for i, (ip, mac, is_gw, name, open_ports) in enumerate(fake, 1):
            if self._cancel.is_set():
                break
            await asyncio.sleep(0.15)
            h = Host(ip=ip, mac=mac, vendor=oui.lookup(mac), hostname=name, is_gateway=is_gw,
                     rtt_ms=round(random.uniform(0.4, 12.0), 1), sources=["arp", "tcp"])
            if self.mode == "deep":
                h.services = [Service(port=p, name=fingerprint.service_name(p)[0],
                                      secure=fingerprint.service_name(p)[1]) for p in open_ports]
                classify.classify(h)
            hosts.append(h)
            self.progress.update(done=i, total=total, found=len(hosts))
        result = ScanResult(mode=self.mode, subnet="192.168.1.0/24", gateway="192.168.1.1")
        result.hosts = hosts
        result.notes = ["DEMO scan — fabricated data, no network was touched."]
        result.finished = time.time()
        self.result = result


class ScanManager:
    """Holds the most recent jobs in memory (this is an on-site tool, not a service)."""

    def __init__(self, max_jobs: int = 8):
        self.jobs: dict[str, ScanJob] = {}
        self._order: list[str] = []
        self.max_jobs = max_jobs

    def start(self, mode: str, subnet: str | None, deep_opts: dict | None = None, demo: bool = False) -> ScanJob:
        if mode not in ("discovery", "deep"):
            raise ValueError("mode must be 'discovery' or 'deep'")
        if not demo:
            subnet = subnet or _auto_subnet()
            if not subnet:
                raise ValueError("could not determine a local subnet; pass one explicitly")
            ipaddress.ip_network(subnet, strict=False)  # validate early
        job = ScanJob(mode, subnet or "demo", deep_opts, demo=demo)
        self.jobs[job.id] = job
        self._order.append(job.id)
        self._evict()
        job._task = asyncio.create_task(job.run())
        return job

    def get(self, job_id: str) -> ScanJob | None:
        return self.jobs.get(job_id)

    def latest(self) -> ScanJob | None:
        return self.jobs.get(self._order[-1]) if self._order else None

    def _evict(self):
        while len(self._order) > self.max_jobs:
            old = self._order.pop(0)
            self.jobs.pop(old, None)


def _auto_subnet() -> str | None:
    sub = net.default_subnet()
    return sub["cidr"] if sub else None

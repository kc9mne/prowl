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

import ipaddress as _ip

from . import classify, creds, discovery, fingerprint, net, oui, ports, smb, snmp, ssdp
from .model import Host, ScanResult, Service

# Refuse to enumerate anything bigger than this without an explicit override — a /16 is
# 65k hosts and almost never what you meant on a LAN baseline.
MAX_HOSTS_DEFAULT = 4096


class ScanJob:
    def __init__(self, mode: str, subnet: str, deep_opts: dict | None = None, demo: bool = False, audit=None):
        self.id = uuid.uuid4().hex[:12]
        self.mode = mode
        self.subnet = subnet
        self.deep_opts = deep_opts or {}
        self.demo = demo
        self.audit = audit
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

        # One network-wide SSDP/UPnP sweep (not per host), unless disabled.
        upnp: dict[str, dict] = {}
        if self.deep_opts.get("ssdp", True):
            try:
                upnp = await ssdp.discover(timeout=2.0)
            except OSError:
                upnp = {}
        do_snmp = self.deep_opts.get("snmp", True)

        async def one(host: Host):
            nonlocal done
            if self._cancel.is_set():
                return
            async with host_conc:
                open_ports = await ports.scan_ports(host.ip, port_set, timeout=timeout)
                svcs = await asyncio.gather(*(fingerprint.fingerprint(host.ip, p, timeout * 2) for p in open_ports))
                host.services = sorted(svcs, key=lambda s: s.port)
                await self._extra_fingerprint(host, set(open_ports), upnp.get(host.ip), do_snmp, timeout)
                classify.classify(host)
            done += 1
            self.progress.update(done=done, total=total, found=done, phase="deep")

        self.progress.update(done=0, total=total, found=0, phase="deep")
        await asyncio.gather(*(one(h) for h in hosts))
        extras = [note for note in (
            f"UPnP: {len(upnp)} responder(s)." if upnp else "",
        ) if note]
        result.notes.append(f"Deep scan fingerprinted {total} hosts across {len(port_set)} ports each. "
                            + " ".join(extras))

    async def _extra_fingerprint(self, host: Host, open_ports: set, upnp: dict | None,
                                 do_snmp: bool, timeout: float):
        """SNMP sysDescr, SMB/NTLM name+OS, and UPnP SERVER — all read-only, best-effort."""
        if do_snmp:
            try:
                snmp_res = await snmp.probe(host.ip, timeout=1.0)
            except OSError:
                snmp_res = None
            if snmp_res and snmp_res.get("sysDescr"):
                host.services.append(Service(port=161, proto="udp", name="snmp",
                                             banner=snmp_res["sysDescr"][:160], secure=False))
                if not host.hostname and snmp_res.get("sysName"):
                    host.hostname = snmp_res["sysName"]
        if 445 in open_ports:
            try:
                info = await smb.probe(host.ip, timeout=timeout * 2)
            except OSError:
                info = None
            if info:
                name = info.get("dns_computer") or info.get("nb_computer")
                if name and not host.hostname:
                    host.hostname = name
                parts = [p for p in (name, info.get("nb_domain")) if p]
                banner = "SMB " + " / ".join(parts) + (f"  OS {info['os']}" if info.get("os") else "")
                smbsvc = next((s for s in host.services if s.port == 445), None)
                if smbsvc:
                    smbsvc.banner = banner.strip()
        if upnp and upnp.get("server"):
            bits = [upnp["server"]] + ([upnp["st"]] if upnp.get("st") else [])
            host.services.append(Service(port=1900, proto="udp", name="upnp",
                                         banner=" | ".join(bits)[:160], secure=False))

        if self.deep_opts.get("check_default_creds") and not self._cancel.is_set():
            await self._check_creds(result)

    async def _check_creds(self, result: ScanResult):
        """Opt-in, on-link-only default-credential check. Caller guarantees authorization."""
        self.progress.update(phase="creds", done=0, total=0, found=0)
        nets = [n["network"] for n in net.local_networks()]

        def on_link(ip: str) -> bool:
            try:
                addr = _ip.ip_address(ip)
            except ValueError:
                return False
            return any(addr in n for n in nets)

        hosts = [h for h in result.hosts if not h.is_self and h.services and on_link(h.ip)]
        skipped = [h for h in result.hosts if not h.is_self and h.services and not on_link(h.ip)]
        if skipped:
            result.notes.append(f"Default-cred check skipped {len(skipped)} off-link host(s) (on-link only).")
        if not hosts:
            result.notes.append("Default-cred check: no eligible on-link hosts with services.")
            return

        # Limited concurrency across hosts; the per-host checker is serial + delayed internally.
        sem = asyncio.Semaphore(int(self.deep_opts.get("cred_host_concurrency", 4)))
        total = len(hosts)
        done = 0

        async def one(host: Host):
            nonlocal done
            if self._cancel.is_set():
                return
            async with sem:
                await creds.check_host(host, audit=self.audit, cancel=self._cancel)
            done += 1
            self.progress.update(done=done, total=total, found=done, phase="creds")

        self.progress.update(done=0, total=total, found=0, phase="creds")
        await asyncio.gather(*(one(h) for h in hosts))
        hits = [h for h in hosts if h.default_creds]
        if self.audit:
            self.audit("cred-check-summary", f"{len(hits)}/{total} hosts accept a documented default")
        result.notes.append(
            f"Default-cred check: {len(hits)} of {total} on-link host(s) still accept a factory default "
            f"login (such devices are also likely unpatched).")

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
                self._demo_banners(h)
                classify.classify(h)
            hosts.append(h)
            self.progress.update(done=i, total=total, found=len(hosts))
        if self.mode == "deep" and self.deep_opts.get("check_default_creds"):
            self._demo_cred_hits(hosts)
        result = ScanResult(mode=self.mode, subnet="192.168.1.0/24", gateway="192.168.1.1")
        result.hosts = hosts
        result.notes = ["DEMO scan — fabricated data, no network was touched."]
        if self.deep_opts.get("check_default_creds"):
            hits = sum(h.default_creds for h in hosts)
            result.notes.append(f"Default-cred check (demo): {hits} host(s) accept a factory default "
                                f"login (such devices are also likely unpatched).")
        result.finished = time.time()
        self.result = result


    def _demo_banners(self, h: Host):
        """Fabricated SNMP/SMB/HTTP banners so the demo shows slice-6 fingerprinting."""
        if h.is_gateway:
            h.services.append(Service(port=161, proto="udp", name="snmp", secure=False,
                                      banner="RouterOS RB750Gr3, MikroTik 7.11"))
        byport = {s.port: s for s in h.services}
        if h.ip == "192.168.1.50" and 80 in byport:   # printer
            byport[80].banner = "HP HTTP Server | Brother HL-L2370DW"
        if h.ip == "192.168.1.77" and 80 in byport:   # camera
            byport[80].banner = "App-webs/ | Hikvision DS-2CD2042"
        if h.ip == "192.168.1.150" and 445 in byport:  # windows host
            byport[445].banner = "SMB FILESERVER / WORKGROUP  OS 10.0 build 19045"
            byport[445].name = "smb"

    def _demo_cred_hits(self, hosts: list[Host]):
        """Fabricate a couple of default-cred findings so the UI/report can be seen offline."""
        rigged = {"192.168.1.77": ("http", 80, "admin", "12345"),   # the camera
                  "192.168.1.50": ("http", 80, "admin", "admin")}    # the printer
        for h in hosts:
            h.cred_checked = bool(h.services)
            if h.ip in rigged and h.services:
                svc, port, user, pw = rigged[h.ip]
                h.default_creds = True
                h.default_cred_detail = {"service": svc, "port": port, "username": user, "password": pw}


class ScanManager:
    """Holds the most recent jobs in memory (this is an on-site tool, not a service)."""

    def __init__(self, max_jobs: int = 8, audit=None):
        self.jobs: dict[str, ScanJob] = {}
        self._order: list[str] = []
        self.max_jobs = max_jobs
        self.audit = audit

    def start(self, mode: str, subnet: str | None, deep_opts: dict | None = None, demo: bool = False) -> ScanJob:
        if mode not in ("discovery", "deep"):
            raise ValueError("mode must be 'discovery' or 'deep'")
        if not demo:
            subnet = subnet or _auto_subnet()
            if not subnet:
                raise ValueError("could not determine a local subnet; pass one explicitly")
            ipaddress.ip_network(subnet, strict=False)  # validate early
        job = ScanJob(mode, subnet or "demo", deep_opts, demo=demo, audit=self.audit)
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

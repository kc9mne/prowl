"""Best-guess device classification from observed signals.

Inputs we have per host: OUI vendor, the set of open ports, and service banners (HTTP
Server/title/realm, TLS cert CN, SSH banner, ...). None of these is authoritative, so the
result is always marked confidence="guess" and the UI shows it as a guess, never a fact.

The order matters: strong banner/port signatures win over weak vendor hints.
"""
from __future__ import annotations

from .model import Host

# Vendor substrings that strongly imply a class even before ports.
VENDOR_CLASS = [
    (("mikrotik", "routerboard"), "router/switch"),
    (("ubiquiti",), "network gear"),
    (("cisco", "aruba", "fortinet", "netgear", "tp-link", "d-link", "zyxel"), "network gear"),
    (("hikvision", "dahua", "axis", "mobotix", "instar"), "camera"),
    (("brother", "canon", "kyocera", "lexmark", "xerox", "epson", "jetdirect", "hewlett"), "printer"),
    (("grandstream", "yealink", "polycom", "avaya"), "voip-phone"),
    (("raspberry pi",), "sbc/host"),
    (("vmware", "virtualbox", "qemu", "hyper-v", "proxmox"), "virtual machine"),
    (("philips", "signify", "sonos", "amazon", "google", "nest", "espressif", "tuya"), "iot"),
    (("apple",), "apple device"),
    (("samsung",), "samsung device"),
]

# (required open ports as a set, banner keyword or None, class, model-hint)
PORT_SIGNATURES = [
    ({9100}, None, "printer", None),
    ({515}, None, "printer", None),
    ({631}, None, "printer", None),
    ({554}, None, "camera", None),
    ({8728}, None, "router/switch", "MikroTik RouterOS"),
    ({3389}, None, "windows host", None),
    ({445, 139}, None, "windows/SMB host", None),
    ({5985}, None, "windows host", None),
    ({139, 445, 5357}, None, "windows host", None),
    ({3306}, None, "database server", "MySQL/MariaDB"),
    ({5432}, None, "database server", "PostgreSQL"),
    ({1433}, None, "database server", "MS SQL Server"),
    ({6379}, None, "database server", "Redis"),
    ({9200}, None, "server", "Elasticsearch"),
    ({32400}, None, "media server", "Plex"),
    ({8006}, None, "hypervisor", "Proxmox VE"),
    ({5060}, None, "voip", None),
    ({1883, 8883}, None, "iot/mqtt broker", None),
    ({7547}, None, "router/CPE", "TR-069 managed"),
    ({161}, None, "managed device", None),
]

# Banner keywords -> (class, model hint). Checked across all service banners.
BANNER_KEYWORDS = [
    ("routeros", ("router/switch", "MikroTik RouterOS")),
    ("mikrotik", ("router/switch", "MikroTik")),
    ("ubnt", ("network gear", "Ubiquiti")),
    ("unifi", ("network gear", "Ubiquiti UniFi")),
    ("dd-wrt", ("router", "DD-WRT")),
    ("openwrt", ("router", "OpenWrt")),
    ("hikvision", ("camera", "Hikvision")),
    ("dahua", ("camera", "Dahua")),
    ("axis", ("camera", "Axis")),
    ("rtsp", ("camera", None)),
    ("jetdirect", ("printer", "HP JetDirect")),
    ("cups", ("printer", "CUPS")),
    ("printer", ("printer", None)),
    ("synology", ("NAS", "Synology")),
    ("qnap", ("NAS", "QNAP")),
    ("truenas", ("NAS", "TrueNAS")),
    ("proxmox", ("hypervisor", "Proxmox VE")),
    ("vmware", ("hypervisor", "VMware ESXi")),
    ("home assistant", ("iot hub", "Home Assistant")),
    ("plex", ("media server", "Plex")),
    ("microsoft-iis", ("windows host", "IIS")),
    ("windows", ("windows host", None)),
    ("ubuntu", ("linux host", "Ubuntu")),
    ("debian", ("linux host", "Debian")),
    ("openssh", ("host", None)),
    ("grandstream", ("voip-phone", "Grandstream")),
    ("yealink", ("voip-phone", "Yealink")),
]


def classify(host: Host) -> None:
    """Fill host.device_class / host.model / host.confidence in place."""
    ports = {s.port for s in host.services}
    banners = " ".join((s.banner or "") for s in host.services).lower()
    vendor = (host.vendor or "").lower()

    cls = None
    model = None

    # 1) Strong banner keywords.
    for kw, (c, m) in BANNER_KEYWORDS:
        if kw in banners:
            cls, model = c, (m or model)
            break

    # 2) Port signatures (only if banners didn't already decide, or to add a model).
    if cls is None:
        for req, kw, c, m in PORT_SIGNATURES:
            if req <= ports and (kw is None or kw in banners):
                cls, model = c, m
                break

    # 3) Vendor hint as a fallback / tie-breaker.
    if cls is None:
        for subs, c in VENDOR_CLASS:
            if any(s in vendor for s in subs):
                cls = c
                break

    # 4) Last resort from generic port shape.
    if cls is None:
        names = {(s.name or "") for s in host.services}
        if {80, 443} & ports or any(n.startswith("http") for n in names):
            cls = "web host"
        elif 22 in ports:
            cls = "host (ssh)"
        elif ports:
            cls = "host"
        else:
            cls = "unknown"

    # Model: prefer an HTTP Server / TLS cert CN snippet if we didn't get one.
    if model is None:
        model = _model_from_banner(host)
    if host.is_gateway and "router" not in (cls or ""):
        cls = f"gateway / {cls}" if cls and cls != "unknown" else "router/gateway"

    host.device_class = cls
    host.model = model
    host.confidence = "guess"


def _model_from_banner(host: Host) -> str | None:
    for s in host.services:
        if not s.banner:
            continue
        if s.banner.startswith("cert:"):
            cn = s.banner.split("cert:", 1)[1].split(" | ")[0].strip()
            if cn and not cn.replace(".", "").isdigit():
                return cn
    for s in host.services:
        b = s.banner or ""
        if "|" in b:  # HTTP "Server | title | realm"
            server = b.split("|")[0].strip()
            if server and server.lower() not in ("http", "https"):
                return server[:48]
    return host.vendor

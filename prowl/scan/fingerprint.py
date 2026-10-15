"""Deep-mode service fingerprinting: identify what's listening on an open port.

Everything here is read-only and best-effort: connect, read a banner or make one benign
request (an HTTP GET /, an RTSP OPTIONS), record what came back, move on. Nothing is sent
that changes device state. Each probe is individually timed and failures degrade to "the
port is open, service unknown".

Optional: if the `cryptography` package is importable, TLS services also yield the cert's
subject CN / SANs, which often name the device. Without it, TLS still yields version/cipher.
"""
from __future__ import annotations

import asyncio
import re
import ssl

from .model import Service

try:  # optional, for TLS cert subject/SAN extraction
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    _HAVE_CRYPTO = True
except ImportError:  # pragma: no cover
    _HAVE_CRYPTO = False

# Port -> (default service name, secure?)  secure=False flags cleartext/legacy services (⚠ in UI)
PORT_NAMES: dict[int, tuple[str, bool]] = {
    21: ("ftp", False), 22: ("ssh", True), 23: ("telnet", False), 25: ("smtp", False),
    53: ("dns", True), 80: ("http", False), 110: ("pop3", False), 111: ("rpcbind", True),
    135: ("msrpc", True), 139: ("netbios-ssn", False), 143: ("imap", False),
    161: ("snmp", False), 389: ("ldap", True), 443: ("https", True), 445: ("smb", True),
    465: ("smtps", True), 500: ("isakmp", True), 515: ("lpd", False), 554: ("rtsp", True),
    587: ("submission", True), 623: ("ipmi", False), 631: ("ipp", True), 636: ("ldaps", True),
    873: ("rsync", True), 902: ("vmware", True), 993: ("imaps", True), 995: ("pop3s", True),
    1080: ("socks", True), 1433: ("mssql", True), 1521: ("oracle", True), 1723: ("pptp", False),
    1883: ("mqtt", False), 2049: ("nfs", True), 3000: ("http-alt", False), 3306: ("mysql", True),
    3389: ("rdp", True), 5000: ("http-alt", False), 5060: ("sip", False), 5432: ("postgres", True),
    5555: ("adb/http", False), 5601: ("kibana", False), 5900: ("vnc", False), 5985: ("winrm", False),
    5986: ("winrm-s", True), 6379: ("redis", False), 7547: ("tr069", True), 8000: ("http-alt", False),
    8006: ("proxmox", True), 8008: ("http-alt", False), 8080: ("http-alt", False),
    8081: ("http-alt", False), 8083: ("http-alt", False), 8088: ("http-alt", False),
    8123: ("home-assistant", False), 8443: ("https-alt", True), 8530: ("wsus", False),
    8728: ("mikrotik-api", False), 8729: ("mikrotik-api-s", True), 8883: ("mqtt-s", True),
    8888: ("http-alt", False), 9000: ("http-alt", False), 9090: ("http-alt", False),
    9100: ("jetdirect", False), 9200: ("elasticsearch", False), 10000: ("webmin", True),
    32400: ("plex", False), 49152: ("upnp", True),
}

HTTP_PORTS = {80, 3000, 5000, 8000, 8008, 8080, 8081, 8083, 8088, 8123, 8888, 9000, 9090, 10000, 32400}
TLS_HTTP_PORTS = {443, 4443, 8006, 8443, 5601, 9200}
BANNER_PORTS = {21, 22, 23, 25, 110, 143, 587, 6379}


def service_name(port: int) -> tuple[str, bool]:
    """(name, secure?) for a port. secure=False marks cleartext/legacy services."""
    return PORT_NAMES.get(port, ("tcp", True))


async def _read_banner(ip: str, port: int, timeout: float, send: bytes = b"") -> str | None:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
    except (OSError, asyncio.TimeoutError):
        return None
    try:
        if send:
            writer.write(send)
            await writer.drain()
        data = await asyncio.wait_for(reader.read(512), timeout=timeout)
        return data.decode("latin-1", "replace").strip() or None
    except (OSError, asyncio.TimeoutError):
        return None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, asyncio.TimeoutError):
            pass


async def _http(ip: str, port: int, tls: bool, timeout: float) -> dict | None:
    """Benign GET /. Returns {server, title, status} or None."""
    ctx = None
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=ip if tls else None), timeout=timeout)
    except (OSError, asyncio.TimeoutError, ssl.SSLError):
        return None
    try:
        req = (f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: Prowl\r\n"
               f"Accept: */*\r\nConnection: close\r\n\r\n").encode()
        writer.write(req)
        await writer.drain()
        raw = await asyncio.wait_for(reader.read(8192), timeout=timeout)
    except (OSError, asyncio.TimeoutError, ssl.SSLError):
        return None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, asyncio.TimeoutError, ssl.SSLError):
            pass
    text = raw.decode("latin-1", "replace")
    head, _, body = text.partition("\r\n\r\n")
    status = re.match(r"HTTP/[\d.]+ (\d{3})", head)
    server = re.search(r"(?im)^Server:\s*(.+)$", head)
    realm = re.search(r'(?i)WWW-Authenticate:\s*\w+\s+realm="([^"]+)"', head)
    title = re.search(r"(?is)<title[^>]*>(.*?)</title>", body)
    return {
        "status": status.group(1) if status else None,
        "server": server.group(1).strip() if server else None,
        "realm": realm.group(1).strip() if realm else None,
        "title": re.sub(r"\s+", " ", title.group(1)).strip()[:80] if title else None,
    }


def _tls_cert_subject(ip: str, port: int, timeout: float) -> str | None:
    """Blocking helper (run in a thread): subject CN / first SAN of the server cert, if available."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        import socket
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                der = ssock.getpeercert(binary_form=True)
        if not der or not _HAVE_CRYPTO:
            return None
        cert = x509.load_der_x509_certificate(der, default_backend())
        cn = None
        try:
            cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        except (IndexError, Exception):  # noqa: BLE001
            cn = None
        if not cn:
            try:
                san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                names = san.value.get_values_for_type(x509.DNSName)
                cn = names[0] if names else None
            except Exception:  # noqa: BLE001
                cn = None
        return cn
    except (OSError, ssl.SSLError, ValueError):
        return None


async def fingerprint(ip: str, port: int, timeout: float = 2.0) -> Service:
    """Identify one open port, non-destructively, and return a populated Service."""
    name, secure = service_name(port)
    svc = Service(port=port, name=name, secure=secure)
    banner = None

    if port in HTTP_PORTS or port in TLS_HTTP_PORTS or name.startswith("http"):
        tls = port in TLS_HTTP_PORTS or name in ("https", "https-alt")
        info = await _http(ip, port, tls, timeout)
        if info:
            bits = [b for b in (info.get("server"), info.get("title"), info.get("realm")) if b]
            banner = " | ".join(bits) if bits else (f"HTTP {info['status']}" if info.get("status") else None)
            svc.name = "https" if tls else "http"
        if tls:
            cn = await asyncio.to_thread(_tls_cert_subject, ip, port, timeout)
            if cn:
                banner = (banner + " | " if banner else "") + f"cert:{cn}"
    elif port in BANNER_PORTS:
        banner = await _read_banner(ip, port, timeout)
    elif port == 554:  # RTSP
        banner = await _read_banner(ip, port, timeout,
                                    send=f"OPTIONS rtsp://{ip}:{port} RTSP/1.0\r\nCSeq: 1\r\n\r\n".encode())
    elif port in (443, 4443, 8443):
        cn = await asyncio.to_thread(_tls_cert_subject, ip, port, timeout)
        banner = f"cert:{cn}" if cn else None
    else:
        banner = await _read_banner(ip, port, timeout)

    if banner:
        svc.banner = banner[:160]
    return svc

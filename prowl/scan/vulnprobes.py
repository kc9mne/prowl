"""Read-only vulnerability checks that produce structured findings.

Everything here connects and reads — it never authenticates destructively, writes, or sends
credentials. Each check returns a list of finding dicts:
    {severity, title, evidence, recommendation, category}
which the assessment engine attaches to the host.

Covered here: TLS certificate/protocol hygiene and unauthenticated data stores. SMB checks
live in smb.py (they share its wire code).
"""
from __future__ import annotations

import asyncio
import datetime
import socket
import ssl
import warnings

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    _HAVE_CRYPTO = True
except ImportError:  # pragma: no cover
    _HAVE_CRYPTO = False

TLS_PORTS = {443, 4443, 8443, 8006, 9443, 993, 995, 5986}
CERT_SOON_DAYS = 30


def _finding(sev, title, ev, rec, cat):
    return {"severity": sev, "title": title, "evidence": ev, "recommendation": rec, "category": cat}


# ---- TLS ------------------------------------------------------------------------------

def _get_cert(ip: str, port: int, timeout: float):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ss:
                der = ss.getpeercert(binary_form=True)
                version = ss.version()
        if der and _HAVE_CRYPTO:
            return x509.load_der_x509_certificate(der, default_backend()), version
        return None, version
    except (OSError, ssl.SSLError, ValueError):
        return None, None


def _proto_enabled(ip: str, port: int, tls_version, timeout: float) -> bool | None:
    """True if the server completes a handshake pinned to this (obsolete) TLS version.

    None means our client can't even offer it, so we can't conclude (avoids false flags).
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)  # we pin old versions on purpose
            ctx.minimum_version = tls_version
            ctx.maximum_version = tls_version
    except (ValueError, OSError):
        return None
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip):
                return True
    except (ssl.SSLError, OSError):
        return False


def _tls_audit_blocking(ip: str, port: int, timeout: float) -> list[dict]:
    out: list[dict] = []
    cert, version = _get_cert(ip, port, timeout)
    if version is None and cert is None:
        return out
    if cert is not None:
        try:
            not_after = cert.not_valid_after_utc
            now = datetime.datetime.now(datetime.timezone.utc)
        except AttributeError:   # older cryptography
            not_after = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
            now = datetime.datetime.now(datetime.timezone.utc)
        if not_after < now:
            out.append(_finding("medium", "Expired TLS certificate",
                                f"cert on :{port} expired {not_after.date()}",
                                "Replace the certificate.", "tls"))
        elif (not_after - now).days <= CERT_SOON_DAYS:
            out.append(_finding("low", "TLS certificate expiring soon",
                                f"cert on :{port} expires {not_after.date()}",
                                "Renew the certificate before it expires.", "tls"))
        if cert.issuer == cert.subject:
            out.append(_finding("low", "Self-signed TLS certificate",
                                f"issuer == subject on :{port}",
                                "Use a certificate from a trusted CA for management interfaces.", "tls"))
    for name, ver in (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)):
        if _proto_enabled(ip, port, ver, timeout) is True:
            out.append(_finding("high", f"Obsolete TLS enabled ({name})",
                                f"{name} handshake accepted on :{port}",
                                "Disable TLS 1.0/1.1; require TLS 1.2+.", "tls"))
    return out


# ---- unauthenticated data stores ------------------------------------------------------

def _tcp(ip: str, port: int, payload: bytes, timeout: float, nbytes: int = 1024) -> bytes:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if payload:
                s.sendall(payload)
            return s.recv(nbytes)
    except OSError:
        return b""


def _datastore_blocking(ip: str, open_ports: set, timeout: float) -> list[dict]:
    out: list[dict] = []
    if 6379 in open_ports:
        r = _tcp(ip, 6379, b"PING\r\n", timeout)
        if r.startswith(b"+PONG"):
            out.append(_finding("critical", "Unauthenticated Redis",
                                "PING answered without AUTH on :6379",
                                "Require a password (requirepass) and bind to localhost/VLAN.", "data-service"))
        elif r:
            out.append(_finding("high", "Redis exposed", "Redis reachable on :6379",
                                "Restrict access and require authentication.", "data-service"))
    if 11211 in open_ports:
        r = _tcp(ip, 11211, b"stats\r\n", timeout)
        if b"STAT " in r:
            out.append(_finding("high", "Unauthenticated Memcached",
                                "stats answered without auth on :11211",
                                "Bind Memcached to localhost and firewall :11211.", "data-service"))
    if 9200 in open_ports:
        r = _tcp(ip, 9200, b"GET / HTTP/1.0\r\nHost: x\r\n\r\n", timeout, 2048)
        if b" 200 " in r and (b"cluster_name" in r or b"lucene_version" in r):
            out.append(_finding("high", "Unauthenticated Elasticsearch",
                                "cluster info served without auth on :9200",
                                "Enable authentication and restrict access.", "data-service"))
    if 5984 in open_ports:
        r = _tcp(ip, 5984, b"GET /_all_dbs HTTP/1.0\r\nHost: x\r\n\r\n", timeout, 2048)
        if b" 200 " in r and b"[" in r:
            out.append(_finding("high", "Unauthenticated CouchDB",
                                "/_all_dbs served without auth on :5984",
                                "Require admin auth and restrict access.", "data-service"))
    return out


# ---- anonymous FTP, open DNS resolver, VNC no-auth, NFS -------------------------------

def _ftp_anon_blocking(ip: str, timeout: float, port: int = 21) -> list[dict]:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if not s.recv(256).startswith(b"220"):
                return []
            s.sendall(b"USER anonymous\r\n"); s.recv(256)
            s.sendall(b"PASS prowl@example.com\r\n")
            if s.recv(256).startswith(b"230"):
                s.sendall(b"QUIT\r\n")
                return [_finding("medium", "Anonymous FTP enabled",
                                 "anonymous login accepted on :21",
                                 "Disable anonymous FTP or replace FTP with SFTP.", "ftp")]
    except OSError:
        pass
    return []


def _dns_query(name: str) -> bytes:
    q = b""
    for part in name.split("."):
        q += bytes([len(part)]) + part.encode()
    q += b"\x00"
    return b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + q + b"\x00\x01\x00\x01"


def _dns_resolver_blocking(ip: str, timeout: float, port: int = 53) -> list[dict]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(_dns_query("example.com"), (ip, port))
        data, _ = s.recvfrom(1024)
        s.close()
    except OSError:
        return []
    if len(data) < 8:
        return []
    flags = int.from_bytes(data[2:4], "big")
    ancount = int.from_bytes(data[6:8], "big")
    ra = bool(flags & 0x0080)      # recursion available
    rcode = flags & 0x000F
    if ra and rcode == 0 and ancount > 0:
        return [_finding("medium", "Open DNS resolver",
                         "answers recursive queries for external names on :53",
                         "Restrict recursion to internal clients; open resolvers enable DDoS "
                         "amplification.", "dns")]
    return []


def _vnc_noauth_blocking(ip: str, port: int, timeout: float) -> list[dict]:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            ver = s.recv(12)
            if not ver.startswith(b"RFB "):
                return []
            try:
                minor = int(ver[8:11])
            except ValueError:
                minor = 8
            if minor >= 7:
                s.sendall(b"RFB 003.008\n")
                n = s.recv(1)
                if not n or n[0] == 0:
                    return []
                types = s.recv(n[0])
                none_auth = 1 in types
            else:
                s.sendall(b"RFB 003.003\n")
                st = s.recv(4)
                none_auth = len(st) == 4 and int.from_bytes(st, "big") == 1
            if none_auth:
                return [_finding("high", "VNC allows unauthenticated access",
                                 f"RFB 'None' security type offered on :{port}",
                                 "Require a VNC password and restrict access to a management VLAN/VPN.",
                                 "remote-access")]
    except OSError:
        pass
    return []


# ---- entry point ----------------------------------------------------------------------

async def audit(ip: str, open_ports: set, timeout: float = 3.0) -> list[dict]:
    """Run the read-only vuln checks relevant to a host's open ports."""
    findings: list[dict] = []
    for p in (p for p in open_ports if p in TLS_PORTS):
        findings += await asyncio.to_thread(_tls_audit_blocking, ip, p, timeout)
    if open_ports & {6379, 11211, 9200, 5984}:
        findings += await asyncio.to_thread(_datastore_blocking, ip, set(open_ports), timeout)
    if 21 in open_ports:
        findings += await asyncio.to_thread(_ftp_anon_blocking, ip, timeout)
    if 53 in open_ports:
        findings += await asyncio.to_thread(_dns_resolver_blocking, ip, timeout)
    if 5900 in open_ports:
        findings += await asyncio.to_thread(_vnc_noauth_blocking, ip, 5900, timeout)
    if 2049 in open_ports:
        findings.append(_finding("medium", "NFS service reachable",
                                 "NFS (2049) open to the LAN",
                                 "Restrict NFS by export ACL/firewall and avoid world-readable exports.",
                                 "nfs"))
    return findings

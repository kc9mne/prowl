"""SMB name/OS fingerprint — unauthenticated, read-only.

Windows and Samba hosts leak their computer name, domain, and OS build in the NTLM CHALLENGE
(Type 2) they return during the SMB2 session-setup handshake — before any credential is sent.
Prowl does an SMB2 NEGOTIATE then a SESSION_SETUP carrying an NTLMSSP NEGOTIATE (Type 1),
reads back the challenge, and parses it. No password is ever sent; the handshake is abandoned
after the challenge.

Hand-rolled wire format, no dependency. Best-effort: any mismatch returns None.
"""
from __future__ import annotations

import asyncio
import socket
import struct
import uuid

# NTLMSSP NEGOTIATE flags: unicode|oem|request_target|ntlm|always_sign|ext_sec|version
_NTLM_FLAGS = 0x00088207

_AV_NAMES = {1: "nb_computer", 2: "nb_domain", 3: "dns_computer", 4: "dns_domain", 5: "dns_tree"}


def _ntlm_type1() -> bytes:
    version = struct.pack("<BBHBBBB", 6, 1, 7601, 0, 0, 0, 15)
    return (b"NTLMSSP\x00" + struct.pack("<I", 1) + struct.pack("<I", _NTLM_FLAGS)
            + b"\x00" * 8 + b"\x00" * 8 + version)


def parse_type2(data: bytes, start: int = 0) -> dict | None:
    """Parse an NTLMSSP CHALLENGE (Type 2) starting at `start`. Returns names + OS, or None."""
    b = data[start:]
    if len(b) < 48 or b[:8] != b"NTLMSSP\x00" or struct.unpack_from("<I", b, 8)[0] != 2:
        return None
    try:
        flags = struct.unpack_from("<I", b, 20)[0]
        ti_len, _ti_max, ti_off = struct.unpack_from("<HHI", b, 40)
        info: dict[str, str] = {}
        if flags & 0x02000000 and len(b) >= 56:   # NEGOTIATE_VERSION
            maj, minr = b[48], b[49]
            build = struct.unpack_from("<H", b, 50)[0]
            info["os"] = f"{maj}.{minr} build {build}"
        av = b[ti_off:ti_off + ti_len]
        i = 0
        while i + 4 <= len(av):
            av_id, av_len = struct.unpack_from("<HH", av, i)
            i += 4
            if av_id == 0:
                break
            val = av[i:i + av_len]
            i += av_len
            if av_id in _AV_NAMES:
                info[_AV_NAMES[av_id]] = val.decode("utf-16-le", "replace")
        return info or None
    except (struct.error, IndexError):
        return None


def _smb2_header(command: int, message_id: int) -> bytes:
    return struct.pack("<4sHHIHHIIQIIQ16s", b"\xfeSMB", 64, 0, 0, command, 1, 0, 0,
                       message_id, 0, 0, 0, b"\x00" * 16)


def _negotiate() -> bytes:
    body = struct.pack("<HHHHI16sQHH", 36, 2, 1, 0, 0, uuid.uuid4().bytes, 0, 0x0202, 0x0210)
    return _smb2_header(0x0000, 0) + body


def _session_setup(ntlm: bytes) -> bytes:
    body = struct.pack("<HBBIIHHQ", 25, 0, 1, 0, 0, 88, len(ntlm), 0) + ntlm
    return _smb2_header(0x0001, 1) + body


def _frame(msg: bytes) -> bytes:
    return struct.pack(">I", len(msg)) + msg   # NetBIOS session header


def _recv_frame(sock: socket.socket) -> bytes:
    hdr = _recvn(sock, 4)
    if len(hdr) < 4:
        return b""
    n = struct.unpack(">I", hdr)[0] & 0x00FFFFFF
    return _recvn(sock, n)


def _recvn(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def _query(ip: str, timeout: float) -> dict | None:
    try:
        sock = socket.create_connection((ip, 445), timeout=timeout)
    except OSError:
        return None
    sock.settimeout(timeout)
    try:
        sock.sendall(_frame(_negotiate()))
        if not _recv_frame(sock):
            return None
        sock.sendall(_frame(_session_setup(_ntlm_type1())))
        resp = _recv_frame(sock)
    except OSError:
        return None
    finally:
        sock.close()
    idx = resp.find(b"NTLMSSP\x00")
    if idx < 0:
        return None
    return parse_type2(resp, idx)


async def probe(ip: str, timeout: float = 2.0) -> dict | None:
    """Return {nb_computer, nb_domain, dns_computer, dns_domain, os?} or None."""
    return await asyncio.to_thread(_query, ip, timeout)


# ---- read-only SMB security checks ----------------------------------------------------

def _smb1_negotiate() -> bytes:
    # SMB1 header (command 0x72 = negotiate) + one dialect "NT LM 0.12".
    header = struct.pack("<4sBIBHH12sHHHH", b"\xffSMB", 0x72, 0, 0x18, 0x4301, 0,
                         b"\x00" * 12, 0, 0xFFFE, 0, 0)
    dialect = b"\x02NT LM 0.12\x00"
    body = struct.pack("<B", 0) + struct.pack("<H", len(dialect)) + dialect
    return header + body


def _smb_audit_blocking(ip: str, timeout: float) -> list[dict]:
    out: list[dict] = []
    # SMB2 negotiate -> read the server's SecurityMode (signing required?).
    try:
        sock = socket.create_connection((ip, 445), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(_frame(_negotiate()))
        resp = _recv_frame(sock)
        sock.close()
    except OSError:
        resp = b""
    if resp[:4] == b"\xfeSMB" or resp[4:8] == b"\xfeSMB":
        body = resp[resp.find(b"\xfeSMB"):]
        if len(body) >= 66:
            security_mode = body[64]   # NegotiateResponse SecurityMode (first byte after 64-byte header)
            if not (security_mode & 0x02):   # SMB2_NEGOTIATE_SIGNING_REQUIRED
                out.append({"severity": "medium", "title": "SMB signing not required",
                            "evidence": "server advertises signing not required",
                            "recommendation": "Require SMB signing to prevent relay/MITM.",
                            "category": "smb"})
    # SMB1 negotiate -> if the server answers SMB1, SMBv1 is still enabled.
    try:
        sock = socket.create_connection((ip, 445), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(_frame(_smb1_negotiate()))
        r1 = _recv_frame(sock)
        sock.close()
    except OSError:
        r1 = b""
    if r1[:4] == b"\xffSMB" or r1[4:8] == b"\xffSMB":
        out.append({"severity": "high", "title": "SMBv1 enabled",
                    "evidence": "server responded to an SMBv1 negotiate",
                    "recommendation": "Disable SMBv1 (SMB1); it is obsolete and exploitable "
                                      "(e.g. EternalBlue).", "category": "smb"})
    return out


async def audit(ip: str, timeout: float = 3.0) -> list[dict]:
    """Read-only SMB checks: SMBv1 enabled, SMB signing not required."""
    return await asyncio.to_thread(_smb_audit_blocking, ip, timeout)

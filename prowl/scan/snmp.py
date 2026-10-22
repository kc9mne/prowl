"""Minimal SNMPv2c reader — fetch sysDescr/sysName with a read community, no dependencies.

Managed gear (switches, routers, printers, APs, UPSes) answers SNMP with a sysDescr that
usually names the make, model, and firmware — one of the best model signals available. This
is a read-only GET of two well-known OIDs; it changes nothing.

An SNMP agent that answers a default/guessable community (`public`) over v1/v2c is also an
exposure in its own right — Prowl records it with the service marked insecure.

Hand-rolled BER keeps the dependency list empty. Only what we need is implemented.
"""
from __future__ import annotations

import asyncio
import random
import socket
import struct

SYS_DESCR = (1, 3, 6, 1, 2, 1, 1, 1, 0)
SYS_NAME = (1, 3, 6, 1, 2, 1, 1, 5, 0)


def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = b""
    while n:
        body = bytes([n & 0xFF]) + body
        n >>= 8
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _len(len(body)) + body


def _int(n: int) -> bytes:
    if n == 0:
        return _tlv(0x02, b"\x00")
    body = b""
    tmp = n
    while tmp:
        body = bytes([tmp & 0xFF]) + body
        tmp >>= 8
    if body[0] & 0x80:            # keep it positive
        body = b"\x00" + body
    return _tlv(0x02, body)


def _oid(arcs: tuple[int, ...]) -> bytes:
    first = 40 * arcs[0] + arcs[1]
    body = bytes([first])
    for a in arcs[2:]:
        if a < 0x80:
            body += bytes([a])
        else:
            chunk = bytes([a & 0x7F])
            a >>= 7
            while a:
                chunk = bytes([(a & 0x7F) | 0x80]) + chunk
                a >>= 7
            body += chunk
    return _tlv(0x06, body)


def _build_get(community: str, oids: list[tuple[int, ...]], req_id: int) -> bytes:
    varbinds = b"".join(_tlv(0x30, _oid(o) + _tlv(0x05, b"")) for o in oids)
    pdu = _tlv(0xA0, _int(req_id) + _int(0) + _int(0) + _tlv(0x30, varbinds))  # GetRequest
    msg = _int(1) + _tlv(0x04, community.encode()) + pdu                      # version=1 (v2c)
    return _tlv(0x30, msg)


def _parse(data: bytes) -> dict:
    """Walk the response and return {oid_tuple-ish: value_str} for OCTET STRING varbinds."""
    out: dict[str, str] = {}

    def read_tlv(buf, i):
        tag = buf[i]; i += 1
        ln = buf[i]; i += 1
        if ln & 0x80:
            nb = ln & 0x7F
            ln = int.from_bytes(buf[i:i + nb], "big"); i += nb
        return tag, buf[i:i + ln], i + ln

    try:
        _, msg, _ = read_tlv(data, 0)              # outer SEQUENCE
        i = 0
        # version, community, pdu
        _, _, i = read_tlv(msg, i)                  # version
        _, _, i = read_tlv(msg, i)                  # community
        tag, pdu, _ = read_tlv(msg, i)              # PDU (0xA2 = Response)
        j = 0
        _, _, j = read_tlv(pdu, j)                  # request-id
        _, _, j = read_tlv(pdu, j)                  # error-status
        _, _, j = read_tlv(pdu, j)                  # error-index
        _, vbl, _ = read_tlv(pdu, j)                # varbind list SEQUENCE
        k = 0
        idx = 0
        while k < len(vbl):
            _, vb, k = read_tlv(vbl, k)             # one varbind SEQUENCE
            m = 0
            otag, oval, m = read_tlv(vb, m)         # OID
            vtag, vval, _ = read_tlv(vb, m)         # value
            if vtag == 0x04:                        # OCTET STRING
                out[str(idx)] = vval.decode("latin-1", "replace").strip()
            idx += 1
    except (IndexError, ValueError):
        pass
    return out


def _query(ip: str, community: str, timeout: float, port: int = 161) -> dict | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        req_id = random.randint(1, 0x7FFFFFFF)
        pkt = _build_get(community, [SYS_DESCR, SYS_NAME], req_id)
        sock.sendto(pkt, (ip, port))
        data, _ = sock.recvfrom(4096)
    except (OSError, socket.timeout):
        return None
    finally:
        sock.close()
    vals = _parse(data)
    if not vals:
        return None
    return {"community": community, "sysDescr": vals.get("0"), "sysName": vals.get("1")}


async def probe(ip: str, communities=("public",), timeout: float = 1.0, port: int = 161) -> dict | None:
    """Return {community, sysDescr, sysName} if an SNMP agent answers, else None."""
    for community in communities:
        res = await asyncio.to_thread(_query, ip, community, timeout, port)
        if res:
            return res
    return None

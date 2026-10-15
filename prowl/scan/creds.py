"""Default-credential check — "did anyone ever change the factory login?"

This is an AUTHORIZED, non-destructive audit, not an attack. It is off by default and only
runs when the operator has acknowledged authorization. Its whole purpose is to flag a device
that still accepts its documented factory default so it can be fixed (and such a device is
almost always unpatched/out-of-date too — Prowl notes that as an inference, it does not probe
firmware).

Guardrails enforced here:
  * At most TWO passwords per username (configurable down), to avoid account lockouts.
  * Stop at the first confirmed default on a host — one hit is enough to flag it.
  * Hard caps on usernames and total attempts per host; serial per host with delay + jitter.
  * Non-destructive: on success, confirm the login and immediately stop. Nothing is changed,
    no session is kept, no command is run.
  * On-link targets only (enforced by the caller passing local networks).
  * Honour lockout/rate-limit signals (HTTP 429, repeated connection refusals) and back off.
  * Only probes services that actually gate on the credential (HTTP Basic realm, SSH, Telnet).
    Form-based web logins are NOT auto-tried (too varied to do safely) — reported as a note.
  * Every attempt is handed to an audit callback with the password masked.
"""
from __future__ import annotations

import asyncio
import base64
import random
import ssl
from functools import lru_cache
from pathlib import Path

import yaml

from .model import Host

DATA = Path(__file__).resolve().parent.parent / "data" / "defaults.yaml"

MAX_PW_PER_USER = 2        # the lockout-safety cap the operator asked for
MAX_USERS_PER_HOST = 6
MAX_ATTEMPTS_PER_HOST = 10
ATTEMPT_DELAY = 0.7        # seconds between attempts on one host (serial)

HTTP_PORTS = {80, 8000, 8008, 8080, 8081, 8083, 8088, 8888, 9000}
TLS_HTTP_PORTS = {443, 4443, 8443}


@lru_cache(maxsize=1)
def _db() -> dict:
    if not DATA.exists():
        return {"generic": [], "vendors": {}, "classes": {}}
    with DATA.open(encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def mask(pw: str) -> str:
    if pw == "":
        return "(blank)"
    if len(pw) <= 2:
        return pw[0] + "*"
    return pw[0] + "*" * (len(pw) - 1)


def candidates(host: Host) -> list[tuple[str, list[str]]]:
    """Applicable (username, passwords[:MAX_PW_PER_USER]) for a host, deduped and capped."""
    db = _db()
    vendor = (host.vendor or "").lower()
    cls = (host.device_class or "").lower()
    # Order matters: vendor- and class-specific defaults come FIRST so they occupy the
    # per-username password cap ahead of the generic fallbacks (the device's own documented
    # default is the one most likely to still be set).
    sets: list[dict] = []
    for key, entries in (db.get("vendors") or {}).items():
        if key in vendor:
            sets += entries
    for key, entries in (db.get("classes") or {}).items():
        if key.lower() in cls:
            sets += entries
    sets += list(db.get("generic", []))

    merged: dict[str, list[str]] = {}
    for entry in sets:
        user = str(entry.get("user", ""))
        pws = [str(p) for p in (entry.get("passwords") or [])]
        bucket = merged.setdefault(user, [])
        for p in pws:
            if p not in bucket:
                bucket.append(p)
    out = [(u, pws[:MAX_PW_PER_USER]) for u, pws in merged.items()]
    return out[:MAX_USERS_PER_HOST]


# ---- per-protocol, non-destructive login confirmations --------------------------------

async def _http_basic_realm(ip: str, port: int, tls: bool, timeout: float) -> bool:
    """True only if an unauthenticated GET / returns 401 with a Basic challenge."""
    ctx = None
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=ip if tls else None), timeout=timeout)
        writer.write(f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode())
        await writer.drain()
        raw = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        writer.close()
    except (OSError, asyncio.TimeoutError, ssl.SSLError):
        return False
    head = raw.decode("latin-1", "replace")
    return head.startswith("HTTP/") and " 401" in head.split("\r\n")[0] and "www-authenticate: basic" in head.lower()


async def _http_basic_try(ip: str, port: int, tls: bool, user: str, pw: str, timeout: float) -> bool | None:
    """True if these creds are accepted (non-401), False if rejected, None on error/lockout."""
    ctx = None
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    token = base64.b64encode(f"{user}:{pw}".encode()).decode()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=ip if tls else None), timeout=timeout)
        req = (f"GET / HTTP/1.1\r\nHost: {ip}\r\nAuthorization: Basic {token}\r\n"
               f"Connection: close\r\n\r\n").encode()
        writer.write(req)
        await writer.drain()
        raw = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        writer.close()
    except (OSError, asyncio.TimeoutError, ssl.SSLError):
        return None
    status_line = raw.decode("latin-1", "replace").split("\r\n", 1)[0]
    if " 429" in status_line:      # rate-limited / lockout signal
        return None
    if " 401" in status_line or " 403" in status_line:
        return False
    return raw.startswith(b"HTTP/")   # 200/30x => accepted


def _ssh_try(ip: str, port: int, user: str, pw: str, timeout: float) -> bool | None:
    """Blocking SSH auth confirmation via paramiko (optional). None if paramiko missing/error."""
    try:
        import paramiko
    except ImportError:
        return None
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ip, port=port, username=user, password=pw, timeout=timeout,
                       allow_agent=False, look_for_keys=False, banner_timeout=timeout, auth_timeout=timeout)
        return True
    except paramiko.AuthenticationException:
        return False
    except Exception:  # noqa: BLE001 - unreachable / protocol error / lockout
        return None
    finally:
        try:
            client.close()
        except Exception:  # noqa: BLE001
            pass


async def _telnet_try(ip: str, port: int, user: str, pw: str, timeout: float) -> bool | None:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
    except (OSError, asyncio.TimeoutError):
        return None
    try:
        async def expect(tokens, t):
            buf = b""
            try:
                while True:
                    chunk = await asyncio.wait_for(reader.read(256), timeout=t)
                    if not chunk:
                        break
                    buf += chunk
                    low = buf.lower()
                    if any(tok in low for tok in tokens):
                        return low
            except asyncio.TimeoutError:
                pass
            return buf.lower()
        await expect([b"login:", b"username:"], timeout)
        writer.write(user.encode() + b"\r\n"); await writer.drain()
        await expect([b"password:"], timeout)
        writer.write(pw.encode() + b"\r\n"); await writer.drain()
        resp = await expect([b"#", b"$", b">", b"incorrect", b"fail", b"login:"], timeout)
        if any(b in resp for b in (b"incorrect", b"fail", b"login:", b"username:")):
            return False
        return any(p in resp for p in (b"#", b"$", b">", b"welcome"))
    except OSError:
        return None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, asyncio.TimeoutError):
            pass


def _targets(host: Host) -> list[tuple[str, int, bool]]:
    """Which (method, port, tls) to try, cheapest/safest first; one web port is enough."""
    ports = {s.port for s in host.services}
    out: list[tuple[str, int, bool]] = []
    web = sorted(p for p in ports if p in HTTP_PORTS)
    webs = sorted(p for p in ports if p in TLS_HTTP_PORTS)
    if web:
        out.append(("http", web[0], False))
    elif webs:
        out.append(("http", webs[0], True))
    if 23 in ports:
        out.append(("telnet", 23, False))
    if 22 in ports:
        out.append(("ssh", 22, False))
    return out


async def check_host(host: Host, *, timeout: float = 3.0, audit=None, cancel=None) -> None:
    """Run the default-credential check on one host, in place. Serial, capped, non-destructive."""
    host.cred_checked = True
    targets = _targets(host)
    if not targets:
        return
    cands = candidates(host)
    attempts = 0

    def log(method, port, user, pw, result):
        if audit:
            audit("cred-check", f"{host.ip}:{port} {method} {user}/{mask(pw)} -> {result}")

    for method, port, tls in targets:
        if method == "http" and not await _http_basic_realm(host.ip, port, tls, timeout):
            log("http", port, "-", "", "no-basic-auth")
            continue   # not basic-auth gated (maybe a form) — don't guess
        service_dead = False
        for user, pws in cands:
            if service_dead:
                break
            for pw in pws:
                if cancel is not None and cancel.is_set():
                    return
                if attempts >= MAX_ATTEMPTS_PER_HOST:
                    return
                attempts += 1
                if method == "http":
                    res = await _http_basic_try(host.ip, port, tls, user, pw, timeout)
                elif method == "ssh":
                    res = await asyncio.to_thread(_ssh_try, host.ip, port, user, pw, timeout)
                else:
                    res = await _telnet_try(host.ip, port, user, pw, timeout)
                log(method, port, user, pw, {True: "ACCEPTED", False: "rejected", None: "error/skip"}[res])
                if res is True:
                    host.default_creds = True
                    host.default_cred_detail = {"service": method, "port": port, "username": user, "password": pw}
                    return   # one confirmed default is enough — stop immediately
                if res is None:   # error or lockout signal: abandon this whole service
                    service_dead = True
                    break
                await asyncio.sleep(ATTEMPT_DELAY + random.uniform(0, 0.3))
    return

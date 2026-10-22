"""Optional online MAC-prefix -> vendor lookup (maclookup.app), used only to fill offline gaps.

Prowl is offline-first: the bundled/updated OUI database is always consulted first. This
module is a last resort for MAC prefixes the local database doesn't know, and it is OFF by
default. It matters because it sends the client's device MAC prefixes to a third-party web
service — a confidentiality consideration during an assessment — so it is explicit opt-in,
rate-limited, capped, and every prefix it resolves is written back into the local database
(via oui.add_user_entries) so the next scan needs no network.

No dependency: a plain stdlib HTTPS GET. An API key (env PROWL_MACLOOKUP_KEY) raises the
free-tier rate limit. Any error degrades to "unknown" — it never fails a scan.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import urllib.error
import urllib.request

from . import oui

log = logging.getLogger("prowl.macvendor")

API = "https://api.maclookup.app/v2/macs/"
MAX_LOOKUPS = 256          # never fan out to more than this many unique prefixes
FREE_DELAY = 0.6           # ~2 req/s free-tier budget


def _parse(body: bytes) -> str | None:
    """Vendor company name from an API response, or None if not found / malformed."""
    try:
        d = json.loads(body.decode("utf-8", "replace"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(d, dict):
        return None
    if d.get("success") and d.get("found") and d.get("company"):
        return str(d["company"]).strip() or None
    return None


def _fetch(prefix: str, timeout: float, api_key: str | None) -> str | None | bool:
    """Return vendor str, None (not found), or False (rate-limited / transient — stop)."""
    url = API + prefix
    if api_key:
        url += f"?apiKey={api_key}"
    req = urllib.request.Request(url, headers={"User-Agent": "Prowl/0.1", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return _parse(resp.read(4096))
    except urllib.error.HTTPError as e:
        if e.code in (429, 403):     # rate-limited / quota — back off and stop
            return False
        return None
    except (urllib.error.URLError, OSError, ValueError):
        return None


def _enrich_blocking(prefixes: list[str], timeout: float, api_key: str | None) -> dict[str, str]:
    found: dict[str, str] = {}
    for i, prefix in enumerate(prefixes[:MAX_LOOKUPS]):
        res = _fetch(prefix, timeout, api_key)
        if res is False:             # rate-limited: stop here, keep what we have
            log.info("online MAC lookup throttled after %d prefixes", i)
            break
        if res:
            found[prefix] = res
        if not api_key and i < len(prefixes) - 1:
            time.sleep(FREE_DELAY)
    return found


async def enrich_hosts(hosts, *, timeout: float = 4.0, audit=None) -> int:
    """Fill host.vendor for hosts whose MAC the offline DB missed. Returns count resolved.

    Caches every hit into the local OUI database so it is offline next time.
    """
    api_key = os.environ.get("PROWL_MACLOOKUP_KEY") or None
    # unique OUI prefixes we still can't name, mapped to the hosts that need them
    need: dict[str, list] = {}
    for h in hosts:
        if h.mac and not h.vendor:
            prefix = h.mac.replace(":", "").replace("-", "").upper()[:6]
            need.setdefault(prefix, []).append(h)
    if not need:
        return 0
    if audit:
        audit("online-oui", f"querying maclookup.app for {len(need)} unknown MAC prefix(es)")
    resolved = await asyncio.to_thread(_enrich_blocking, list(need), timeout, api_key)
    if resolved:
        oui.add_user_entries(resolved)   # persist for offline reuse
    count = 0
    for prefix, vendor in resolved.items():
        for h in need.get(prefix, []):
            h.vendor = vendor
            count += 1
    return count

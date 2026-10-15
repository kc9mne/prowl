"""Offline MAC-prefix -> vendor lookup.

Ships a starter `data/oui.csv` (prefix,vendor where prefix is the 6-hex-digit OUI).
It is intentionally a subset of the IEEE registry so Prowl stays small and works with no
internet at a client site; `prowl update-oui` (TODO) can refresh it from a local copy of
the IEEE OUI file. Lookup is also MA-M/MA-S aware only at the /24 OUI level for now.
"""
from __future__ import annotations

import csv
import re
from functools import lru_cache
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "data" / "oui.csv"


@lru_cache(maxsize=1)
def _table() -> dict[str, str]:
    table: dict[str, str] = {}
    if not DATA.exists():
        return table
    with DATA.open(encoding="utf-8", newline="") as f:
        for row in csv.reader(f):
            if len(row) < 2 or row[0].startswith("#"):
                continue
            prefix = re.sub(r"[^0-9A-F]", "", row[0].strip().upper())
            if len(prefix) == 6:
                table[prefix] = row[1].strip()
    return table


def lookup(mac: str | None) -> str | None:
    """Vendor for a normalized MAC, or None. A locally-administered MAC returns a marker."""
    if not mac:
        return None
    hexmac = mac.replace(":", "").replace("-", "").upper()
    if len(hexmac) < 6:
        return None
    # Locally-administered bit (second-least-significant bit of the first octet) => randomized MAC.
    first = int(hexmac[0:2], 16)
    if first & 0x02:
        return "(locally administered / randomized)"
    return _table().get(hexmac[:6])

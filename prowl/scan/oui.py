"""Offline MAC-prefix -> vendor lookup.

Ships a starter `data/oui.csv` (prefix,vendor where prefix is the 6-hex-digit OUI). It is a
subset of the IEEE registry so Prowl stays small and works with no internet at a client site.
`prowl update-oui PATH` ingests a local copy of the official IEEE file (oui.csv or oui.txt)
into a user-data database that takes precedence over the bundled subset.
"""
from __future__ import annotations

import csv
import os
import re
from functools import lru_cache
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "data" / "oui.csv"

# Canonical full OUI database (IEEE). Override with PROWL_OUI_URL or the UI field.
DEFAULT_OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"


def user_db_path() -> Path:
    from ..store import default_db_path
    return default_db_path().parent / "oui.csv"


def _load_csv(path: Path, table: dict[str, str]) -> None:
    if not path.exists():
        return
    with path.open(encoding="utf-8", newline="") as f:
        for row in csv.reader(f):
            if len(row) < 2 or row[0].startswith("#"):
                continue
            prefix = re.sub(r"[^0-9A-F]", "", row[0].strip().upper())
            if len(prefix) == 6:
                table[prefix] = row[1].strip()


@lru_cache(maxsize=1)
def _table() -> dict[str, str]:
    table: dict[str, str] = {}
    _load_csv(DATA, table)             # bundled subset first
    _load_csv(user_db_path(), table)   # user database overrides/extends
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


_HEADER_WORDS = ("assignment", "organization", "vendor name", "assignment",
                 "vendor", "company", "organization name")


def parse_ieee(text: str) -> dict[str, str]:
    """Parse an OUI export into {prefix(6-hex): vendor}.

    Handles the IEEE `oui.txt` (hex) format, the IEEE `oui.csv`
    (Registry,Assignment,Organization Name,...) format, and the maclookup.app CSV
    (Mac Prefix,Vendor Name,...) format — or any CSV with a MAC-prefix column and a
    vendor-name column. Longer MA-M/MA-S prefixes are truncated to the 24-bit OUI.
    """
    out: dict[str, str] = {}
    # 1) IEEE oui.txt lines: "FC-FB-FB   (hex)\t\tCisco Systems, Inc"
    for m in re.finditer(r"(?im)^\s*([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.+)$", text):
        out[m.group(1).replace("-", "")] = m.group(2).strip()
    if out:
        return out

    # 2) CSV of any layout: find the prefix column and the vendor column.
    rows = list(csv.reader(text.splitlines()))
    if not rows:
        return out
    header = [c.strip().lower() for c in rows[0]]
    prefix_idx = vendor_idx = None
    for i, c in enumerate(header):
        if prefix_idx is None and any(k in c for k in ("prefix", "assignment", "oui", "mac")):
            prefix_idx = i
        if vendor_idx is None and any(k in c for k in ("vendor", "organization", "company", "manufacturer")):
            vendor_idx = i
    has_header = prefix_idx is not None or vendor_idx is not None
    for row in (rows[1:] if has_header else rows):
        prefix = vendor = None
        if prefix_idx is not None and vendor_idx is not None and max(prefix_idx, vendor_idx) < len(row):
            prefix, vendor = row[prefix_idx], row[vendor_idx]
        else:
            for j, field in enumerate(row):     # heuristic: first hex-prefix field, next text field
                looks_prefix = re.fullmatch(r"[0-9A-Fa-f][0-9A-Fa-f:.\- ]{4,}", field.strip() or "")
                if looks_prefix and len(re.sub(r"[^0-9A-Fa-f]", "", field)) >= 6:
                    prefix = field
                    vendor = next((row[k].strip() for k in range(j + 1, len(row)) if row[k].strip()), None)
                    break
        hexp = re.sub(r"[^0-9A-F]", "", (prefix or "").upper())[:6]
        vendor = (vendor or "").strip()
        if len(hexp) == 6 and vendor and vendor.lower() not in _HEADER_WORDS:
            out[hexp] = vendor
    return out


def add_user_entries(mapping: dict[str, str]) -> int:
    """Merge {prefix(6-hex): vendor} into the user OUI database (for caching online lookups)."""
    clean = {re.sub(r"[^0-9A-F]", "", p.upper()): v for p, v in mapping.items() if v}
    clean = {p: v for p, v in clean.items() if len(p) == 6}
    if not clean:
        return 0
    dest = user_db_path()
    dest.parent.mkdir(parents=True, exist_ok=True)
    existing: dict[str, str] = {}
    _load_csv(dest, existing)
    existing.update(clean)
    with dest.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["# Prowl user OUI database"])
        for prefix, org in sorted(existing.items()):
            w.writerow([prefix, org])
    _table.cache_clear()
    return len(clean)


def _write_user_db(table: dict[str, str], note: str) -> int:
    dest = user_db_path()
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow([f"# Prowl user OUI database — {note}"])
        for prefix, org in sorted(table.items()):
            w.writerow([prefix, org])
    _table.cache_clear()
    return len(table)


def update_from_text(text: str, note: str = "uploaded") -> int:
    """Parse an OUI export and replace the user database. Returns the number of prefixes."""
    table = parse_ieee(text)
    if not table:
        raise ValueError("no OUI records found — expected an IEEE oui.csv/oui.txt or maclookup.app CSV")
    return _write_user_db(table, note)


def update_from_ieee(path: str | Path) -> int:
    """Ingest a local OUI file into the user database."""
    return update_from_text(Path(path).read_text(encoding="utf-8", errors="replace"), f"from {path}")


def update_from_url(url: str | None = None, timeout: float = 60.0) -> int:
    """Download a full OUI database and ingest it. Returns the number of prefixes."""
    import urllib.request
    url = url or os.environ.get("PROWL_OUI_URL") or DEFAULT_OUI_URL
    req = urllib.request.Request(url, headers={"User-Agent": "Prowl/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        text = resp.read().decode("utf-8", "replace")
    return update_from_text(text, f"from {url}")


def status() -> dict:
    """Current database size and whether a user database is present."""
    return {"prefixes": len(_table()), "user_db": str(user_db_path()),
            "has_user_db": user_db_path().exists()}

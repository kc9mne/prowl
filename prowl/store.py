"""Persistence + baseline diff — so a repeat visit shows what changed since last time.

Every completed real scan is saved to a small SQLite file (demo scans are not). When a new
scan of the same subnet finishes, Prowl diffs it against the most recent prior scan of that
subnet and reports what is new, gone, or changed.

Hosts are keyed by MAC when known (stable across DHCP changes) and fall back to IP, so a
device that merely got a new lease reads as *changed* (IP changed), not new + gone.
"""
from __future__ import annotations

import json
import os
import platform
import sqlite3
import time
from pathlib import Path

WINDOWS = platform.system() == "Windows"
MACOS = platform.system() == "Darwin"


def default_db_path() -> Path:
    if WINDOWS:
        base = Path(os.environ.get("APPDATA") or Path.home())
    elif MACOS:
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share"))
    d = base / "prowl"
    d.mkdir(parents=True, exist_ok=True)
    return d / "prowl.db"


class Store:
    def __init__(self, path: str | os.PathLike):
        self.path = str(path)
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subnet TEXT NOT NULL,
                mode TEXT,
                started REAL,
                finished REAL,
                gateway TEXT,
                host_count INTEGER,
                default_cred_hits INTEGER,
                json TEXT NOT NULL
            )""")
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_scans_subnet ON scans(subnet, started)")
        self.db.commit()

    def save(self, result_dict: dict) -> int:
        hits = sum(1 for h in result_dict.get("hosts", []) if h.get("default_creds"))
        cur = self.db.execute(
            "INSERT INTO scans (subnet, mode, started, finished, gateway, host_count, default_cred_hits, json)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (result_dict.get("subnet"), result_dict.get("mode"), result_dict.get("started"),
             result_dict.get("finished"), result_dict.get("gateway"), result_dict.get("count"),
             hits, json.dumps(result_dict)))
        self.db.commit()
        return cur.lastrowid

    def list(self, subnet: str | None = None, limit: int = 100) -> list[dict]:
        if subnet:
            rows = self.db.execute(
                "SELECT id, subnet, mode, started, finished, host_count, default_cred_hits"
                " FROM scans WHERE subnet=? ORDER BY started DESC LIMIT ?", (subnet, limit))
        else:
            rows = self.db.execute(
                "SELECT id, subnet, mode, started, finished, host_count, default_cred_hits"
                " FROM scans ORDER BY started DESC LIMIT ?", (limit,))
        return [dict(r) for r in rows]

    def get(self, scan_id: int) -> dict | None:
        row = self.db.execute("SELECT json FROM scans WHERE id=?", (scan_id,)).fetchone()
        return json.loads(row["json"]) if row else None

    def previous(self, subnet: str, before: float) -> dict | None:
        """Most recent scan of this subnet strictly before `before` (the current scan's start)."""
        row = self.db.execute(
            "SELECT id, started, json FROM scans WHERE subnet=? AND started < ? ORDER BY started DESC LIMIT 1",
            (subnet, before)).fetchone()
        if not row:
            return None
        d = json.loads(row["json"])
        d["_id"] = row["id"]
        return d

    def close(self):
        self.db.close()


def _key(host: dict) -> str:
    return host.get("mac") or f"ip:{host.get('ip')}"


def _label(host: dict) -> str:
    return host.get("hostname") or host.get("ip") or host.get("mac") or "?"


def _host_changes(base: dict, cur: dict) -> list[str]:
    changes: list[str] = []
    if base.get("ip") != cur.get("ip"):
        changes.append(f"IP {base.get('ip')} → {cur.get('ip')}")
    b_ports = {s["port"] for s in base.get("services", [])}
    c_ports = {s["port"] for s in cur.get("services", [])}
    opened = sorted(c_ports - b_ports)
    closed = sorted(b_ports - c_ports)
    if opened:
        changes.append("opened " + ", ".join(map(str, opened)))
    if closed:
        changes.append("closed " + ", ".join(map(str, closed)))
    if base.get("device_class") != cur.get("device_class") and cur.get("device_class"):
        changes.append(f"class {base.get('device_class') or '?'} → {cur.get('device_class')}")
    if not base.get("default_creds") and cur.get("default_creds"):
        changes.append("now accepts a default login")
    if base.get("default_creds") and not cur.get("default_creds"):
        changes.append("default login no longer works")
    return changes


def diff(current: dict, baseline: dict) -> dict:
    """Compare two ScanResult dicts. Returns new / gone / changed plus a per-IP delta map."""
    base_hosts = {_key(h): h for h in baseline.get("hosts", [])}
    cur_hosts = {_key(h): h for h in current.get("hosts", [])}

    new, gone, changed = [], [], []
    delta: dict[str, str] = {}

    for k, h in cur_hosts.items():
        if k not in base_hosts:
            new.append({"ip": h.get("ip"), "label": _label(h)})
            delta[h["ip"]] = "new"
        else:
            ch = _host_changes(base_hosts[k], h)
            if ch:
                changed.append({"ip": h.get("ip"), "label": _label(h), "changes": ch})
                delta[h["ip"]] = "changed"
    for k, h in base_hosts.items():
        if k not in cur_hosts:
            gone.append({"ip": h.get("ip"), "label": _label(h), "mac": h.get("mac")})

    return {
        "baseline_id": baseline.get("_id"),
        "baseline_started": baseline.get("started"),
        "new": sorted(new, key=lambda x: x["ip"] or ""),
        "gone": sorted(gone, key=lambda x: x["ip"] or ""),
        "changed": sorted(changed, key=lambda x: x["ip"] or ""),
        "unchanged": len(cur_hosts) - len(new) - len(changed),
        "delta": delta,
        "generated": time.time(),
    }

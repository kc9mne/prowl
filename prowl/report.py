"""Turn a ScanResult into a shareable after-action report: JSON, CSV, or standalone HTML."""
from __future__ import annotations

import csv
import datetime
import html
import io
import json

from .scan.model import ScanResult


def to_json(result: ScanResult) -> str:
    return json.dumps(result.as_dict(), indent=2)


def to_csv(result: ScanResult) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["ip", "mac", "vendor", "hostname", "gateway", "device_class", "model",
                "open_ports", "default_creds", "default_login", "rtt_ms", "sources"])
    for h in sorted(result.hosts, key=lambda h: h.ip_sort_key):
        d = h.default_cred_detail or {}
        login = f"{d['username']}:{d['password']}@{d['service']}:{d['port']}" if d else ""
        w.writerow([
            h.ip, h.mac or "", h.vendor or "", h.hostname or "",
            "yes" if h.is_gateway else "", h.device_class or "", h.model or "",
            " ".join(str(s.port) for s in h.services),
            "YES" if h.default_creds else "", login, h.rtt_ms if h.rtt_ms is not None else "",
            " ".join(h.sources),
        ])
    return buf.getvalue()


def to_html(result: ScanResult) -> str:
    d = result.as_dict()
    when = datetime.datetime.fromtimestamp(result.started).strftime("%Y-%m-%d %H:%M")
    rows = []
    for h in d["hosts"]:
        ports = ", ".join(str(s["port"]) for s in h["services"]) or "—"
        det = h.get("default_cred_detail") or {}
        flag = ""
        if h["default_creds"]:
            cred = f" ({html.escape(det['username'])}:{html.escape(str(det['password']))})" if det else ""
            flag = f' <strong style="color:#c0392b">DEFAULT CREDS{cred}</strong>'
        gw = " (gateway)" if h["is_gateway"] else ""
        rows.append(
            f"<tr><td>{html.escape(h['ip'])}{gw}</td>"
            f"<td>{html.escape(h['mac'] or '—')}</td>"
            f"<td>{html.escape(h['vendor'] or '—')}</td>"
            f"<td>{html.escape(h['hostname'] or '—')}</td>"
            f"<td>{html.escape(h['device_class'] or '—')}</td>"
            f"<td>{html.escape(ports)}{flag}</td></tr>")
    return f"""<!doctype html><meta charset="utf-8">
<title>Prowl report — {html.escape(d['subnet'])}</title>
<style>
 body{{font:14px/1.5 system-ui,sans-serif;margin:2rem;color:#1a1a1a}}
 h1{{font-size:1.4rem}} .meta{{color:#555}}
 table{{border-collapse:collapse;width:100%;margin-top:1rem}}
 th,td{{border:1px solid #ddd;padding:.4rem .6rem;text-align:left}}
 th{{background:#f4f4f4}} tr:nth-child(even){{background:#fafafa}}
</style>
<h1>Prowl network baseline</h1>
<p class="meta">Subnet <b>{html.escape(d['subnet'])}</b> · mode {html.escape(d['mode'])} ·
 {d['count']} hosts · gateway {html.escape(d['gateway'] or '—')} · {when}</p>
<table><thead><tr><th>IP</th><th>MAC</th><th>Vendor</th><th>Hostname</th>
 <th>Class</th><th>Open ports</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<p class="meta">{html.escape(' '.join(d['notes']))}</p>
"""

"""Turn a ScanResult into a shareable after-action report: JSON, CSV, or standalone HTML."""
from __future__ import annotations

import csv
import datetime
import html
import io
import json

from . import assess
from .scan.model import ScanResult

_SEV_COLOR = {"critical": "#8e1b1b", "high": "#c0392b", "medium": "#b7791f",
              "low": "#2b6cb0", "info": "#6b7480"}


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


def to_assessment_html(result: ScanResult) -> str:
    """A security-assessment overview: executive summary, ranked findings, then inventory."""
    d = result.as_dict()
    flist = assess.findings(d)
    s = assess.summary(d, flist)
    when = datetime.datetime.fromtimestamp(result.started).strftime("%Y-%m-%d %H:%M")

    tiles = "".join(
        f'<div class="tile" style="border-color:{_SEV_COLOR[sev]}">'
        f'<div class="num" style="color:{_SEV_COLOR[sev]}">{s["counts"].get(sev,0)}</div>'
        f'<div class="lbl">{sev}</div></div>'
        for sev in ("critical", "high", "medium", "low"))

    def finding_rows():
        if not flist:
            return '<tr><td colspan="4">No findings — no exposed-service or default-credential issues observed.</td></tr>'
        out = []
        for f in flist:
            c = _SEV_COLOR[f["severity"]]
            out.append(
                f'<tr><td><span class="sev" style="background:{c}">{f["severity"].upper()}</span></td>'
                f'<td><b>{html.escape(f["title"])}</b><div class="ev">{html.escape(f["evidence"])}</div></td>'
                f'<td>{html.escape(f["host"] or "")}<div class="ev">{html.escape(f["ip"] or "")}</div></td>'
                f'<td>{html.escape(f["recommendation"])}</td></tr>')
        return "".join(out)

    inv = []
    for h in d["hosts"]:
        ports = ", ".join(str(x["port"]) for x in h["services"]) or "—"
        flag = ' <b style="color:#c0392b">DEFAULT CREDS</b>' if h["default_creds"] else ""
        inv.append(f"<tr><td>{html.escape(h['ip'])}{' (gw)' if h['is_gateway'] else ''}</td>"
                   f"<td>{html.escape(h['mac'] or '—')}</td><td>{html.escape(h['vendor'] or '—')}</td>"
                   f"<td>{html.escape(h['device_class'] or '—')}</td>"
                   f"<td>{html.escape(ports)}{flag}</td></tr>")

    dc = s["default_cred_hosts"]
    dc_line = (f'<p class="alert">{len(dc)} device(s) accept a factory default login: '
               f'{html.escape(", ".join(dc))}. These are the priority — such devices are also '
               f'likely unpatched.</p>') if dc else ""

    return f"""<!doctype html><meta charset="utf-8">
<title>Prowl security assessment — {html.escape(d['subnet'])}</title>
<style>
 body{{font:14px/1.55 system-ui,-apple-system,Segoe UI,sans-serif;margin:2rem;color:#1a1a1a;max-width:1000px}}
 h1{{font-size:1.5rem;margin-bottom:.2rem}} h2{{font-size:1.1rem;margin-top:1.8rem;border-bottom:1px solid #ddd;padding-bottom:.2rem}}
 .meta{{color:#555}} .alert{{background:#fdecea;border:1px solid #f5c6cb;padding:.6rem .8rem;border-radius:7px}}
 .tiles{{display:flex;gap:.8rem;margin:1rem 0}}
 .tile{{border:2px solid;border-radius:10px;padding:.6rem 1rem;text-align:center;min-width:90px}}
 .tile .num{{font-size:1.8rem;font-weight:700;line-height:1}} .tile .lbl{{text-transform:uppercase;font-size:.72rem;color:#555}}
 table{{border-collapse:collapse;width:100%;margin-top:.6rem}}
 th,td{{border:1px solid #ddd;padding:.45rem .6rem;text-align:left;vertical-align:top}}
 th{{background:#f4f4f4}} tr:nth-child(even){{background:#fafafa}}
 .sev{{color:#fff;border-radius:4px;padding:.1rem .4rem;font-size:.72rem;font-weight:700}}
 .ev{{color:#666;font-size:.82rem;font-family:ui-monospace,monospace}}
 @media print{{body{{margin:0}}}}
</style>
<h1>Network Security Assessment</h1>
<p class="meta">Subnet <b>{html.escape(d['subnet'])}</b> · {s['hosts_total']} devices ·
 scanned {when} · generated by Prowl</p>

<h2>Executive summary</h2>
<div class="tiles">{tiles}</div>
<p>{s['total_findings']} finding(s) across {s['hosts_affected']} of {s['hosts_total']} devices.</p>
{dc_line}

<h2>Findings</h2>
<table><thead><tr><th>Severity</th><th>Finding</th><th>Device</th><th>Recommendation</th></tr></thead>
<tbody>{finding_rows()}</tbody></table>

<h2>Device inventory</h2>
<table><thead><tr><th>IP</th><th>MAC</th><th>Vendor</th><th>Class</th><th>Open ports</th></tr></thead>
<tbody>{''.join(inv)}</tbody></table>
<p class="meta">Findings are derived from observed open ports, banners, and confirmed default
 logins. Device class/model are best-guess. This is a point-in-time baseline, not a full
 penetration test.</p>
"""

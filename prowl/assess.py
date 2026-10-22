"""Derive a ranked list of security findings from a scan result.

Everything here is a conclusion drawn from what the scan *observed* (open ports, banners,
confirmed default logins) — no new network traffic. Findings are deduplicated per host and
ranked by severity so the assessment report can lead with what matters.

A finding is: {severity, title, host, ip, evidence, recommendation, category}.
"""
from __future__ import annotations

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _ports(host: dict) -> dict:
    return {s["port"]: s for s in host.get("services", [])}


def findings(result: dict) -> list[dict]:
    out: list[dict] = []

    def add(host, severity, title, evidence, rec, category):
        out.append({"severity": severity, "title": title,
                    "host": host.get("hostname") or host.get("ip"), "ip": host.get("ip"),
                    "evidence": evidence, "recommendation": rec, "category": category})

    for h in result.get("hosts", []):
        svc = _ports(h)
        label = f"{h.get('device_class') or 'device'} {h.get('vendor') or ''}".strip()

        # 0) Structured findings from the read-only vuln probes (TLS, SMB, data stores).
        for v in h.get("vulns", []):
            add(h, v.get("severity", "low"), v.get("title", "Finding"), v.get("evidence", ""),
                v.get("recommendation", ""), v.get("category", "vuln"))

        # 1) Default credentials — the headline finding.
        if h.get("default_creds"):
            d = h.get("default_cred_detail") or {}
            login = f"{d.get('username')} : {d.get('password') or '(blank)'}" if d else "a documented default"
            add(h, "critical", "Accepts default credentials",
                f"{label} — login {login} via {d.get('service','?')}/{d.get('port','?')}",
                "Change the credentials immediately. A device still on defaults is almost "
                "certainly also behind on firmware/security patches.", "default-credentials")

        # 2) Service-level exposures.
        for port, s in svc.items():
            name = (s.get("name") or "").lower()
            banner = s.get("banner") or ""
            if port == 23 or name == "telnet":
                add(h, "high", "Cleartext management (Telnet)",
                    f"Telnet open on {port}", "Disable Telnet; manage over SSH instead.", "cleartext")
            elif port == 21 or name == "ftp":
                add(h, "medium", "Cleartext file transfer (FTP)",
                    f"FTP open on {port}", "Disable FTP or replace with SFTP/FTPS.", "cleartext")
            elif name == "snmp":
                add(h, "high", "SNMP answers a default community",
                    f"SNMP v1/v2c readable ('{banner[:60]}')",
                    "Change the community string, restrict SNMP by ACL, and prefer SNMPv3.", "snmp")
            elif port == 5900 or name == "vnc":
                add(h, "high", "VNC exposed",
                    f"VNC open on {port}", "Restrict VNC to a management VLAN/VPN and require a strong "
                    "password; many VNC servers allow unauthenticated access.", "remote-access")
            elif port == 3389 or name == "rdp":
                add(h, "medium", "RDP exposed on the LAN",
                    f"RDP open on {port}", "Restrict RDP, require Network Level Authentication, and keep "
                    "it patched.", "remote-access")
            elif port == 445 or name == "smb":
                add(h, "low", "SMB file sharing exposed",
                    f"SMB open on {port}" + (f" — {banner}" if banner else ""),
                    "Ensure SMB signing is required, guest/null sessions are disabled, and SMBv1 is off.",
                    "smb")
            elif port == 9100 or name == "jetdirect":
                add(h, "low", "Unauthenticated raw printing",
                    f"JetDirect/raw print open on {port}", "Restrict port 9100 and enable the printer's "
                    "access controls.", "printer")
            elif port == 554 or name == "rtsp":
                add(h, "medium", "Camera stream (RTSP) exposed",
                    f"RTSP open on {port}", "Require authentication on the stream and restrict access.",
                    "camera")
            elif name == "http" and h.get("device_class") and any(
                    k in h["device_class"] for k in ("router", "switch", "gear", "printer", "camera",
                                                      "firewall", "ap", "gateway")):
                add(h, "low", "Unencrypted web management interface",
                    f"HTTP admin on {port}" + (f" — {banner}" if banner else ""),
                    "Use HTTPS for the management UI and restrict it to a management network.", "cleartext")

    seen = set()
    deduped = []
    for f in out:
        key = (f["ip"], f["title"])
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    deduped.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["ip"] or ""))
    return deduped


def summary(result: dict, flist: list[dict]) -> dict:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in flist:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    affected = {f["ip"] for f in flist}
    default_cred_hosts = sorted({h["ip"] for h in result.get("hosts", []) if h.get("default_creds")})
    return {
        "counts": counts,
        "total_findings": len(flist),
        "hosts_total": result.get("count", len(result.get("hosts", []))),
        "hosts_affected": len(affected),
        "default_cred_hosts": default_cred_hosts,
    }

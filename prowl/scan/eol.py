"""End-of-life / unsupported software detection from observed banners and OS strings.

A device running software past its support date gets no security patches, so it is
inherently exposed regardless of any specific CVE. This is a conservative, offline check:
it only flags versions that are clearly out of support, and it is explicit that "unknown"
means no finding (never a false "unsupported").

Produces the same finding dicts as the vuln probes.
"""
from __future__ import annotations

import re

from .model import Host


def _finding(sev, title, ev, rec, cat="eol"):
    return {"severity": sev, "title": title, "evidence": ev, "recommendation": rec, "category": cat}


# Windows NT build number -> (label, status). status: "eol" (clearly unsupported for both
# client and server) or "old-client" (client build EOL; shared server build excluded).
# Unknown builds are intentionally absent -> no finding.
WINDOWS_BUILDS: dict[int, tuple[str, str]] = {
    2600: ("Windows XP", "eol"), 3790: ("Windows Server 2003 / XP x64", "eol"),
    6000: ("Windows Vista", "eol"), 6001: ("Windows Vista SP1 / Server 2008", "eol"),
    6002: ("Windows Vista SP2 / Server 2008 SP2", "eol"),
    7600: ("Windows 7 / Server 2008 R2", "eol"), 7601: ("Windows 7 SP1 / Server 2008 R2 SP1", "eol"),
    9200: ("Windows 8 / Server 2012", "eol"), 9600: ("Windows 8.1 / Server 2012 R2", "eol"),
    10240: ("Windows 10 1507", "old-client"), 10586: ("Windows 10 1511", "old-client"),
    15063: ("Windows 10 1703", "old-client"), 16299: ("Windows 10 1709", "old-client"),
    17134: ("Windows 10 1803", "old-client"), 18362: ("Windows 10 1903", "old-client"),
    18363: ("Windows 10 1909", "old-client"), 19041: ("Windows 10 2004", "old-client"),
    19042: ("Windows 10 20H2", "old-client"), 19043: ("Windows 10 21H1", "old-client"),
    # 14393 (Server 2016) and 17763 (Server 2019) are deliberately NOT listed as EOL.
}

# High-confidence EOL software by banner substring (lowercased) -> (severity, label).
BANNER_EOL = [
    ("apache/2.0", "Apache httpd 2.0 (end-of-life)"),
    ("apache/2.2", "Apache httpd 2.2 (end-of-life 2017)"),
    ("microsoft-iis/5.", "IIS 5.x (end-of-life)"),
    ("microsoft-iis/6.", "IIS 6.0 / Server 2003 (end-of-life)"),
    ("microsoft-iis/7.", "IIS 7.x / Server 2008 (end-of-life)"),
    ("php/5.", "PHP 5.x (end-of-life)"),
    ("openssl/0.", "OpenSSL 0.x (end-of-life)"),
    ("openssl/1.0", "OpenSSL 1.0.x (end-of-life)"),
    ("lighttpd/1.3", "lighttpd 1.3 (end-of-life)"),
    ("proftpd 1.2", "ProFTPD 1.2 (end-of-life)"),
    ("exim 4.6", "Exim 4.6x (very old)"),
]
# OpenSSH older than 7.0 is very old; captured with a regex below.
_OLD_OPENSSH = re.compile(r"openssh[_/]([1-6])\.")


def check(host: Host) -> list[dict]:
    out: list[dict] = []
    banners = " ".join(s.banner for s in host.services if s.banner)
    low = banners.lower()

    # Windows build from the SMB OS string ("OS 10.0 build 19045") or any "build NNNNN".
    m = re.search(r"build (\d{4,5})", low)
    if m:
        build = int(m.group(1))
        info = WINDOWS_BUILDS.get(build)
        if info and info[1] == "eol":
            out.append(_finding("high", "Unsupported Windows version",
                                f"{info[0]} (build {build}) — no security updates",
                                "Upgrade to a supported Windows release."))
        elif info and info[1] == "old-client":
            out.append(_finding("medium", "Likely end-of-life Windows 10 build",
                                f"{info[0]} (build {build}) — client builds past this are unsupported",
                                "Update to the current Windows 10/11 feature update (or confirm it is a "
                                "still-supported Server build)."))

    for needle, label in BANNER_EOL:
        if needle in low:
            out.append(_finding("medium", "End-of-life software",
                                label, "Upgrade to a supported, patched version."))
    mo = _OLD_OPENSSH.search(low)
    if mo:
        out.append(_finding("medium", "Outdated OpenSSH",
                            f"OpenSSH {mo.group(1)}.x is old and missing years of fixes",
                            "Upgrade OpenSSH to a current release."))
    return out

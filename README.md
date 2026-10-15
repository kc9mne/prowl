# 🐾 Prowl

**Fast on-site network baseline & recon for authorized IT/security work.**

Walk onto a network, connect, run Prowl, and in a few minutes get a picture of what's there:
every host with its IP/MAC/vendor, the services each exposes, a best-guess device class and
make/model, the gateway identified, a clickable map to reach each service, and a flag on
anything still using default credentials. One tool instead of an hour of `nmap` + OUI
lookups + poking at web UIs.

Prowl is **self-contained** (pure-Python scanning, no `nmap` dependency), **cross-platform**
(Windows/Linux/macOS), and runs as a small **local web UI** plus a scriptable **CLI**.

> ⚖️ **Authorized use only.** Run Prowl only on networks you own or have been explicitly
> engaged to assess. See [Scope & safety](#scope--safety).

---

## Install

```bash
python -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e .              # add ".[dev]" for the test deps
```

Requires Python 3.11+. Dependencies: FastAPI, uvicorn, psutil.

## Use

```bash
prowl                 # start the local UI (http://127.0.0.1:7474) and open a browser
prowl --no-browser    # start the UI without opening a browser
prowl scan            # one-shot discovery of your local subnet, printed as a table
prowl scan --mode deep --subnet 192.168.1.0/24 --html report.html
prowl scan --demo     # fabricated data for a UI/report walkthrough — touches no network
```

The UI has two scan modes, a map and a table view, a device detail panel with launch links,
and CSV/JSON/HTML report export.

## Scan modes

- **Discovery (fast):** find every live host and its IP / MAC / vendor and identify the
  gateway. Unprivileged — it primes the OS ARP cache with light TCP/ICMP probes and reads it
  back, so it needs no root and no raw sockets. A /24 in well under a minute.
- **Deep (ports + ID):** discovery, then per host a port sweep of a curated service set,
  banner/service fingerprinting, device classification and make/model guess, and an
  **opt-in** default-credential check.

> **Build status:** Discovery mode, deep-mode port sweep + service fingerprinting + device
> classification, the clickable map/table UI, OUI vendor lookup, the hardened service
> launcher (SSH/RDP/VNC/Telnet/SMB/web), the default-credential check, and report export are
> implemented — the core tool is usable end to end. See [Roadmap](#roadmap) for what's next.
> `--demo` shows the full UI (including flagged defaults) without touching a network.

Optional extras: `pip install -e ".[tls]"` adds TLS cert subject/SAN extraction during
fingerprinting; `pip install -e ".[creds]"` adds `paramiko` so the default-credential check
can confirm SSH logins (HTTP Basic and Telnet checks work without it).

## Scope & safety

These are design rules, not just advice:

- **Local-subnet by default.** Targets come from the host's own interfaces; a larger or
  off-link range must be given explicitly (and subnets over ~4096 addresses need
  `--allow-large`).
- **Loopback-only server.** The UI binds to `127.0.0.1` and rejects non-loopback callers.
  It's a single-operator on-the-spot tool, not a shared service.
- **Non-destructive.** Discovery and fingerprinting are read-only. The default-credential
  check tries at most two documented factory-default passwords per username (no brute
  forcing, no spraying, no wordlists), confirms and stops, and never changes a device — behind
  an explicit per-session authorization acknowledgement, off by default, on-link-only.
- **Honest provenance.** The UI separates *observed facts* (open port, MAC, banner) from
  *guesses* (device class / model inference).
- **Audit trail.** Scan start, authorization, every launch, and every credential attempt
  (with the password masked) are recorded in the in-memory audit log (`GET /api/audit`) and
  the server log.

## Layout

```
prowl/
  cli.py          # `prowl` entry point (server + one-shot scan)
  server.py       # loopback-only FastAPI UI + JSON API + audit log
  launch.py       # hardened native-client launcher (ssh/rdp/vnc/telnet/smb/web)
  report.py       # JSON / CSV / HTML report
  scan/
    net.py         # interfaces, subnet calc, ARP-cache read, gateway, reverse-DNS
    discovery.py   # Mode-1 host discovery (unprivileged)
    ports.py       # async TCP connect scanner (probe set + curated deep set)
    fingerprint.py # deep-mode service ID: HTTP/TLS/SSH/RTSP banners (read-only)
    classify.py    # vendor + ports + banners -> device class + make/model guess
    creds.py       # opt-in default-credential check (lockout-safe, non-destructive)
    oui.py         # offline MAC-prefix -> vendor
    scanner.py     # scan jobs: progress, cancel, demo mode
    model.py       # Host / Service / ScanResult
    data/oui.csv      # bundled offline OUI subset
    data/defaults.yaml # public, vendor-documented factory default logins
  store.py        # SQLite scan history + "since last baseline" diff
  web/             # static UI (no CDN): index.html, app.js, style.css, logo
tests/
```

## Roadmap

1. ✅ **Mode 1 slice** — discovery, OUI, map/table UI, reports, demo mode.
2. ✅ **Deep mode** — curated port sweep + banner/protocol fingerprinting (HTTP
   Server/title/realm, TLS cert CN, SSH/FTP/SMTP banners, RTSP) + device classification
   and make/model guess.
3. ✅ **Hardened service launcher** — loopback-only, gated endpoint that opens a native
   client (SSH/RDP/VNC/Telnet in a terminal, SMB in the file manager, web in a browser).
   Target must be a discovered host; usernames are strictly validated; argv is built as a
   list (never a shell string); passwords go via env (SSH `sshpass -e`) and are never on the
   command line, logged, or stored. Every launch is audit-logged.
4. ✅ **Default-credential check** — opt-in, behind a per-session authorization
   acknowledgement, on-link devices only. Tries at most **two documented factory-default
   passwords per username** (lockout-safe), stops at the first confirmed default, is
   non-destructive (confirm login, change nothing), honours lockout/rate-limit signals, and
   audit-logs every attempt with the password masked. Checks HTTP Basic-auth, SSH (with the
   `[creds]` extra), and Telnet. Flags the device with the working login and a "likely
   unpatched too" note. Ships only public, vendor-documented defaults — no exploits.
5. ✅ **Persistence + baseline diff** — every real scan is saved to a local SQLite history;
   the next scan of the same subnet is diffed against the previous one and the UI shows
   **what's new, gone, or changed since last visit** (hosts keyed by MAC, so a DHCP lease
   change reads as *changed*, not new+gone). `prowl scan` prints the same diff; `--data-dir`
   sets where the history lives.
6. More fingerprinting: SNMP sysDescr, SMB OS string, UPnP/SSDP, mDNS, favicon hashing;
   fuller OUI database loader.
7. Extra recon: DHCP/DNS intel, passive mDNS/SSDP/NetBIOS, TLS inventory, printer/camera
   exposure, SMB null-session, Wi-Fi survey.

## Develop

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT — see [LICENSE](LICENSE).

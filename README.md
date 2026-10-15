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

> **Build status:** Discovery mode, the map/table UI, OUI vendor lookup, and report export
> are implemented. Deep mode's port sweep, fingerprinting, classification, the hardened
> service launcher, and the default-credential check are scaffolded and land in the next
> slices — see [Roadmap](#roadmap). `--demo` shows the full intended UI today.

## Scope & safety

These are design rules, not just advice:

- **Local-subnet by default.** Targets come from the host's own interfaces; a larger or
  off-link range must be given explicitly (and subnets over ~4096 addresses need
  `--allow-large`).
- **Loopback-only server.** The UI binds to `127.0.0.1` and rejects non-loopback callers.
  It's a single-operator on-the-spot tool, not a shared service.
- **Non-destructive.** Discovery and fingerprinting are read-only. The planned
  default-credential check makes at most one attempt per documented factory-default pair per
  service (no brute forcing, no spraying, no wordlists), confirms and stops, and never
  changes a device — behind an explicit per-session authorization acknowledgement, off by
  default, on-link-only.
- **Honest provenance.** The UI separates *observed facts* (open port, MAC, banner) from
  *guesses* (device class / model inference).
- **Audit trail** (planned): scan start/stop, mode, target, and every credential attempt are
  logged and exportable with the report.

## Layout

```
prowl/
  cli.py          # `prowl` entry point (server + one-shot scan)
  server.py       # loopback-only FastAPI UI + JSON API
  report.py       # JSON / CSV / HTML report
  scan/
    net.py        # interfaces, subnet calc, ARP-cache read, gateway, reverse-DNS
    discovery.py  # Mode-1 host discovery (unprivileged)
    ports.py      # async TCP connect scanner (probe set + curated deep set)
    oui.py        # offline MAC-prefix -> vendor
    scanner.py    # scan jobs: progress, cancel, demo mode
    model.py      # Host / Service / ScanResult
    data/oui.csv  # bundled offline OUI subset
  web/            # static UI (no CDN): index.html, app.js, style.css
tests/
```

## Roadmap

1. ✅ **Mode 1 slice** — discovery, OUI, map/table UI, reports, demo mode. *(this build)*
2. Deep mode: curated port sweep + banner/protocol fingerprinting (HTTP title/favicon,
   SSH/TLS/SMB/SNMP/RTSP/IPP/UPnP/mDNS).
3. Device classification + gateway make/model mapping.
4. Hardened service launcher (loopback-only, gated): SSH/RDP/VNC/SMB/web with inline,
   never-stored credentials.
5. Default-credential check with its full guardrails and the authorization gate.
6. Persistence + **"new since last baseline"** diff for repeat site visits; report polish.
7. Extra recon: DHCP/DNS intel, passive mDNS/SSDP/NetBIOS, SNMP sysDescr, TLS inventory,
   printer/camera exposure, SMB null-session, Wi-Fi survey.

## Develop

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT — see [LICENSE](LICENSE).

"""`prowl` command line.

    prowl                      # start the local UI and open a browser
    prowl --no-browser         # start the UI without opening a browser
    prowl scan                 # one-shot discovery of the local subnet, print a table
    prowl scan --mode deep --subnet 192.168.1.0/24 --json out.json
    prowl scan --demo          # fabricated data, touches no network
"""
from __future__ import annotations

import argparse
import asyncio
import datetime
import sys
import threading
import webbrowser

from . import report
from .scan import ScanManager


def main(argv=None):
    ap = argparse.ArgumentParser(prog="prowl", description="On-site network baseline & recon (authorized use only).")
    sub = ap.add_subparsers(dest="cmd")

    ap.add_argument("--host", default="127.0.0.1", help="bind address for the UI (default loopback)")
    ap.add_argument("--port", type=int, default=7474, help="UI port (default 7474)")
    ap.add_argument("--no-browser", action="store_true", help="don't open a browser automatically")
    ap.add_argument("--data-dir", help="directory for the scan history database (default: user data dir)")

    s = sub.add_parser("scan", help="run one scan from the terminal, no server")
    s.add_argument("--mode", choices=["discovery", "deep"], default="discovery")
    s.add_argument("--subnet", help="CIDR to scan (default: auto-detect local subnet)")
    s.add_argument("--demo", action="store_true", help="fabricated data; touches no network")
    s.add_argument("--allow-large", action="store_true", help="permit subnets larger than /20")
    s.add_argument("--online-oui", action="store_true",
                   help="look up unknown MAC vendors at maclookup.app (opt-in; sends MAC prefixes online)")
    s.add_argument("--data-dir", help="directory for the scan history database (default: user data dir)")
    s.add_argument("--json", metavar="FILE", help="write a JSON report")
    s.add_argument("--csv", metavar="FILE", help="write a CSV report")
    s.add_argument("--html", metavar="FILE", help="write an HTML report")

    u = sub.add_parser("update-oui", help="ingest a local OUI database (IEEE oui.csv/oui.txt or maclookup.app CSV)")
    u.add_argument("path", help="path to an IEEE oui.csv/oui.txt or a maclookup.app CSV export")

    args = ap.parse_args(argv)
    if args.cmd == "scan":
        return _scan_cli(args)
    if args.cmd == "update-oui":
        return _update_oui(args)
    return _serve(args)


def _update_oui(args) -> int:
    from .scan import oui
    try:
        n = oui.update_from_ieee(args.path)
    except (OSError, ValueError) as e:
        print(f"update-oui failed: {e}", file=sys.stderr)
        return 1
    print(f"loaded {n} OUI prefixes into {oui.user_db_path()}", file=sys.stderr)
    return 0


def _scan_cli(args) -> int:
    async def go():
        mgr = ScanManager()
        job = mgr.start(mode=args.mode, subnet=args.subnet,
                        deep_opts={"allow_large": args.allow_large, "online_oui": args.online_oui},
                        demo=args.demo)
        while job.status in ("queued", "running"):
            p = job.progress
            print(f"\r{p['phase']}: {p['done']}/{p['total']} probed, {p['found']} found", end="", file=sys.stderr)
            await asyncio.sleep(0.25)
        print("", file=sys.stderr)
        if job.status == "error":
            print(f"scan failed: {job.error}", file=sys.stderr)
            return 1
        result = job.result
        _print_table(result)
        if not args.demo:
            _persist_and_diff(result, args.data_dir)
        if args.json:
            _write(args.json, report.to_json(result))
        if args.csv:
            _write(args.csv, report.to_csv(result))
        if args.html:
            _write(args.html, report.to_html(result))
        return 0

    return asyncio.run(go())


def _persist_and_diff(result, data_dir) -> None:
    from pathlib import Path

    from . import store as store_mod
    path = (Path(data_dir) / "prowl.db") if data_dir else store_mod.default_db_path()
    if data_dir:
        Path(data_dir).mkdir(parents=True, exist_ok=True)
    st = store_mod.Store(path)
    cur = result.as_dict()
    prev = st.previous(cur["subnet"], cur["started"])
    st.save(cur)
    if prev:
        d = store_mod.diff(cur, prev)
        when = datetime.datetime.fromtimestamp(d["baseline_started"]).strftime("%Y-%m-%d %H:%M")
        print(f"\nvs baseline {when}: +{len(d['new'])} new, -{len(d['gone'])} gone, "
              f"~{len(d['changed'])} changed", file=sys.stderr)
        for c in d["changed"]:
            print(f"   ~ {c['ip']}: {'; '.join(c['changes'])}", file=sys.stderr)
        for n in d["new"]:
            print(f"   + {n['ip']} ({n['label']})", file=sys.stderr)
        for g in d["gone"]:
            print(f"   - {g['ip']} ({g['label']})", file=sys.stderr)
    else:
        print("\nsaved as the first baseline for this subnet.", file=sys.stderr)
    st.close()


def _print_table(result) -> None:
    d = result.as_dict()
    print(f"\n{d['count']} hosts on {d['subnet']} (gateway {d['gateway'] or '?'}, mode {d['mode']})")
    print(f"{'IP':<16}{'MAC':<19}{'VENDOR':<24}{'HOST/PORTS'}")
    print("-" * 80)
    for h in d["hosts"]:
        tag = "*" if h["is_gateway"] else " "
        extra = h["hostname"] or ""
        if h["services"]:
            extra = (extra + " " if extra else "") + "[" + ",".join(str(s["port"]) for s in h["services"]) + "]"
        if h["default_creds"]:
            extra += "  !! DEFAULT CREDS"
        print(f"{tag}{h['ip']:<15}{(h['mac'] or '—'):<19}{(h['vendor'] or '—'):<24}{extra}")
    for note in d["notes"]:
        print(f"\n  note: {note}")


def _write(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"wrote {path}", file=sys.stderr)


def _serve(args) -> int:
    import uvicorn

    from pathlib import Path

    from .server import create_app

    db_path = (Path(args.data_dir) / "prowl.db") if args.data_dir else None
    if args.data_dir:
        Path(args.data_dir).mkdir(parents=True, exist_ok=True)
    url = f"http://{'127.0.0.1' if args.host == '0.0.0.0' else args.host}:{args.port}/"
    if not args.no_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    print(f"Prowl UI at {url}  (Ctrl-C to stop)", file=sys.stderr)
    uvicorn.run(create_app(db_path), host=args.host, port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

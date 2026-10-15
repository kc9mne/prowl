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

    s = sub.add_parser("scan", help="run one scan from the terminal, no server")
    s.add_argument("--mode", choices=["discovery", "deep"], default="discovery")
    s.add_argument("--subnet", help="CIDR to scan (default: auto-detect local subnet)")
    s.add_argument("--demo", action="store_true", help="fabricated data; touches no network")
    s.add_argument("--allow-large", action="store_true", help="permit subnets larger than /20")
    s.add_argument("--json", metavar="FILE", help="write a JSON report")
    s.add_argument("--csv", metavar="FILE", help="write a CSV report")
    s.add_argument("--html", metavar="FILE", help="write an HTML report")

    args = ap.parse_args(argv)
    if args.cmd == "scan":
        return _scan_cli(args)
    return _serve(args)


def _scan_cli(args) -> int:
    async def go():
        mgr = ScanManager()
        job = mgr.start(mode=args.mode, subnet=args.subnet,
                        deep_opts={"allow_large": args.allow_large}, demo=args.demo)
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
        if args.json:
            _write(args.json, report.to_json(result))
        if args.csv:
            _write(args.csv, report.to_csv(result))
        if args.html:
            _write(args.html, report.to_html(result))
        return 0

    return asyncio.run(go())


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

    from .server import create_app

    url = f"http://{'127.0.0.1' if args.host == '0.0.0.0' else args.host}:{args.port}/"
    if not args.no_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    print(f"Prowl UI at {url}  (Ctrl-C to stop)", file=sys.stderr)
    uvicorn.run(create_app(), host=args.host, port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

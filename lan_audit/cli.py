from __future__ import annotations
import argparse
import os
import sys
from typing import List

from .scanner import scan
from .report import write_reports
from .utils import (
    parse_ports, is_private_network, exit_error, ensure_dir
)

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="lan-audit",
        description="Non-intrusive LAN discovery + TCP port scan (Windows + Android/Termux)."
    )
    p.add_argument("target", help="IP/CIDR, e.g., 192.168.1.0/24 or 192.168.1.10")
    p.add_argument("--ports", help="Comma list or ranges (e.g., 22,80,443 or 1-1024). Default: common set.")
    p.add_argument("--workers", type=int, default=120, help="Max concurrent threads (default: 120)")
    p.add_argument("--ping-timeout", type=int, default=1000, help="Ping timeout ms (default: 1000)")
    p.add_argument("--tcp-timeout", type=float, default=0.6, help="TCP connect/banner timeout seconds (default: 0.6)")
    p.add_argument("--skip-ping", action="store_true", help="Skip ping reachability test (scan all hosts)")
    p.add_argument("--format", choices=["json","html","both"], default="json", help="Report format")
    p.add_argument("--output", default=None, help="Output directory (default: ./reports/<timestamp>)")
    p.add_argument("--allow-public", action="store_true",
                   help="Allow scanning non-private ranges (use only with permission)")
    p.add_argument("--consent", metavar="YES", required=True,
                   help='Type YES to affirm you have authorization to scan the target')
    return p

def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.consent.strip().upper() != "YES":
        exit_error("Consent not affirmed (use --consent YES).")

    if not args.allow_public and not is_private_network(args.target):
        exit_error("Target is not a private RFC1918 network. Add --allow-public if you are authorized.")

    ports = parse_ports(args.ports)
    if not ports:
        exit_error("No valid ports were parsed from --ports.")

    # Output dir
    out_dir = args.output
    if not out_dir:
        from datetime import datetime
        stamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        out_dir = os.path.join(os.getcwd(), "reports", stamp)
    ensure_dir(out_dir)

    print(f"[*] Target: {args.target}")
    print(f"[*] Ports: {len(ports)} ports")
    print(f"[*] Workers: {args.workers}")
    print(f"[*] Output: {out_dir}")
    print("[*] Scanning...")

    hosts = scan(
        target=args.target,
        ports=ports,
        workers=max(1, int(args.workers)),
        ping_timeout_ms=max(100, int(args.ping_timeout)),
        tcp_timeout=max(0.1, float(args.tcp_timeout)),
        skip_ping=bool(args.skip_ping),
    )

    paths = write_reports(
        target=args.target,
        hosts=hosts,
        out_dir=out_dir,
        workers=args.workers,
        ports_used=ports,
        formats=args.format
    )
    print("[+] Done.")
    for k, v in paths.items():
        print(f"[+] {k.upper()} report: {v}")

if __name__ == "__main__":
    main()

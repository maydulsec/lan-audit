import argparse
import asyncio
import datetime as dt
import ipaddress
import json
import os
import sys
from typing import List

from .netutils import (
    autodetect_private_cidr,
    count_hosts,
    describe_networks,
    is_private_networks,
    parse_cidrs,
    parse_ports,
)
from .report import write_reports
from .scanner import scan_networks
from . import __version__

DEFAULT_PORTS = "22,80,443,445,139,3389,53,3306,5432,8080,8000,8443"

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="lan-audit",
        description="Non-intrusive LAN discovery + basic port scan + banner grab; JSON/HTML report.",
    )
    p.add_argument("--consent", required=True, help="Must be 'YES' to run scans")
    p.add_argument("--cidr", help="CIDRs to scan (comma/space separated). If absent, autodetect local private network.")
    p.add_argument("--ports", default=DEFAULT_PORTS, help=f"Port list/ranges. Default: {DEFAULT_PORTS}")
    p.add_argument("--concurrency", type=int, default=512, help="Global concurrency (default: 512)")
    p.add_argument("--timeout", type=float, default=1.0, help="Connect timeout seconds (default: 1.0)")
    p.add_argument("--read-timeout", type=float, default=0.8, help="Banner read timeout seconds (default: 0.8)")
    p.add_argument("--resolve-hostnames", action="store_true", help="Try reverse DNS for hosts")
    p.add_argument("--output-dir", default="reports", help="Output directory (default: reports)")
    p.add_argument("--allow-public", action="store_true", help="Allow scanning non-private CIDRs")
    p.add_argument("--max-hosts", type=int, default=4096, help="Safety cap on total hosts (default: 4096)")
    return p.parse_args()

def main():
    args = parse_args()

    # Safety gate: explicit consent
    if args.consent != "YES":
        print("[!] Consent required. Run with: --consent YES", file=sys.stderr)
        sys.exit(2)

    # Ports
    ports = parse_ports(args.ports)
    if not ports:
        print("[!] No valid ports parsed.", file=sys.stderr)
        sys.exit(2)

    # CIDRs
    nets: List[ipaddress.IPv4Network] = []
    if args.cidr:
        nets = parse_cidrs(args.cidr)
        if not nets:
            print("[!] No valid CIDR(s) parsed.", file=sys.stderr)
            sys.exit(2)
    else:
        net = autodetect_private_cidr()
        if not net:
            print("[!] Could not autodetect a local private IPv4 network. Specify --cidr.", file=sys.stderr)
            sys.exit(2)
        nets = [net]

    # Safety: private-only unless --allow-public
    if not is_private_networks(nets) and not args.allow_public:
        print("[!] Refusing to scan non-private networks without --allow-public.", file=sys.stderr)
        sys.exit(2)

    total_hosts = count_hosts(nets)
    if total_hosts > args.max_hosts:
        print(f"[!] Host count {total_hosts} exceeds --max-hosts {args.max_hosts}. "
              f"Use a narrower CIDR or raise --max-hosts.", file=sys.stderr)
        sys.exit(2)

    nets_desc = ", ".join(n for n, _ in describe_networks(nets))
    print(f"[*] lan-audit v{__version__}")
    print(f"[*] Networks    : {nets_desc}")
    print(f"[*] Ports       : {','.join(map(str, ports))}")
    print(f"[*] Hosts       : {total_hosts}")
    print(f"[*] Concurrency : {args.concurrency}")
    print(f"[*] Timeouts    : connect={args.timeout}s, read={args.read_timeout}s")
    print(f"[*] ReverseDNS  : {'ON' if args.resolve_hostnames else 'OFF'}")
    print(f"[*] Output Dir  : {args.output_dir}")

    started = dt.datetime.now()

    # Run scan
    scan_out = asyncio.run(
        scan_networks(
            nets=nets,
            ports=ports,
            concurrency=args.concurrency,
            connect_timeout=args.timeout,
            read_timeout=args.read_timeout,
            resolve_hostnames=args.resolve_hostnames,
        )
    )

    ended = dt.datetime.now()
    duration = (ended - started).total_seconds()

    # Build JSON payload
    payload = {
        "metadata": {
            "start_time": started.isoformat(timespec="seconds"),
            "end_time": ended.isoformat(timespec="seconds"),
            "duration_s": round(duration, 3),
            "args": {
                "ports": ports,
                "concurrency": args.concurrency,
                "timeout": args.timeout,
                "read_timeout": args.read_timeout,
                "resolve_hostnames": bool(args.resolve_hostnames),
                "allow_public": bool(args.allow_public),
                "max_hosts": args.max_hosts,
            },
            "networks": [str(n) for n in nets],
            "tool": f"lan-audit v{__version__}",
            "consent": "YES",
        },
        "hosts": scan_out["hosts"],
        "summary": scan_out["summary"],
    }

    os.makedirs(args.output_dir, exist_ok=True)
    paths = write_reports(args.output_dir, payload)

    print(f"[*] JSON  : {paths['json']}")
    print(f"[*] HTML  : {paths['html']}")
    print("[*] Done.")

if __name__ == "__main__":
    main()

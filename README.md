# LAN Audit (Cross-Platform)

Simple, non-intrusive LAN discovery + port scan + banner grab with JSON/HTML report.
Works on **Windows** and **Android (Termux)** without admin/root.

## Features
- CIDR/host scan (e.g., `192.168.1.0/24` or `192.168.1.10`)
- ICMP reachability via system `ping` (no raw sockets)
- TCP connect scan (default common ports, or custom list)
- Lightweight banner grab on open ports (HTTP HEAD for web ports)
- TTL-based coarse OS guess (from `ping` output)
- JSON + HTML reports
- Safety gates: `--consent YES`, block public ranges unless `--allow-public`

## Install

### Windows
1. Install Python 3.10+ from python.org (add to PATH).
2. Clone or download this repo.
3. (Optional) `python -m venv .venv && .venv\Scripts\activate`
4. `pip install -r requirements.txt`

### Android (Termux)
```sh
pkg update && pkg upgrade -y
pkg install python git -y
git clone <your-repo-url>.git && cd lan-audit
pip install -r requirements.txt

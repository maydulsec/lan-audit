🚀 LAN Audit



✨ Features

⚡ Live host discovery (TCP connect heuristic — no raw sockets)

🔎 Basic port scan

🏷️ Lightweight banner grab (HTTP/HTTPS HEAD, SSH/FTP/SMTP read)

📊 JSON + HTML report (self-contained, no external deps)

🛡️ Safety Gates

✅ Must pass --consent YES

🔒 Default: scan only private RFC1918 ranges

🌍 To scan non-private CIDRs, pass --allow-public

🚧 Safety cap: --max-hosts (default: 4096)

⚙️ Quick Start
🖥️ Windows (PowerShell)
git clone https://github.com/maydulsec/lan-audit.git
cd lan-audit
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Run (auto-detect private LAN)
python -m lan_audit.cli --consent YES --resolve-hostnames

# Or scan a specific subnet:
# python -m lan_audit.cli --consent YES --cidr 192.168.1.0/24

📱 Android (Termux)
pkg install python git -y
git clone https://github.com/maydulsec/lan-audit.git
cd lan-audit
python -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt || true   # psutil optional; fallback works

# Run
python -m lan_audit.cli --consent YES --resolve-hostnames

⚡ Common Options
--ports "22,80,443,1-1024"     # custom ports/ranges
--cidr "192.168.1.0/24"        # one or more CIDRs (comma/space separated)
--concurrency 512              # global async concurrency
--timeout 1.0                  # TCP connect timeout
--read-timeout 0.8             # banner read timeout
--resolve-hostnames            # try reverse DNS
--allow-public                 # allow non-private networks
--max-hosts 4096               # safety cap
--output-dir reports           # output folder

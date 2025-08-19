from __future__ import annotations
import ipaddress
import os
import platform
import re
import sys
from datetime import datetime
from typing import Iterable, List

PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

COMMON_PORTS = [
    21,22,23,25,53,80,110,123,135,139,143,161,389,443,445,587,631,
    993,995,1433,1521,2049,2181,2379,2380,27017,3306,3389,5432,5672,
    5900,5985,5986,6379,8080,8443,9000,9200,11211
]

SERVICE_MAP = {
    21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"dns",
    80:"http",110:"pop3",123:"ntp",135:"rpc",139:"netbios-ssn",
    143:"imap",161:"snmp",389:"ldap",443:"https",445:"smb",
    587:"smtp-sub",631:"ipp",993:"imaps",995:"pop3s",
    1433:"mssql",1521:"oracle",2049:"nfs",2181:"zookeeper",
    2379:"etcd",2380:"etcd-peer",27017:"mongodb",3306:"mysql",
    3389:"rdp",5432:"postgres",5672:"amqp",5900:"vnc",
    5985:"winrm-http",5986:"winrm-https",6379:"redis",
    8080:"http-proxy",8443:"https-alt",9000:"svc",9200:"elasticsearch",
    11211:"memcached"
}

def now_iso() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def is_private_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return any(ip_obj in net for net in PRIVATE_NETS)
    except ValueError:
        return False

def is_private_network(target: str) -> bool:
    try:
        if "/" in target:
            net = ipaddress.ip_network(target, strict=False)
            return any(net.subnet_of(p) or p.subnet_of(net) for p in PRIVATE_NETS)
        else:
            return is_private_ip(target)
    except ValueError:
        return False

def parse_ports(s: str | None) -> List[int]:
    if not s:
        return COMMON_PORTS
    s = s.strip().lower()
    if s in ("top", "common", "default"):
        return COMMON_PORTS
    ports = []
    for chunk in s.split(","):
        chunk = chunk.strip()
        if "-" in chunk:
            a,b = chunk.split("-",1)
            a,b = int(a), int(b)
            ports.extend(range(min(a,b), max(a,b)+1))
        elif chunk:
            ports.append(int(chunk))
    ports = sorted(set(p for p in ports if 1 <= p <= 65535))
    return ports

def os_guess_from_ttl(ttl: int | None) -> str:
    if ttl is None:
        return "Unknown"
    if ttl <= 64:
        return "Linux/Unix (approx)"
    if ttl <= 128:
        return "Windows (approx)"
    if ttl <= 255:
        return "Network device (approx)"
    return "Unknown"

def is_windows() -> bool:
    return platform.system().lower().startswith("win")

PING_TTL_REGEX = re.compile(r"[Tt][Tt][Ll]\D*(\d+)")

def extract_ttl(text: str) -> int | None:
    m = PING_TTL_REGEX.search(text)
    if m:
        try:
            return int(m.group(1))
        except ValueError:
            return None
    return None

def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)

def exit_error(msg: str, code: int = 2):
    print(f"[!] {msg}", file=sys.stderr)
    sys.exit(code)

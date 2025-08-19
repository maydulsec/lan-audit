import ipaddress
import platform
import re
import shutil
import subprocess
from typing import List, Optional, Tuple

def parse_ports(spec: str) -> List[int]:
    """
    Accepts "22,80,443,1-1024" and returns sorted unique ints.
    """
    if not spec:
        return []
    ports = set()
    for part in re.split(r"[,\s]+", spec.strip()):
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            try:
                a, b = int(a), int(b)
            except ValueError:
                continue
            if a > b:
                a, b = b, a
            for p in range(a, b + 1):
                if 1 <= p <= 65535:
                    ports.add(p)
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                continue
    return sorted(ports)

def parse_cidrs(spec: str) -> List[ipaddress.IPv4Network]:
    nets = []
    if not spec:
        return nets
    for part in re.split(r"[,\s]+", spec.strip()):
        if not part:
            continue
        try:
            net = ipaddress.ip_network(part, strict=False)
            if isinstance(net, ipaddress.IPv4Network):
                nets.append(net)
        except Exception:
            # ignore invalid chunks
            pass
    return nets

def is_private_networks(nets: List[ipaddress.IPv4Network]) -> bool:
    return all(n.is_private for n in nets)

def count_hosts(nets: List[ipaddress.IPv4Network]) -> int:
    total = 0
    for n in nets:
        total += sum(1 for _ in n.hosts())
    return total

def _psutil_autodetect() -> Optional[ipaddress.IPv4Network]:
    try:
        import psutil  # optional
    except Exception:
        return None
    addrs = psutil.net_if_addrs()
    # Prefer interfaces that look "up" and global
    for iface, lst in addrs.items():
        ipv4s = [a for a in lst if getattr(a, "family", None).__class__.__name__ == "AddressFamily" and a.family.name == "AF_INET"]
        # In some versions psutil returns integers, not enums:
        if not ipv4s:
            ipv4s = [a for a in lst if getattr(a, "family", None) == 2]  # AF_INET == 2
        for a in ipv4s:
            ip = a.address
            netmask = getattr(a, "netmask", None)
            if not ip or not netmask:
                continue
            try:
                net = ipaddress.ip_network(f"{ip}/{netmask}", strict=False)
            except Exception:
                continue
            if isinstance(net, ipaddress.IPv4Network) and net.is_private:
                return net
    return None

def _run(cmd: List[str]) -> str:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
        if out.returncode == 0:
            return out.stdout
    except Exception:
        pass
    return ""

def _parse_ip_linux_android() -> Optional[ipaddress.IPv4Network]:
    if not shutil.which("ip"):
        return None
    out = _run(["ip", "-o", "-4", "addr", "show", "scope", "global"])
    # Example: 2: wlan0    inet 192.168.1.10/24 brd 192.168.1.255 scope global dynamic wlan0
    for line in out.splitlines():
        m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
        if not m:
            continue
        ip, prefix = m.group(1), m.group(2)
        try:
            net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
            if net.is_private:
                return net
        except Exception:
            continue
    return None

def _parse_ip_windows() -> Optional[ipaddress.IPv4Network]:
    out = _run(["ipconfig"])
    # Very rough extraction (English output). Works often enough; psutil is preferred.
    # IPv4 Address. . . . . . . . . . . : 192.168.1.33
    # Subnet Mask . . . . . . . . . . . : 255.255.255.0
    ip, mask = None, None
    for line in out.splitlines():
        if ip is None and re.search(r"IPv4.*?:\s*(\d+\.\d+\.\d+\.\d+)", line):
            ip = re.search(r"(\d+\.\d+\.\d+\.\d+)", line).group(1)
        elif mask is None and re.search(r"Subnet.*?:\s*(\d+\.\d+\.\d+\.\d+)", line):
            mask = re.search(r"(\d+\.\d+\.\d+\.\d+)", line).group(1)
        if ip and mask:
            try:
                net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
                if net.is_private:
                    return net
            except Exception:
                ip, mask = None, None
    return None

def autodetect_private_cidr() -> Optional[ipaddress.IPv4Network]:
    """
    Try psutil first; fall back to parsing OS command output.
    """
    net = _psutil_autodetect()
    if net:
        return net
    system = platform.system().lower()
    if system in ("linux", "android"):  # Termux shows as Linux
        net = _parse_ip_linux_android()
    elif system.startswith("win"):
        net = _parse_ip_windows()
    else:
        net = _parse_ip_linux_android() or _parse_ip_windows()
    return net

def describe_networks(nets: List[ipaddress.IPv4Network]) -> List[Tuple[str, int]]:
    return [(str(n), n.num_addresses) for n in nets]

from __future__ import annotations
import ipaddress
import socket
import ssl
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple

from .utils import (
    COMMON_PORTS, SERVICE_MAP, extract_ttl, os_guess_from_ttl, is_windows
)

@dataclass
class PortResult:
    port: int
    state: str  # "open" or "closed"
    service_guess: str
    banner: Optional[str] = None

@dataclass
class HostResult:
    ip: str
    alive: bool
    ttl: Optional[int]
    os_guess: str
    ports: List[PortResult]

def iter_hosts(target: str) -> List[str]:
    if "/" in target:
        net = ipaddress.ip_network(target, strict=False)
        return [str(h) for h in net.hosts()]
    # single IP
    ipaddress.ip_address(target)  # validate
    return [target]

def ping_host(ip: str, timeout_ms: int = 1000) -> Tuple[bool, Optional[int]]:
    """ICMP reachability via system ping; returns (alive, ttl)."""
    if is_windows():
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        # Busybox/iputils (Android/Termux): -c count, -W timeout (seconds)
        secs = max(1, int(round(timeout_ms/1000)))
        cmd = ["ping", "-c", "1", "-W", str(secs), ip]
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True)
        out = (cp.stdout or "") + "\n" + (cp.stderr or "")
        ttl = extract_ttl(out)
        alive = (cp.returncode == 0) or (ttl is not None)
        return alive, ttl
    except Exception:
        return False, None

def tcp_connect(ip: str, port: int, timeout: float = 0.6) -> Optional[socket.socket]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        return s
    except Exception:
        s.close()
        return None

def banner_grab(sock: socket.socket, ip: str, port: int, timeout: float = 0.6) -> Optional[str]:
    try:
        sock.settimeout(timeout)
        # Basic heuristics
        if port in (80, 8080, 8000, 8888):
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % ip.encode())
            data = sock.recv(512)
            return data.decode(errors="ignore")[:500]
        if port in (443, 8443):
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with ctx.wrap_socket(sock, server_hostname=ip) as tls:
                    tls.sendall(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % ip.encode())
                    data = tls.recv(512)
                    return data.decode(errors="ignore")[:500]
            except Exception:
                return None
        # Generic: try to read something
        try:
            data = sock.recv(256)
            if data:
                return data.decode(errors="ignore")[:250]
        except Exception:
            pass
        # Try an empty line to prompt banner
        try:
            sock.sendall(b"\r\n")
            data = sock.recv(256)
            if data:
                return data.decode(errors="ignore")[:250]
        except Exception:
            pass
        return None
    except Exception:
        return None

def scan_host(ip: str, ports: List[int], tcp_timeout: float) -> List[PortResult]:
    results: List[PortResult] = []
    for p in ports:
        sock = tcp_connect(ip, p, timeout=tcp_timeout)
        if sock:
            try:
                banner = banner_grab(sock, ip, p, timeout=tcp_timeout) or None
            finally:
                try: sock.close()
                except Exception: pass
            results.append(PortResult(
                port=p, state="open",
                service_guess=SERVICE_MAP.get(p, "unknown"),
                banner=banner
            ))
        else:
            # record only open ports to keep report tight
            pass
    return results

def scan(target: str,
         ports: List[int] | None = None,
         workers: int = 100,
         ping_timeout_ms: int = 1000,
         tcp_timeout: float = 0.6,
         skip_ping: bool = False) -> List[HostResult]:
    ports = ports or COMMON_PORTS
    hosts = iter_hosts(target)
    out: List[HostResult] = []

    # First pass: ping (optionally)
    alive_map: Dict[str, Tuple[bool, Optional[int]]] = {}
    if skip_ping:
        for ip in hosts:
            alive_map[ip] = (True, None)  # optimistic
    else:
        with ThreadPoolExecutor(max_workers=min(workers, 256)) as ex:
            futs = {ex.submit(ping_host, ip, ping_timeout_ms): ip for ip in hosts}
            for fut in as_completed(futs):
                ip = futs[fut]
                alive, ttl = fut.result()
                alive_map[ip] = (alive, ttl)

    # Second: port scans for alive hosts
    tasks = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for ip, (alive, ttl) in alive_map.items():
            if not alive:
                out.append(HostResult(ip=ip, alive=False, ttl=ttl,
                                      os_guess=os_guess_from_ttl(ttl), ports=[]))
                continue
            tasks.append((ip, ttl, ex.submit(scan_host, ip, ports, tcp_timeout)))

        for ip, ttl, fut in tasks:
            port_results = fut.result()
            out.append(HostResult(ip=ip, alive=True, ttl=ttl,
                                  os_guess=os_guess_from_ttl(ttl), ports=port_results))
    # Keep stable order
    out.sort(key=lambda h: tuple(int(o) for o in h.ip.split(".")))
    return out

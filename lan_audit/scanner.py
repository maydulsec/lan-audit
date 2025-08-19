import asyncio
import ipaddress
import socket
import ssl
from typing import Dict, List, Optional

SERVICE_GUESSES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    6379: "redis",
    8000: "http-alt",
    8080: "http-alt",
    8443: "https-alt",
}

HTTP_PORTS = {80, 8080, 8000}
HTTPS_PORTS = {443, 8443}

async def _reverse_dns(ip: str, timeout: float = 0.5) -> Optional[str]:
    try:
        return await asyncio.wait_for(asyncio.to_thread(socket.gethostbyaddr, ip), timeout)
    except Exception:
        return None

async def _banner_read(reader: asyncio.StreamReader, nbytes: int, timeout: float) -> str:
    try:
        data = await asyncio.wait_for(reader.read(nbytes), timeout=timeout)
        return data.decode("latin-1", errors="replace").strip()
    except Exception:
        return ""

async def _probe_http(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, host: str, timeout: float) -> str:
    try:
        req = f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: lan-audit/0.1\r\nConnection: close\r\n\r\n"
        writer.write(req.encode("ascii", errors="ignore"))
        await writer.drain()
        banner = await _banner_read(reader, 2048, timeout)
        return banner
    except Exception:
        return ""

async def _scan_port(ip: str, port: int, connect_timeout: float, read_timeout: float) -> Dict:
    ssl_flag = port in HTTPS_PORTS
    status = "unknown"
    banner = ""
    service = SERVICE_GUESSES.get(port)

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ssl_flag if ssl_flag else None),
            timeout=connect_timeout,
        )
        status = "open"
        if port in HTTP_PORTS or port in HTTPS_PORTS:
            banner = await _probe_http(reader, writer, ip, read_timeout)
        elif port in (21, 22, 23, 25, 110, 143):
            banner = await _banner_read(reader, 512, read_timeout)
        else:
            # Try a tiny read; many services greet first (e.g., SSH/FTP/SMTP). If nothing, it's fine.
            banner = await _banner_read(reader, 256, 0.2)
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
    except (asyncio.TimeoutError, ssl.SSLError):
        status = "filtered"
    except (ConnectionRefusedError, OSError):
        # Connection refused => host alive, port closed.
        status = "closed"

    return {
        "port": port,
        "service_guess": service,
        "status": status,
        "banner": banner[:4096] if banner else "",
    }

async def _scan_host(ip: str, ports: List[int], sem: asyncio.Semaphore,
                     connect_timeout: float, read_timeout: float) -> Dict:
    openish = False
    results = []
    # Limit per-host parallelism to avoid overwhelming small devices
    per_host = min(64, max(4, len(ports)))
    host_sem = asyncio.Semaphore(per_host)

    async def _task(p: int):
        async with host_sem:
            return await _scan_port(ip, p, connect_timeout, read_timeout)

    async with sem:
        tasks = [asyncio.create_task(_task(p)) for p in ports]
        port_results = await asyncio.gather(*tasks)
        for pr in port_results:
            results.append(pr)
            if pr["status"] in ("open", "closed"):
                openish = True

    return {
        "ip": ip,
        "alive_likely": openish,
        "ports": sorted(results, key=lambda x: x["port"]),
    }

async def scan_networks(nets: List[ipaddress.IPv4Network],
                        ports: List[int],
                        concurrency: int = 512,
                        connect_timeout: float = 1.0,
                        read_timeout: float = 0.8,
                        resolve_hostnames: bool = True) -> Dict:
    sem = asyncio.Semaphore(concurrency)
    hosts = []
    for net in nets:
        for h in net.hosts():
            hosts.append(str(h))

    # Scan all hosts
    tasks = [asyncio.create_task(_scan_host(ip, ports, sem, connect_timeout, read_timeout))
             for ip in hosts]

    host_results = await asyncio.gather(*tasks)

    # Optional reverse DNS (keep it lightweight)
    if resolve_hostnames:
        async def _rdns(entry):
            ip = entry["ip"]
            name = None
            r = await _reverse_dns(ip, timeout=0.5)
            if isinstance(r, tuple) and r:
                name = r[0]
            entry["hostname"] = name
            return entry

        rdns_tasks = [asyncio.create_task(_rdns(e)) for e in host_results]
        host_results = await asyncio.gather(*rdns_tasks)

    # Build summary
    summary = {
        "total_hosts": len(hosts),
        "scanned_ports": ports,
        "open_counts": sum(1 for e in host_results for p in e["ports"] if p["status"] == "open"),
        "closed_counts": sum(1 for e in host_results for p in e["ports"] if p["status"] == "closed"),
        "filtered_counts": sum(1 for e in host_results for p in e["ports"] if p["status"] == "filtered"),
        "alive_hosts": sum(1 for e in host_results if e["alive_likely"]),
    }

    return {
        "hosts": host_results,
        "summary": summary,
    }

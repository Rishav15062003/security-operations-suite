"""TCP port checks: optional nmap or built-in socket probe."""
from __future__ import annotations

import concurrent.futures
import socket
import subprocess
from typing import List, Set

from .tool_paths import resolve_nmap_executable


DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 9000, 27017]


def resolve_ipv4(host: str, timeout: float = 3.0) -> str | None:
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


def socket_scan(host: str, ports: List[int], timeout: float = 0.6) -> Set[int]:
    """Parallel connect scan (no root required); resolves host via DNS per connect."""
    open_ports: Set[int] = set()

    def check(p: int) -> bool:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((host, p))
            return True
        except OSError:
            return False
        finally:
            s.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as ex:
        futs = {ex.submit(check, p): p for p in ports}
        for fut, p in futs.items():
            try:
                if fut.result():
                    open_ports.add(p)
            except Exception:
                pass
    return open_ports


def nmap_scan(host: str, ports: List[int], timeout: int = 120) -> Set[int]:
    """Use nmap if available; otherwise empty and caller falls back to socket_scan."""
    nmap_exe = resolve_nmap_executable()
    if not nmap_exe:
        return set()
    port_arg = ",".join(str(p) for p in ports)
    try:
        p = subprocess.run(
            [
                nmap_exe,
                "-Pn",
                "-sT",
                "-T4",
                "--open",
                "-p",
                port_arg,
                host,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return set()
    open_ports: Set[int] = set()
    for line in (p.stdout or "").splitlines():
        line = line.strip()
        if "/tcp" in line and "open" in line:
            parts = line.split()
            if parts:
                port_str = parts[0].split("/")[0]
                try:
                    open_ports.add(int(port_str))
                except ValueError:
                    pass
    return open_ports


def scan_ports(host: str, ports: List[int] | None = None, prefer_nmap: bool = True) -> Set[int]:
    ports = ports or list(DEFAULT_PORTS)
    if prefer_nmap:
        nm = nmap_scan(host, ports)
        if nm:
            return nm
    if not resolve_ipv4(host):
        return set()
    return socket_scan(host, ports)

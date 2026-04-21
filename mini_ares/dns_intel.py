"""DNS resolution + reverse PTR for hostname context."""
from __future__ import annotations

import socket
from typing import Any


def hostname_intel(host: str) -> dict[str, Any]:
    """Resolve A record and optional PTR for display in reports."""
    out: dict[str, Any] = {"hostname": host, "ipv4": None, "ptr": None, "error": None}
    try:
        ip = socket.gethostbyname(host)
        out["ipv4"] = ip
    except OSError as e:
        out["error"] = str(e)[:200]
        return out
    try:
        ptr = socket.gethostbyaddr(ip)[0]
        out["ptr"] = ptr
    except OSError:
        pass
    return out


def format_hostname_intel(d: dict[str, Any]) -> str:
    lines = [f"Hostname: {d.get('hostname')}", f"A/IPv4: {d.get('ipv4') or '—'}"]
    if d.get("ptr"):
        lines.append(f"PTR reverse: {d['ptr']}")
    if d.get("error"):
        lines.append(f"DNS: {d['error']}")
    return "\n".join(lines)

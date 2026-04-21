"""IPv4 public vs private classification for traffic heuristics."""
from __future__ import annotations


def _ipv4_octets(ip: str) -> tuple[int, int, int, int] | None:
    try:
        parts = ip.strip().split(".")
        if len(parts) != 4:
            return None
        o = [int(p) for p in parts]
        return (o[0], o[1], o[2], o[3])
    except ValueError:
        return None


def is_private_ipv4(ip: str) -> bool:
    """RFC1918, loopback, link-local, CGNAT (RFC6598 100.64/10). Non-IPv4 → False."""
    t = _ipv4_octets(ip)
    if not t:
        return False
    a, b, c, d = t
    if a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if a == 127:
        return True
    if a == 169 and b == 254:
        return True
    if a == 100 and 64 <= b <= 127:
        return True
    return False


def is_public_ipv4(ip: str) -> bool:
    """Globally routable unicast IPv4 (best-effort; excludes private, loopback, multicast, reserved)."""
    t = _ipv4_octets(ip)
    if not t:
        return False
    if is_private_ipv4(ip):
        return False
    a, b, c, d = t
    if a == 0 or a == 127:
        return False
    if a >= 224:
        return False
    if a == 198 and (b == 18 or b == 19):
        return False
    if a == 192 and b == 0:
        return False
    return True

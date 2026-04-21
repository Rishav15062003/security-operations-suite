"""DNS-oriented heuristics (tunneling volume, suspicious FQDN shapes)."""
from __future__ import annotations

import math
import re
from collections import Counter

# High DNS query rate from one host (possible tunneling or misconfiguration)
DNS_TUNNEL_MIN_QPS = 42

# Minimum suspicious-looking FQDN samples to flag a source
DNS_SUSPICIOUS_MIN_SAMPLES = 4


def _label_entropy(label: str) -> float:
    if not label:
        return 0.0
    freq = Counter(label.lower())
    n = len(label)
    if n == 0:
        return 0.0
    return -sum((cnt / n) * math.log2(cnt / n) for cnt in freq.values())


def is_suspicious_domain(fqdn: str) -> bool:
    """
    Random-looking / excessive labels (entropy, length, depth) — best-effort, not a threat feed.
    """
    s = fqdn.strip().lower().rstrip(".")
    if not s or len(s) > 200:
        return True
    parts = [p for p in s.split(".") if p]
    if len(parts) > 8:
        return True
    for lab in parts[:-1] if len(parts) > 1 else parts:
        if len(lab) >= 32:
            return True
        if len(lab) >= 14 and _label_entropy(lab) > 3.85:
            return True
        if re.fullmatch(r"[a-f0-9]{20,}", lab):
            return True
        if re.fullmatch(r"[a-z0-9]{24,}", lab) and _label_entropy(lab) > 3.5:
            return True
    return False


def extract_dns_qname_from_packet(pkt) -> str | None:
    """Best-effort DNS query name from a Scapy packet (UDP/TCP DNS)."""
    try:
        from scapy.layers.dns import DNS
    except ImportError:
        return None
    try:
        if DNS not in pkt:
            return None
        dns = pkt[DNS]
        if getattr(dns, "qr", 0) != 0:
            return None
        qd = getattr(dns, "qd", None)
        if qd is None:
            return None
        if isinstance(qd, (list, tuple)):
            if len(qd) == 0:
                return None
            qd = qd[0]
        qname = getattr(qd, "qname", None)
        if qname is None:
            return None
        if isinstance(qname, bytes):
            s = qname.decode("utf-8", errors="replace").strip().rstrip(".")
        else:
            s = str(qname).strip().rstrip(".")
        return s or None
    except (AttributeError, TypeError, ValueError, UnicodeDecodeError):
        return None

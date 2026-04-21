"""
Read binary packet captures (.pcap, .pcapng) into ParsedEvent rows (PACKET_RECORD).

Requires: pip install scapy
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from .models import ParsedEvent
from .wireshark_parser import _build_packet_event

# Default cap keeps UI responsive on large classroom captures (override with max_pcap_packets=0 for unlimited).
DEFAULT_MAX_PCAP_PACKETS = 250_000


def _infer_proto(pkt) -> str:
    try:
        from scapy.layers.inet import ICMP, IP, TCP, UDP
        from scapy.layers.inet6 import IPv6
        from scapy.layers.l2 import ARP
    except ImportError:
        return "Unknown"

    if TCP in pkt:
        return "TCP"
    if UDP in pkt:
        return "UDP"
    if ICMP in pkt:
        return "ICMP"
    if IPv6 in pkt:
        inner = pkt[IPv6].payload
        if inner is not None and getattr(inner, "name", None) and inner.name != "NoPayload":
            return inner.name
        return "IPv6"
    if IP in pkt:
        try:
            return str(pkt[IP].sprintf("%IP.proto%"))
        except (AttributeError, TypeError, ValueError):
            return "IP"
    if ARP in pkt:
        return "ARP"
    return "Unknown"


def _endpoints(pkt) -> tuple[Optional[str], Optional[str]]:
    """Best-effort L3/L2 source and destination for display and detectors."""
    try:
        from scapy.layers.inet import IP
        from scapy.layers.inet6 import IPv6
        from scapy.layers.l2 import ARP
    except ImportError:
        return None, None

    if IP in pkt:
        ip = pkt[IP]
        return ip.src, ip.dst
    if IPv6 in pkt:
        ip6 = pkt[IPv6]
        return ip6.src, ip6.dst
    if ARP in pkt:
        arp = pkt[ARP]
        return arp.psrc, arp.pdst
    return None, None


def parse_pcap_file(path: str, *, max_packets: Optional[int] = None) -> List[ParsedEvent]:
    """
    Stream packets from a .pcap or .pcapng file into PACKET_RECORD events.

    :param max_packets: Optional cap (e.g. for huge captures); None = read all.
    """
    try:
        from scapy.utils import PcapReader
    except ImportError as exc:
        raise ImportError(
            "Reading .pcap/.pcapng requires the 'scapy' package. Install with: pip install scapy"
        ) from exc

    p = Path(path)
    suffix = p.suffix.lower()
    svc = "pcapng" if suffix == ".pcapng" else "pcap"

    events: List[ParsedEvent] = []
    with PcapReader(str(p)) as reader:
        for i, pkt in enumerate(reader, start=1):
            if max_packets is not None and i > max_packets:
                break
            ts: Optional[datetime] = None
            try:
                t = float(pkt.time)
                ts = datetime.fromtimestamp(t, tz=timezone.utc).replace(tzinfo=None)
            except (TypeError, ValueError, OSError):
                pass
            src, dst = _endpoints(pkt)
            proto = _infer_proto(pkt)
            try:
                info = pkt.summary()
            except Exception:
                info = repr(pkt)[:500]
            raw = info[:2000]
            plen = len(pkt)
            ev = _build_packet_event(
                raw,
                i,
                ts,
                src or "",
                dst or "",
                proto,
                info,
                length=str(plen),
                service=svc,
            )
            meta = dict(ev.metadata)
            meta["format"] = "pcap" if suffix == ".pcap" else "pcapng"
            ev.metadata = meta
            events.append(ev)
    return events

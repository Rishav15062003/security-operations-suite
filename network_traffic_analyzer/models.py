"""Data models for network traffic anomaly detection."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class FlowRecord:
    """One observed packet or log-derived flow row."""

    src_ip: str
    dst_ip: str
    proto: str  # tcp | udp | icmp | ip | other
    sport: int | None
    dport: int | None
    pkt_size: int = 0
    ts: float | None = None  # epoch seconds, optional
    tcp_syn: bool = False
    tcp_rst: bool = False
    icmp_type: int | None = None  # 8=echo request, 0=echo reply; None if unknown (logs)
    dns_qname: str | None = None  # DNS query FQDN when known (pcap DNS layer or Zeek dns.log)
    ip_proto: int | None = None  # IPv4 protocol field when known (pcap); None for plain-text logs
    mac_src: str | None = None  # Ethernet/ARP sender MAC when known (pcap)
    mac_dst: str | None = None  # Ethernet/ARP target MAC when known (pcap)
    # Cleartext HTTP in TCP only (pcap); None = not HTTP / not parsed
    http_method: str | None = None
    http_user_agent: str | None = None  # "" = HTTP request without User-Agent header
    # Port misuse (pcap TCP decode): HTTP/TLS heuristics on payload + destination port
    http_nonstandard_port: bool = False  # cleartext HTTP request, server port not in HTTP_PARSE_PORTS
    tls_unusual_port: bool = False  # TLS ClientHello to port not typical for HTTPS
    tls_on_plain_http_port: bool = False  # TLS ClientHello to port where cleartext HTTP is common (e.g. 80, 8080)


@dataclass
class TrafficFinding:
    code: str
    severity: str  # info | low | medium | high | critical
    title: str
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)
    # reconnaissance | brute_force | ddos_flood | suspicious_ip | unauthorized_access | dns_anomaly | data_exfil | protocol_anomaly | arp_spoofing | http_behavior | beaconing | traffic_pattern | port_misuse | lateral_movement | traffic_anomaly | info | general
    category: str = "general"


@dataclass
class TrafficReport:
    findings: list[TrafficFinding]
    stats: dict[str, Any]
    records_used: int

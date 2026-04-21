"""Network traffic anomaly detection (Scapy + log parsing)."""
from __future__ import annotations

from .analyzer import (
    analyze_flow_records,
    flows_from_pcap,
    format_tool_status,
    load_records_from_path,
    packet_to_flow,
    sniff_flows,
)
from .dns_heuristics import is_suspicious_domain
from .ip_utils import is_private_ipv4, is_public_ipv4
from .log_parser import parse_network_log, parse_network_log_text
from .models import FlowRecord, TrafficFinding, TrafficReport

__all__ = [
    "FlowRecord",
    "TrafficFinding",
    "TrafficReport",
    "analyze_flow_records",
    "flows_from_pcap",
    "format_tool_status",
    "load_records_from_path",
    "packet_to_flow",
    "is_private_ipv4",
    "is_public_ipv4",
    "is_suspicious_domain",
    "parse_network_log",
    "parse_network_log_text",
    "sniff_flows",
]

"""
Parse common Wireshark / tshark text exports (List, CSV, default text).

Supported:
  - Export as CSV (File → Export Packet Dissections → As CSV)
  - tshark default text (frame time src → dst proto len info)
  - "List" style: No. Time Source Destination Protocol Length Info (space-separated IPv4)

Binary captures (.pcap / .pcapng) are handled by ``pcap_io.parse_pcap_file`` (requires scapy), not this module.

Not supported here: full PDML/PSML XML (export as CSV or plain text instead).
"""
from __future__ import annotations

import csv
import re
from datetime import datetime
from io import StringIO
from typing import Optional

from dateutil import parser as date_parser

from .models import EventKind, ParsedEvent

_IPV4 = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)


def _looks_ipv4(s: str) -> bool:
    return bool(_IPV4.match(s.strip()))


def _looks_ip(s: str) -> bool:
    s = s.strip().strip('"').strip("'")
    if _looks_ipv4(s):
        return True
    if ":" in s and len(s) >= 3:
        return True
    return False


# tshark:   1 0.000000 10.0.0.1 → 10.0.0.2 TCP 66 ...
_RE_TSHARK = re.compile(
    r"^\s*(\d+)\s+(?P<t>[\d.]+)\s+(?P<src>[^\s→]+)\s*(?:→|->)\s*(?P<dst>[^\s]+)\s+(?P<proto>\S+)\s+"
    r"(?P<len>\d+)\s+(?P<info>.+)$"
)
# Two IPv4s after frame/time (variable time format)
_RE_LIST_IPV4 = re.compile(
    r"^\s*(\d+)\s+(?P<t>[^\s]+(?:\s+[^\s]+)?)\s+(?P<src>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(?P<dst>\d{1,3}(?:\.\d{1,3}){3})\s+(?P<proto>\S+)\s+(?P<len>\d+)\s+(?P<info>.*)$"
)


def _parse_time_col(s: str, default_year: int) -> Optional[datetime]:
    s = s.strip().strip('"').strip("'")
    if not s:
        return None
    if re.match(r"^\d+\.\d+$", s):
        return None
    try:
        return date_parser.parse(s)
    except (ValueError, TypeError):
        try:
            return date_parser.parse(f"{default_year} {s}", fuzzy=True)
        except (ValueError, TypeError):
            return None


def _build_packet_event(
    raw: str,
    line_no: int,
    ts: Optional[datetime],
    src: str,
    dst: str,
    proto: str,
    info: str,
    *,
    length: Optional[str] = None,
    service: str = "wireshark",
) -> ParsedEvent:
    meta = {"protocol": proto, "info": info[:2000]}
    if length:
        meta["length"] = length
    sip = (src or "").strip()
    dip = (dst or "").strip()
    return ParsedEvent(
        raw=raw,
        line_no=line_no,
        ts=ts,
        kind=EventKind.PACKET_RECORD,
        user=None,
        ip=sip or None,
        dst_ip=dip or None,
        protocol=proto.strip(),
        info_snippet=info.strip()[:2000],
        service=service,
        metadata=meta,
    )


def is_wireshark_csv_header_line(line: str) -> bool:
    """First row of File → Export Packet Dissections → As CSV."""
    low = line.strip().lower()
    if "no." not in low or "time" not in low:
        return False
    if "source" not in low or "destination" not in low:
        return False
    if "protocol" not in low:
        return False
    return True


def try_parse_wireshark_line(raw: str, line_no: int, default_year: int = 2026) -> Optional[ParsedEvent]:
    """
    If the line matches a Wireshark/tshark export, return a ParsedEvent; else None.
    (Caller falls through to syslog/auth parsing.)
    """
    line = raw.rstrip("\n\r")
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None

    # Skip header lines
    low = stripped.lower()
    if low.startswith("no.") and "time" in low and ("source" in low or "destination" in low):
        return None
    if low.startswith('"no."') or (low.startswith("no,") and "time" in low):
        return None

    # --- Tab-separated (Copy / some plain-text exports) ---
    if "\t" in stripped and stripped.count("\t") >= 5:
        parts = [p.strip() for p in stripped.split("\t")]
        if len(parts) >= 6 and parts[0].isdigit() and _looks_ip(parts[2]) and _looks_ip(parts[3]):
            ts = _parse_time_col(parts[1], default_year)
            proto = parts[4]
            if len(parts) >= 7:
                info = "\t".join(parts[6:])
                length = parts[5] if parts[5].isdigit() else None
            else:
                info = ""
                length = parts[5] if parts[5].isdigit() else None
            return _build_packet_event(
                raw,
                line_no,
                ts,
                parts[2],
                parts[3],
                proto,
                info,
                length=length,
            )

    # --- CSV (Wireshark export) ---
    if "," in stripped and stripped.count(",") >= 5:
        try:
            row = next(csv.reader(StringIO(line)))
        except (csv.Error, StopIteration):
            row = None
        if row and len(row) >= 6:
            row = [c.strip().strip('"') for c in row]
            if row[0].isdigit() and _looks_ip(row[2]) and _looks_ip(row[3]):
                ts = _parse_time_col(row[1], default_year)
                proto = row[4]
                if len(row) >= 7:
                    info = ",".join(row[6:])
                    length = row[5] if row[5].isdigit() else None
                else:
                    info = ""
                    length = row[5] if row[5].isdigit() else None
                return _build_packet_event(
                    raw,
                    line_no,
                    ts,
                    row[2],
                    row[3],
                    proto,
                    info,
                    length=length,
                )

    # --- tshark arrow format ---
    m = _RE_TSHARK.match(line)
    if m:
        ts = _parse_time_col(m.group("t"), default_year)
        return _build_packet_event(
            raw,
            line_no,
            ts,
            m.group("src"),
            m.group("dst"),
            m.group("proto"),
            m.group("info"),
            length=m.group("len"),
        )

    # --- List-style IPv4 ---
    m = _RE_LIST_IPV4.match(line)
    if m:
        ts = _parse_time_col(m.group("t"), default_year)
        return _build_packet_event(
            raw,
            line_no,
            ts,
            m.group("src"),
            m.group("dst"),
            m.group("proto"),
            m.group("info"),
            length=m.group("len"),
        )

    return None

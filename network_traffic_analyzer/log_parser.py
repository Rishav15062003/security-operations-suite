"""
Parse common network device / firewall text logs into FlowRecord rows (best-effort).
"""
from __future__ import annotations

import re
from pathlib import Path

from .models import FlowRecord

# iptables / ufw style: SRC= DST= PROTO= SPT= DPT=
_RE_IPT = re.compile(
    r"\bSRC=(\d+\.\d+\.\d+\.\d+)\b.*?\bDST=(\d+\.\d+\.\d+\.\d+)\b",
    re.I,
)
_RE_PROTO = re.compile(r"\bPROTO=(\w+)\b", re.I)
_RE_SPT = re.compile(r"\bSPT=(\d+)\b", re.I)
_RE_DPT = re.compile(r"\bDPT=(\d+)\b", re.I)

# Two IPv4s in a line (generic)
_RE_TWO_IP = re.compile(
    r"(\d+\.\d+\.\d+\.\d+)\D+(\d+\.\d+\.\d+\.\d+)",
)

_RE_EPOCH = re.compile(r"^(\d{10}|\d+\.\d+)\b")


def _parse_float_ts(line: str) -> float | None:
    m = _RE_EPOCH.match(line.strip())
    if not m:
        return None
    try:
        return float(m.group(1))
    except ValueError:
        return None


def _from_iptables_line(line: str) -> FlowRecord | None:
    m = _RE_IPT.search(line)
    if not m:
        return None
    src, dst = m.group(1), m.group(2)
    pm = _RE_PROTO.search(line)
    proto = (pm.group(1).lower() if pm else "tcp")
    sm = _RE_SPT.search(line)
    dm = _RE_DPT.search(line)
    sport = int(sm.group(1)) if sm else None
    dport = int(dm.group(1)) if dm else None
    if proto in ("icmp", "2"):
        proto = "icmp"
        sport, dport = None, None
    elif proto in ("6", "tcp"):
        proto = "tcp"
    elif proto in ("17", "udp"):
        proto = "udp"
    elif proto not in ("tcp", "udp"):
        proto = "tcp" if "TCP" in line.upper() else "udp" if "UDP" in line.upper() else proto
    return FlowRecord(
        src_ip=src,
        dst_ip=dst,
        proto=proto,
        sport=sport,
        dport=dport,
        pkt_size=0,
        ts=_parse_float_ts(line),
    )


def _from_zeek_conn_fields(fields: list[str]) -> FlowRecord | None:
    """Zeek conn.log TSV: ts, uid, orig_h, orig_p, resp_h, resp_p, proto, ..."""
    if len(fields) < 7:
        return None
    try:
        ts = float(fields[0])
    except ValueError:
        return None
    orig_h, orig_p, resp_h, resp_p = fields[2], fields[3], fields[4], fields[5]
    proto = fields[6].lower()
    if not re.match(r"^\d+\.\d+\.\d+\.\d+$", orig_h or ""):
        return None
    try:
        op = int(orig_p) if orig_p not in ("-", "") else None
        rp = int(resp_p) if resp_p not in ("-", "") else None
    except ValueError:
        op, rp = None, None
    if proto == "icmp":
        return FlowRecord(orig_h, resp_h, "icmp", None, None, 0, ts)
    if proto == "udp":
        return FlowRecord(orig_h, resp_h, "udp", op, rp, 0, ts)
    if proto == "tcp":
        return FlowRecord(orig_h, resp_h, "tcp", op, rp, 0, ts, tcp_syn=False, tcp_rst=False)
    return FlowRecord(orig_h, resp_h, proto or "ip", op, rp, 0, ts)


def _try_zeek_dns_line(line: str) -> FlowRecord | None:
    """Zeek dns.log TSV: query name typically at field index 9."""
    if line.startswith("#") or not line.strip():
        return None
    parts = line.rstrip("\n").split("\t")
    if len(parts) < 10:
        return None
    try:
        ts = float(parts[0])
    except ValueError:
        return None
    orig_h, orig_p, resp_h, resp_p = parts[2], parts[3], parts[4], parts[5]
    if not re.match(r"^\d+\.\d+\.\d+\.\d+$", orig_h or ""):
        return None
    q = parts[9].strip() if len(parts) > 9 else ""
    if not q or q in ("-", "(empty)"):
        return None
    if re.match(r"^[\d.+-eE]+$", q):
        return None
    if "." not in q or not re.search(r"[a-zA-Z]", q):
        return None
    try:
        op = int(orig_p) if orig_p not in ("-", "") else None
        rp = int(resp_p) if resp_p not in ("-", "") else None
    except ValueError:
        op, rp = None, None
    dport = rp if rp is not None else 53
    return FlowRecord(
        orig_h,
        resp_h,
        "udp",
        op,
        dport,
        0,
        ts,
        dns_qname=q,
    )


def _try_zeek_line(line: str) -> FlowRecord | None:
    if line.startswith("#") or not line.strip():
        return None
    parts = line.rstrip("\n").split("\t")
    if len(parts) < 7:
        return None
    return _from_zeek_conn_fields(parts)


def _from_generic_two_ip(line: str) -> FlowRecord | None:
    m = _RE_TWO_IP.search(line)
    if not m:
        return None
    src, dst = m.group(1), m.group(2)
    ports = [int(x) for x in re.findall(r"\b(\d{2,5})\b", line) if 1 <= int(x) <= 65535]
    sport, dport = (ports[0], ports[1]) if len(ports) >= 2 else (None, None)
    proto = "tcp"
    if "UDP" in line.upper():
        proto = "udp"
    elif "ICMP" in line.upper():
        proto = "icmp"
        sport, dport = None, None
    return FlowRecord(src, dst, proto, sport, dport, 0, _parse_float_ts(line))


def parse_network_log(path: str | Path, *, max_lines: int = 2_000_000) -> tuple[list[FlowRecord], dict]:
    """
    Parse a text log: tries Zeek conn TSV, iptables key=value, then generic two-IP heuristic.
    """
    p = Path(path)
    text = p.read_text(encoding="utf-8", errors="replace")
    return parse_network_log_text(text, max_lines=max_lines, source_name=str(p))


def parse_network_log_text(text: str, *, max_lines: int = 2_000_000, source_name: str = "text") -> tuple[list[FlowRecord], dict]:
    records: list[FlowRecord] = []
    stats = {
        "source": source_name,
        "lines": 0,
        "parsed": 0,
        "skipped": 0,
        "zeek": 0,
        "zeek_dns": 0,
        "iptables": 0,
        "generic": 0,
    }

    for line in text.splitlines():
        stats["lines"] += 1
        if stats["lines"] > max_lines:
            break
        rec = _try_zeek_dns_line(line)
        if rec:
            records.append(rec)
            stats["zeek_dns"] += 1
            stats["parsed"] += 1
            stats["zeek"] += 1
            continue
        rec = _try_zeek_line(line)
        if rec:
            records.append(rec)
            stats["zeek"] += 1
            stats["parsed"] += 1
            continue
        rec = _from_iptables_line(line)
        if rec:
            records.append(rec)
            stats["iptables"] += 1
            stats["parsed"] += 1
            continue
        rec = _from_generic_two_ip(line)
        if rec and rec.src_ip != rec.dst_ip:
            records.append(rec)
            stats["generic"] += 1
            stats["parsed"] += 1
            continue
        stats["skipped"] += 1

    return records, stats

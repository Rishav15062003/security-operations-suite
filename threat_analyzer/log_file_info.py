"""
Rich, file-specific summary for the Log analyzer “Log file info” panel (not security findings).
"""
from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Sequence

from .models import EventKind, ParsedEvent


def _top_items(counter: Counter[str], n: int = 12) -> list[tuple[str, int]]:
    return counter.most_common(n)


def _dns_ips(text: str) -> str:
    ips = re.findall(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        text,
    )
    return ", ".join(sorted(set(ips))[:10])


def _auth_section(events: Sequence[ParsedEvent]) -> list[str]:
    fails = [e for e in events if e.kind == EventKind.LOGIN_FAILURE and e.ip]
    oks = [e for e in events if e.kind == EventKind.LOGIN_SUCCESS and e.ip]
    lines: list[str] = [
        "Authentication activity (parsed)",
        "-------------------------------",
    ]
    if not fails and not oks:
        lines.append(
            "No login_success or login_failure events. This file may be packet-only, non-SSH text, "
            "or lines that do not match the SSH/PAM patterns."
        )
        return lines

    by_fail = Counter(e.ip for e in fails)
    lines.append(f"Failed logins: {len(fails)}")
    lines.append("Top source IPs (failed attempts):")
    for ip, c in _top_items(by_fail, 12):
        lines.append(f"  {ip}: {c}")
    lines.append(f"Successful logins: {len(oks)}")
    if oks:
        users = {e.user for e in oks if e.user}
        lines.append(f"Distinct usernames on successful login: {len(users)}")
    return lines


def _packet_section(events: Sequence[ParsedEvent]) -> list[str]:
    pk = [e for e in events if e.kind == EventKind.PACKET_RECORD]
    if not pk:
        return [
            "Packet / capture data",
            "--------------------",
            "No packet rows in this parse. For protocol and endpoint stats, use .pcap/.pcapng "
            "or a Wireshark CSV / tshark text export.",
        ]

    by_svc = Counter((e.service or "?") for e in pk)
    lines: list[str] = [
        "Packet / capture data",
        "--------------------",
        f"Packet rows: {len(pk)}",
        "Source (how rows were loaded): " + ", ".join(f"{k} ({v})" for k, v in by_svc.most_common()),
        "",
        "Protocols (frame counts, from summary field)",
    ]
    protos = Counter((e.protocol or "?").strip() for e in pk)
    for p, c in _top_items(protos, 20):
        lines.append(f"  {p}: {c}")

    talkers = Counter(e.ip for e in pk if e.ip)
    lines.append("")
    lines.append("Top source IPs (by frame count, not bytes)")
    if talkers:
        for ip, c in _top_items(talkers, 15):
            lines.append(f"  {ip}: {c} frames")
    else:
        lines.append("  (no IPv4/IPv6 source in parsed rows; e.g. non-IP layers only)")

    httpish = [
        e
        for e in pk
        if e.protocol
        and ("HTTP" in e.protocol.upper() or e.protocol.upper() == "TCP")
        and e.info_snippet
        and (
            "GET " in e.info_snippet
            or "POST " in e.info_snippet
            or "HTTP" in e.info_snippet
            or "Host:" in e.info_snippet
        )
    ]
    lines.append("")
    lines.append("HTTP-related frames (heuristic from summaries)")
    if not httpish:
        lines.append("  None obvious. In Wireshark try filter: http")
    else:
        for e in httpish[:12]:
            snip = (e.info_snippet or "")[:160].replace("\n", " ")
            lines.append(f"  {e.ip or '?'} -> {e.dst_ip or '?'} | {snip}")

    dns_like = [
        e
        for e in pk
        if (e.protocol and ("DNS" in e.protocol.upper() or e.protocol.upper() == "MDNS"))
        or (e.info_snippet and "dns" in e.info_snippet.lower())
    ]
    lines.append("")
    lines.append("DNS-related frames (heuristic)")
    if not dns_like:
        lines.append("  None in protocol column. In Wireshark try filter: dns")
    else:
        for e in dns_like[:15]:
            snip = (e.info_snippet or "")[:180].replace("\n", " ")
            extra = _dns_ips(snip)
            lines.append(f"  {snip}" + (f" | IPv4 in line: {extra}" if extra else ""))

    retrans = [e for e in pk if e.info_snippet and "retrans" in e.info_snippet.lower()]
    lines.append("")
    lines.append(f"TCP retransmissions (summary contains 'retrans'): {len(retrans)}")
    if retrans:
        for e in retrans[:6]:
            lines.append(f"    {(e.info_snippet or '')[:130]}")

    arp = [e for e in pk if (e.protocol or "").upper() == "ARP"]
    icmp = [e for e in pk if (e.protocol or "").upper() == "ICMP" or "ICMPv6" in (e.protocol or "")]
    icmp_by_dst = Counter(e.dst_ip for e in icmp if e.dst_ip)
    lines.append("")
    lines.append(f"ARP frames: {len(arp)} | ICMP/ICMPv6-like: {len(icmp)}")
    if icmp_by_dst:
        lines.append("ICMP-like traffic by destination (quick view)")
        for ip, c in _top_items(icmp_by_dst, 8):
            lines.append(f"  -> {ip}: {c} frames")

    return lines


def _time_range(events: Sequence[ParsedEvent]) -> str:
    ts_list = [e.ts for e in events if e.ts]
    if not ts_list:
        return "Time range: (no timestamps parsed on events)"
    mn, mx = min(ts_list), max(ts_list)
    return f"Time range (from parsed timestamps): {mn.isoformat(sep=' ')} -> {mx.isoformat(sep=' ')}"


def build_log_file_info_text(
    events: Sequence[ParsedEvent],
    path: Path,
    performance_notes: str = "",
) -> str:
    """Human-readable report for the current file — metadata, mix, auth, packets, limits."""
    p = Path(path)
    lines: list[str] = [
        "Log file information",
        "====================",
        f"Path: {p.resolve()}",
    ]
    try:
        st = p.stat()
        lines.append(f"Size on disk: {st.st_size:,} bytes")
    except OSError:
        lines.append("Size on disk: (unavailable)")

    lines.append(f"Extension: {p.suffix or '(none)'}")
    lines.append("")

    total = len(events)
    unknown = sum(1 for e in events if e.kind == EventKind.UNKNOWN)
    parsed_n = total - unknown
    lines.append("Parse summary")
    lines.append("------------")
    lines.append(f"Total lines / records read: {total}")
    lines.append(f"Parsed as known event kinds: {parsed_n}")
    lines.append(f"Unparsed (unknown pattern): {unknown}")
    lines.append(_time_range(events))
    lines.append("")

    by_kind: Counter[str] = Counter()
    for e in events:
        if e.kind != EventKind.UNKNOWN:
            by_kind[e.kind.value] += 1
    lines.append("Counts by event kind")
    lines.append("-------------------")
    for k, v in sorted(by_kind.items(), key=lambda x: -x[1]):
        lines.append(f"  {k}: {v}")
    lines.append("")

    lines.extend(_auth_section(events))
    lines.append("")
    lines.extend(_packet_section(events))

    if performance_notes.strip():
        lines.append("")
        lines.append("Performance / limits")
        lines.append("--------------------")
        lines.append(performance_notes.strip())

    lines.append("")
    return "\n".join(lines)

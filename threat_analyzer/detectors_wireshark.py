"""Heuristics for Wireshark / tshark packet list exports (PACKET_RECORD events)."""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import List, Sequence

from .models import EventKind, Finding, ParsedEvent


def detect_wireshark_patterns(
    events: Sequence[ParsedEvent],
    *,
    min_packet_events: int = 40,
    high_volume_src_pct: float = 0.32,
    min_high_volume_abs: int = 120,
    min_unique_dst_for_scan: int = 40,
    min_packets_for_scan: int = 200,
    min_tls_keyword_hits: int = 5,
) -> List[Finding]:
    """
    High traffic from one source, many destinations from one source (scan-like),
    and repeated TLS/security-related strings in the Info column.
    """
    findings: List[Finding] = []
    pkts = [e for e in events if e.kind == EventKind.PACKET_RECORD and e.ip]
    n = len(pkts)
    if n < min_packet_events:
        return findings

    by_src = Counter(e.ip for e in pkts if e.ip)
    total = n
    for src, cnt in by_src.most_common(8):
        thresh = max(min_high_volume_abs, int(total * high_volume_src_pct))
        if cnt >= thresh:
            findings.append(
                Finding(
                    category="network_capture",
                    severity="medium",
                    title=f"Dominant packet source {src}",
                    detail=(
                        f"{cnt} of {total} parsed frames ({100 * cnt / total:.1f}%) originate from this address — "
                        "review for DDoS participation, misconfigured client, or port scan origin."
                    ),
                    evidence=[e.raw[:140] for e in pkts if e.ip == src][:4],
                )
            )
            break

    by_src_dst: dict[str, set[str]] = defaultdict(set)
    for e in pkts:
        if e.ip and e.dst_ip:
            by_src_dst[e.ip].add(e.dst_ip)
    for src, dsts in sorted(by_src_dst.items(), key=lambda x: -len(x[1])):
        pkt_n = sum(1 for e in pkts if e.ip == src)
        if len(dsts) >= min_unique_dst_for_scan and pkt_n >= min_packets_for_scan:
            findings.append(
                Finding(
                    category="network_capture",
                    severity="medium",
                    title=f"Many unique destinations from {src}",
                    detail=(
                        f"{len(dsts)} distinct destination IPs across {pkt_n} frames — pattern consistent with "
                        "horizontal scanning or wide fan-out (verify against known scanners and asset inventory)."
                    ),
                    evidence=[e.raw[:140] for e in pkts if e.ip == src][:4],
                )
            )
            break

    tls_keys = (
        "alert",
        "certificate",
        "handshake failure",
        "fatal",
        "malformed",
        "unknown ca",
        "bad certificate",
        "decrypt_error",
        "version",
        "wrong version",
    )
    hits: List[ParsedEvent] = []
    for e in pkts:
        blob = f"{e.protocol or ''} {(e.info_snippet or '')}".lower()
        if any(k in blob for k in tls_keys):
            hits.append(e)
    if len(hits) >= min_tls_keyword_hits:
        findings.append(
            Finding(
                category="network_capture",
                severity="low",
                title="TLS / handshake-related frames in capture",
                detail=(
                    f"{len(hits)} frames mention TLS alerts, certificate, or handshake issues — "
                    "not necessarily malicious; validate against expected app behavior and endpoints."
                ),
                evidence=[e.raw[:140] for e in hits[:5]],
            )
        )

    return findings

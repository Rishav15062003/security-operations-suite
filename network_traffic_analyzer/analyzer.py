"""
Heuristic anomaly detection over FlowRecord streams (live capture, pcap, or parsed logs).
"""
from __future__ import annotations

import re
import statistics
import time
from collections import Counter, defaultdict
from typing import Any

from .dns_heuristics import (
    DNS_SUSPICIOUS_MIN_SAMPLES,
    DNS_TUNNEL_MIN_QPS,
    extract_dns_qname_from_packet,
    is_suspicious_domain,
)
from .http_heuristics import (
    HTTP_PARSE_PORTS,
    HTTPS_TLS_PORTS,
    is_automated_user_agent,
    is_weird_user_agent,
    looks_like_tls_client_hello,
    parse_http_request_user_agent,
)
from .models import FlowRecord, TrafficFinding, TrafficReport

# Brute-force heuristics: many TCP events to login services in a short window (packet/flow counts proxy for attempts).
BRUTE_FORCE_PORTS: frozenset[int] = frozenset({21, 22, 80, 443, 8080, 8443, 3389})
BRUTE_WINDOW_SEC = 60.0
BRUTE_MIN_IN_WINDOW = 18
BRUTE_HIGH_IN_WINDOW = 30
BRUTE_MIN_TOTAL_NO_TS = 48

# DDoS / traffic flood — packets (treated as "requests" in UI) per second vs thresholds
DDOS_PEAK_PPS_MEDIUM = 80
DDOS_PEAK_PPS_HIGH = 500
DDOS_SINGLE_IP_SHARE = 0.45
DDOS_SINGLE_IP_MIN_PEAK_EVENTS = 35
DDOS_SINGLE_IP_MIN_PPS = 55
DDOS_OVERALL_PPS = 90
DDOS_MIN_SPAN_SEC = 4.0
DDOS_MIN_RECORDS_FOR_BUCKETS = 15

# Suspicious IP behavior (non-brute sensitive ports — excludes BRUTE_FORCE_PORTS to limit overlap)
SENSITIVE_EXTRA_PORTS: frozenset[int] = frozenset(
    {
        23,
        25,
        110,
        135,
        139,
        143,
        445,
        1433,
        1521,
        3306,
        5432,
        5900,
        6379,
        9200,
        11211,
        27017,
        5060,
        161,
        993,
    }
)
SUSP_EXT_MIN_DISTINCT_PORTS = 6
SUSP_EXT_MIN_INTERNAL_HOSTS = 10
SUSP_SENSITIVE_PEAK = 14
SUSP_SENSITIVE_TOTAL_NO_TS = 32
SUSP_PRIV_PUB_MIN_DISTINCT_DSTS = 16
SUSP_PRIV_PUB_MIN_EVENTS = 45

# Lateral movement — internal host probing many other internal hosts (RFC1918 → RFC1918)
LATERAL_MIN_INTERNAL_TARGETS = 12
LATERAL_HIGH_INTERNAL_TARGETS = 24

# Unauthorized access — public → private restricted / admin-style ports (heuristic; not auth truth)
ADMIN_PANEL_PORTS: frozenset[int] = frozenset({8000, 8080, 8443, 8888, 9000, 9090, 10443, 10000, 7001})
RESTRICTED_UNAUTH_PORTS: frozenset[int] = frozenset(
    {23, 135, 139, 445, 1433, 1521, 3306, 5432, 5900, 5985, 5986, 8161, 4848}
)
UNAUTH_MIN_IN_60S = 6
UNAUTH_MIN_TOTAL_NO_TS = 14
UNAUTH_EXPOSURE_MIN_PUBLIC_SOURCES = 3

# Data exfiltration — outbound byte volume (private → public) in a 2-minute sliding window
EXFIL_WINDOW_SEC = 120.0
EXFIL_MIN_BYTES_ALERT = 40 * 1024 * 1024
EXFIL_HIGH_BYTES = 500 * 1024 * 1024
EXFIL_UPLOAD_RATIO_MIN_BYTES = 15 * 1024 * 1024
EXFIL_UPLOAD_RATIO_OUT_SHARE = 0.90

# Protocol anomalies (sizes, rare IP protocols, alternate well-known ports)
RARE_IP_PROTOS: frozenset[int] = frozenset({41, 47, 50, 51, 94, 115, 132})  # IPv6-in-IP, GRE, ESP, AH, etc.
ALT_SSH_PORTS: frozenset[int] = frozenset({2222, 22222, 22022, 22000, 5022, 3022})
ALT_RDP_PORTS: frozenset[int] = frozenset({33890, 13389, 4489})
PROTO_TINY_BYTES = 20
PROTO_TINY_MIN_EVENTS = 80
PROTO_ICMP_LARGE_BYTES = 1400
PROTO_SYM_SERVICE_PORTS: frozenset[int] = frozenset({22, 23, 25, 80, 135, 139, 443, 445, 1433, 3306, 3389, 5432})
PROTO_ALT_PORT_MIN_EVENTS = 18

# Malware / beaconing — repeated small packets to same destination at similar intervals (C2-style heuristic)
BEACON_MAX_PKT_BYTES = 512
BEACON_MIN_EVENTS_MERGED = 6
BEACON_MIN_INTERVALS = 5
BEACON_BURST_MERGE_SEC = 2.0
BEACON_CV_MAX = 0.28
BEACON_MIN_GAP_SEC = 0.5
BEACON_MAX_GAP_SEC = 7200.0

# Traffic pattern anomalies — peak rate vs estimated normal baseline (busiest second excluded from baseline)
PATTERN_MIN_SECOND_BUCKETS = 12
PATTERN_MIN_RECORDS_WITH_TS = 40
PATTERN_MIN_NORMAL_BASELINE_PPS = 4.0
PATTERN_RATIO_WARN = 10.0
PATTERN_RATIO_HIGH = 20.0
PATTERN_MIN_PEAK_PPS = 55


def _normal_traffic_baseline_pps(counts: list[int]) -> float:
    """Median packets/sec after dropping the single busiest second (normal baseline estimate)."""
    if not counts:
        return 0.0
    if len(counts) == 1:
        return float(counts[0])
    sorted_c = sorted(counts)
    trimmed = sorted_c[:-1]
    return float(statistics.median(trimmed))


def _merge_burst_timestamps(ts_sorted: list[float], merge_sec: float) -> list[float]:
    """Collapse events within merge_sec into one timestamp (one pulse per burst)."""
    if not ts_sorted:
        return []
    out = [ts_sorted[0]]
    for t in ts_sorted[1:]:
        if t - out[-1] >= merge_sec:
            out.append(t)
    return out


def _beaconing_gaps_regular(gaps: list[float]) -> tuple[bool, float, float]:
    """Return (regular_interval_pattern, mean_gap_sec, coefficient_of_variation)."""
    if len(gaps) < BEACON_MIN_INTERVALS:
        return False, 0.0, 0.0
    mean_g = statistics.mean(gaps)
    if mean_g < BEACON_MIN_GAP_SEC or mean_g > BEACON_MAX_GAP_SEC:
        return False, mean_g, 0.0
    std = statistics.pstdev(gaps)
    cv = std / mean_g if mean_g > 0 else 999.0
    return (cv <= BEACON_CV_MAX), mean_g, cv


def _max_bytes_in_sliding_window(
    events: list[tuple[float, int]], window_sec: float
) -> tuple[int, float, float]:
    """Maximum total bytes in any window_sec-long interval. Returns (max_bytes, window_start_ts, window_end_ts)."""
    if not events:
        return 0, 0.0, 0.0
    ev = sorted(events, key=lambda x: x[0])
    best = 0
    best_start = ev[0][0]
    best_end = ev[0][0]
    i = 0
    cur = 0
    for j in range(len(ev)):
        cur += ev[j][1]
        while i <= j and ev[j][0] - ev[i][0] > window_sec:
            cur -= ev[i][1]
            i += 1
        if cur > best:
            best = cur
            best_start = ev[i][0]
            best_end = ev[j][0]
    return best, best_start, best_end


def _max_events_in_sliding_window(timestamps: list[float], window_sec: float) -> int:
    """Maximum count of events in any window_sec-long interval."""
    if not timestamps:
        return 0
    ts = sorted(timestamps)
    best = 0
    i = 0
    for j in range(len(ts)):
        while i <= j and ts[j] - ts[i] > window_sec:
            i += 1
        best = max(best, j - i + 1)
    return best


def _brute_force_labels(dport: int) -> tuple[str, str, str]:
    """
    Return (alert_phrase, code_suffix, detail_service) e.g. ("SSH", "ssh", "SSH (:22)").
    """
    if dport == 22:
        return ("SSH", "ssh", "SSH (:22)")
    if dport == 21:
        return ("FTP", "ftp", "FTP (:21)")
    if dport in (80, 443, 8080, 8443):
        return ("Web login", "web", f"web login endpoint (:{dport})")
    if dport == 3389:
        return ("RDP", "rdp", "RDP (:3389)")
    return ("Service", "svc", f"TCP :{dport}")


def _tcp_flag_bits(tcp_layer) -> tuple[bool, bool]:
    """Return (syn, rst) from a Scapy TCP layer."""
    try:
        f = int(tcp_layer.flags)
    except (TypeError, ValueError, AttributeError):
        return False, False
    syn = bool(f & 0x02)
    rst = bool(f & 0x04)
    return syn, rst


def _normalize_mac(m: str | bytes | None) -> str | None:
    """Normalize MAC to lowercase hex with colons."""
    if m is None:
        return None
    if isinstance(m, bytes):
        m = m.decode("ascii", errors="replace")
    m = str(m).strip()
    if not m:
        return None
    m = re.sub(r"[-]", ":", m)
    parts = re.split(r"[:]", m)
    if len(parts) == 6 and all(len(p) == 2 for p in parts):
        try:
            return ":".join(f"{int(x, 16):02x}" for x in parts)
        except ValueError:
            return m.lower()
    return m.lower()


def _tcp_http_tls_port_misuse(pkt) -> tuple[str | None, str | None, bool, bool, bool]:
    """
    Parse TCP payload for cleartext HTTP (any port) or TLS ClientHello.
    Returns (http_method, http_user_agent, http_nonstandard_port, tls_unusual_port, tls_on_plain_http_port).
    """
    try:
        from scapy.layers.inet import TCP

        t = pkt[TCP]
        raw = bytes(t.payload)
        if not raw:
            return None, None, False, False, False
        dport = int(t.dport)
        if looks_like_tls_client_hello(raw):
            if dport in HTTP_PARSE_PORTS:
                return None, None, False, False, True
            if dport not in HTTPS_TLS_PORTS:
                return None, None, False, True, False
            return None, None, False, False, False
        p_http = parse_http_request_user_agent(raw)
        if p_http[0] is not None:
            hm, hua = p_http
            nonstd = dport not in HTTP_PARSE_PORTS
            return hm, hua, nonstd, False, False
        return None, None, False, False, False
    except (TypeError, ValueError, AttributeError):
        return None, None, False, False, False


def _flow_from_arp(pkt, ts: float | None, plen: int) -> FlowRecord | None:
    """Build a FlowRecord from an ARP layer (Ethernet, no IP layer)."""
    try:
        from scapy.layers.l2 import ARP
    except ImportError:
        return None
    try:
        arp = pkt[ARP]
        psrc = str(arp.psrc)
        pdst = str(arp.pdst)
        hwsrc = _normalize_mac(getattr(arp, "hwsrc", None))
        hwdst = _normalize_mac(getattr(arp, "hwdst", None))
    except (AttributeError, TypeError, ValueError):
        return None
    return FlowRecord(
        src_ip=psrc,
        dst_ip=pdst,
        proto="arp",
        sport=None,
        dport=None,
        pkt_size=plen,
        ts=ts,
        mac_src=hwsrc,
        mac_dst=hwdst,
    )


def packet_to_flow(pkt) -> FlowRecord | None:
    """Convert a Scapy packet to FlowRecord, or None if unsupported."""
    try:
        from scapy.layers.inet import ICMP, IP, TCP, UDP
        from scapy.layers.l2 import ARP
    except ImportError:
        return None

    ts: float | None = None
    try:
        ts = float(pkt.time)
    except (TypeError, ValueError, AttributeError):
        pass

    plen = len(pkt) if pkt is not None else 0

    if ARP in pkt:
        return _flow_from_arp(pkt, ts, plen)

    if IP not in pkt:
        return None
    ip = pkt[IP]
    src, dst = ip.src, ip.dst
    try:
        ip_p = int(ip.proto)
    except (TypeError, ValueError, AttributeError):
        ip_p = None
    dns_q = extract_dns_qname_from_packet(pkt)

    syn = rst = False
    if TCP in pkt:
        t = pkt[TCP]
        syn, rst = _tcp_flag_bits(t)
        hm, hua, h_ns, tls_u, tls_p = _tcp_http_tls_port_misuse(pkt)
        return FlowRecord(
            src_ip=src,
            dst_ip=dst,
            proto="tcp",
            sport=int(t.sport),
            dport=int(t.dport),
            pkt_size=plen,
            ts=ts,
            tcp_syn=syn,
            tcp_rst=rst,
            dns_qname=dns_q,
            ip_proto=ip_p,
            http_method=hm,
            http_user_agent=hua,
            http_nonstandard_port=h_ns,
            tls_unusual_port=tls_u,
            tls_on_plain_http_port=tls_p,
        )
    if UDP in pkt:
        u = pkt[UDP]
        return FlowRecord(
            src_ip=src,
            dst_ip=dst,
            proto="udp",
            sport=int(u.sport),
            dport=int(u.dport),
            pkt_size=plen,
            ts=ts,
            dns_qname=dns_q,
            ip_proto=ip_p,
        )
    if ICMP in pkt:
        ic = pkt[ICMP]
        try:
            itype = int(ic.type)
        except (TypeError, ValueError, AttributeError):
            itype = None
        return FlowRecord(
            src_ip=src,
            dst_ip=dst,
            proto="icmp",
            sport=None,
            dport=None,
            pkt_size=plen,
            ts=ts,
            icmp_type=itype,
            ip_proto=ip_p,
        )
    return FlowRecord(
        src_ip=src,
        dst_ip=dst,
        proto="ip",
        sport=None,
        dport=None,
        pkt_size=plen,
        ts=ts,
        ip_proto=ip_p,
    )


def sniff_flows(
    *,
    iface: str | None,
    duration_sec: float,
    bpf_filter: str | None = None,
) -> tuple[list[FlowRecord], str | None]:
    """
    Capture packets for a fixed duration. Requires Scapy + capture permissions (admin/root).

    Returns (records, error_message).
    """
    try:
        from scapy.all import sniff
    except ImportError as e:
        return [], f"Scapy is not installed: {e}"

    flows: list[FlowRecord] = []
    end = time.monotonic() + max(0.5, float(duration_sec))

    def stop_filter(_p) -> bool:
        return time.monotonic() >= end

    def prn(p) -> None:
        try:
            f = packet_to_flow(p)
            if f:
                flows.append(f)
        except (IndexError, KeyError, TypeError, ValueError, AttributeError):
            return

    try:
        sniff(
            iface=iface or None,
            prn=prn,
            store=False,
            filter=bpf_filter.strip() if bpf_filter else None,
            stop_filter=stop_filter,
        )
    except Exception as e:
        return flows, str(e)[:2000]
    return flows, None


def flows_from_pcap(path: str, *, max_packets: int | None = 500_000) -> tuple[list[FlowRecord], str | None]:
    """Read .pcap / .pcapng via Scapy PcapReader."""
    try:
        from scapy.utils import PcapReader
    except ImportError as e:
        return [], f"Scapy is not installed: {e}"

    flows: list[FlowRecord] = []
    try:
        with PcapReader(path) as reader:
            for i, pkt in enumerate(reader, start=1):
                if max_packets is not None and i > max_packets:
                    break
                try:
                    f = packet_to_flow(pkt)
                    if f:
                        flows.append(f)
                except (IndexError, KeyError, TypeError, ValueError, AttributeError):
                    continue
    except Exception as e:
        return [], str(e)[:2000]
    return flows, None


def analyze_flow_records(records: list[FlowRecord]) -> TrafficReport:
    """Run anomaly heuristics on a sequence of flow records."""
    n = len(records)
    findings: list[TrafficFinding] = []
    if n == 0:
        return TrafficReport(
            findings=[
                TrafficFinding(
                    "nta-empty",
                    "info",
                    "No packets parsed",
                    "Load a log, pcap, or run live capture.",
                    category="info",
                )
            ],
            stats={"records": 0},
            records_used=0,
        )

    tcp_recs = [r for r in records if r.proto == "tcp" and r.dport is not None]
    udp_recs = [r for r in records if r.proto == "udp" and r.dport is not None]
    icmp_recs = [r for r in records if r.proto == "icmp"]

    # --- Rapid TCP port sweep: same IP → many ports → short time (reconnaissance) ---
    tcp_by_pair_list: dict[tuple[str, str], list[FlowRecord]] = defaultdict(list)
    for r in tcp_recs:
        tcp_by_pair_list[(r.src_ip, r.dst_ip)].append(r)
    for (src, dst), recs in tcp_by_pair_list.items():
        with_ts = [r for r in recs if r.ts is not None]
        if len(with_ts) < 8:
            continue
        ports = {r.dport for r in with_ts if r.dport is not None}
        if len(ports) < 10:
            continue
        tmin = min(r.ts for r in with_ts)
        tmax = max(r.ts for r in with_ts)
        span = tmax - tmin
        if span <= 30.0:
            findings.append(
                TrafficFinding(
                    "nta-recon-rapid-tcp",
                    "high",
                    f"Rapid TCP port sweep (reconnaissance): {src} → {dst}",
                    f"{len(ports)} distinct destination ports within ~{span:.1f}s — same source probing many ports quickly.",
                    evidence={
                        "src": src,
                        "dst": dst,
                        "distinct_ports": len(ports),
                        "time_span_sec": round(span, 3),
                        "sample_ports": sorted(ports)[:40],
                    },
                    category="reconnaissance",
                )
            )

    # --- TCP vertical port scan: many distinct destination ports between same src -> dst ---
    tcp_ports_by_pair: dict[tuple[str, str], set[int]] = defaultdict(set)
    for r in tcp_recs:
        tcp_ports_by_pair[(r.src_ip, r.dst_ip)].add(r.dport)

    for (src, dst), ports in tcp_ports_by_pair.items():
        if len(ports) >= 15:
            findings.append(
                TrafficFinding(
                    "nta-tcp-portscan",
                    "high",
                    f"Possible TCP port scan: {src} → {dst}",
                    f"Observed {len(ports)} distinct TCP destination ports in this dataset.",
                    evidence={"src": src, "dst": dst, "distinct_ports": len(ports), "sample_ports": sorted(ports)[:40]},
                    category="reconnaissance",
                )
            )

    # --- UDP port scan ---
    udp_ports_by_pair: dict[tuple[str, str], set[int]] = defaultdict(set)
    for r in udp_recs:
        udp_ports_by_pair[(r.src_ip, r.dst_ip)].add(r.dport)

    for (src, dst), ports in udp_ports_by_pair.items():
        if len(ports) >= 12:
            findings.append(
                TrafficFinding(
                    "nta-udp-portscan",
                    "medium",
                    f"Possible UDP scan or multicast noise: {src} → {dst}",
                    f"{len(ports)} distinct UDP destination ports observed.",
                    evidence={"src": src, "dst": dst, "distinct_ports": len(ports)},
                    category="reconnaissance",
                )
            )

    # --- Horizontal scan: same src + dport, many targets ---
    targets_by_src_port: dict[tuple[str, int], set[str]] = defaultdict(set)
    for r in tcp_recs + udp_recs:
        if r.dport is None:
            continue
        targets_by_src_port[(r.src_ip, r.dport)].add(r.dst_ip)

    for (src, dport), dsts in targets_by_src_port.items():
        if len(dsts) >= 20:
            findings.append(
                TrafficFinding(
                    "nta-horizontal-scan",
                    "high",
                    f"Possible horizontal scan / worm activity from {src}",
                    f"Same destination port {dport} toward {len(dsts)} distinct hosts.",
                    evidence={"src": src, "dport": dport, "distinct_targets": len(dsts)},
                    category="reconnaissance",
                )
            )

    # --- Brute-force patterns: same IP → many TCP events to SSH/FTP/web/RDP in a short time ---
    brute_groups: dict[tuple[str, str, int], list[FlowRecord]] = defaultdict(list)
    for r in tcp_recs:
        if r.dport is None or r.dport not in BRUTE_FORCE_PORTS:
            continue
        brute_groups[(r.src_ip, r.dst_ip, r.dport)].append(r)
    for (src, dst, dport), grp in brute_groups.items():
        label, code_suf, svc_detail = _brute_force_labels(dport)
        tss = [r.ts for r in grp if r.ts is not None]
        total = len(grp)
        if tss:
            peak = _max_events_in_sliding_window(tss, BRUTE_WINDOW_SEC)
            if peak < BRUTE_MIN_IN_WINDOW:
                continue
            sev = "high" if peak >= BRUTE_HIGH_IN_WINDOW else "medium"
            title = f"[ALERT] {label} Brute Force suspected from {src}"
            detail = f"Attempts: {peak} in 1 minute (same source → {dst} {svc_detail})."
            code = f"nta-brute-{code_suf}"
            findings.append(
                TrafficFinding(
                    code,
                    sev,
                    title,
                    detail,
                    evidence={
                        "src": src,
                        "dst": dst,
                        "dport": dport,
                        "service": svc_detail,
                        "attempts_in_60s": peak,
                        "window_sec": BRUTE_WINDOW_SEC,
                        "total_events_observed": total,
                    },
                    category="brute_force",
                )
            )
        elif total >= BRUTE_MIN_TOTAL_NO_TS:
            sev = "medium"
            title = f"[ALERT] {label} Brute Force suspected from {src}"
            detail = (
                f"Attempts: {total} in capture (no reliable per-event timestamps — weak signal). "
                f"Same source → {dst} {svc_detail}."
            )
            findings.append(
                TrafficFinding(
                    f"nta-brute-{code_suf}",
                    sev,
                    title,
                    detail,
                    evidence={
                        "src": src,
                        "dst": dst,
                        "dport": dport,
                        "service": svc_detail,
                        "total_events_no_timestamps": total,
                    },
                    category="brute_force",
                )
            )

    # --- Suspicious IP behavior (external vs private space, sensitive ports, private→public) ---
    from .ip_utils import is_private_ipv4, is_public_ipv4

    # --- Lateral movement: one internal host scanning or contacting many distinct internal hosts ---
    lateral_targets: dict[str, set[str]] = defaultdict(set)
    for r in tcp_recs + udp_recs:
        if r.dport is None:
            continue
        if not is_private_ipv4(r.src_ip) or not is_private_ipv4(r.dst_ip):
            continue
        if r.src_ip == r.dst_ip:
            continue
        dst = r.dst_ip
        if dst.endswith(".255") or dst == "255.255.255.255":
            continue
        lateral_targets[r.src_ip].add(dst)

    for r in icmp_recs:
        if not is_private_ipv4(r.src_ip) or not is_private_ipv4(r.dst_ip):
            continue
        if r.src_ip == r.dst_ip:
            continue
        dst = r.dst_ip
        if dst.endswith(".255") or dst == "255.255.255.255":
            continue
        lateral_targets[r.src_ip].add(dst)

    for src, dsts in lateral_targets.items():
        c = len(dsts)
        if c < LATERAL_MIN_INTERNAL_TARGETS:
            continue
        sev = "high" if c >= LATERAL_HIGH_INTERNAL_TARGETS else "medium"
        findings.append(
            TrafficFinding(
                "nta-lateral-internal-scan",
                sev,
                f"Possible lateral movement: internal host scanning multiple internal targets ({src})",
                f"Private (RFC1918) source reached {c} distinct private destination addresses — consistent with "
                f"subnet discovery, worm-like spread, or staged pivoting inside the network.",
                evidence={
                    "src": src,
                    "distinct_internal_targets": c,
                    "sample_targets": sorted(dsts)[:32],
                },
                category="lateral_movement",
            )
        )

    ext_src_ports: dict[str, set[int]] = defaultdict(set)
    ext_src_internals: dict[str, set[str]] = defaultdict(set)
    for r in tcp_recs + udp_recs:
        if r.dport is None:
            continue
        if not is_public_ipv4(r.src_ip) or not is_private_ipv4(r.dst_ip):
            continue
        ext_src_ports[r.src_ip].add(r.dport)
        ext_src_internals[r.src_ip].add(r.dst_ip)

    for src, ports in ext_src_ports.items():
        if len(ports) >= SUSP_EXT_MIN_DISTINCT_PORTS:
            findings.append(
                TrafficFinding(
                    "nta-susp-external-multi-service",
                    "high",
                    f"Suspicious: external IP hitting many services toward internal space ({src})",
                    f"Public source → private destinations on {len(ports)} distinct destination ports "
                    f"(possible lateral probe or multi-service attack).",
                    evidence={
                        "src": src,
                        "distinct_destination_ports": len(ports),
                        "sample_ports": sorted(ports)[:32],
                        "distinct_internal_hosts": len(ext_src_internals.get(src, set())),
                    },
                    category="suspicious_ip",
                )
            )
        elif len(ext_src_internals.get(src, set())) >= SUSP_EXT_MIN_INTERNAL_HOSTS:
            findings.append(
                TrafficFinding(
                    "nta-susp-external-many-hosts",
                    "medium",
                    f"Suspicious: external IP contacting many internal hosts ({src})",
                    f"Same public source reached {len(ext_src_internals[src])} distinct private addresses.",
                    evidence={
                        "src": src,
                        "distinct_internal_hosts": len(ext_src_internals[src]),
                        "sample_internal": sorted(ext_src_internals[src])[:24],
                    },
                    category="suspicious_ip",
                )
            )

    sens_groups: dict[tuple[str, str, int], list[FlowRecord]] = defaultdict(list)
    for r in tcp_recs:
        if r.dport is None or r.dport not in SENSITIVE_EXTRA_PORTS:
            continue
        sens_groups[(r.src_ip, r.dst_ip, r.dport)].append(r)
    for (src, dst, dport), grp in sens_groups.items():
        tss = [r.ts for r in grp if r.ts is not None]
        total = len(grp)
        if tss:
            peak = _max_events_in_sliding_window(tss, BRUTE_WINDOW_SEC)
            if peak < SUSP_SENSITIVE_PEAK:
                continue
            findings.append(
                TrafficFinding(
                    "nta-susp-sensitive-repeated",
                    "high" if peak >= 28 else "medium",
                    f"Repeated access to sensitive port :{dport} from {src}",
                    f"~{peak} connection events to {dst}:{dport} within 60s (non-login sensitive port list).",
                    evidence={
                        "src": src,
                        "dst": dst,
                        "dport": dport,
                        "events_in_60s": peak,
                    },
                    category="suspicious_ip",
                )
            )
        elif total >= SUSP_SENSITIVE_TOTAL_NO_TS:
            findings.append(
                TrafficFinding(
                    "nta-susp-sensitive-repeated",
                    "medium",
                    f"Repeated access to sensitive port :{dport} from {src}",
                    f"{total} events toward {dst}:{dport} (no per-event timestamps — weaker signal).",
                    evidence={"src": src, "dst": dst, "dport": dport, "total_events": total},
                    category="suspicious_ip",
                )
            )

    priv_pub_dsts: dict[str, set[str]] = defaultdict(set)
    priv_pub_count: Counter[str] = Counter()
    for r in tcp_recs + udp_recs:
        if not is_private_ipv4(r.src_ip) or not is_public_ipv4(r.dst_ip):
            continue
        priv_pub_dsts[r.src_ip].add(r.dst_ip)
        priv_pub_count[r.src_ip] += 1

    for src, dsts in priv_pub_dsts.items():
        cnt = priv_pub_count[src]
        if len(dsts) >= SUSP_PRIV_PUB_MIN_DISTINCT_DSTS or (
            cnt >= SUSP_PRIV_PUB_MIN_EVENTS and len(dsts) >= 8
        ):
            findings.append(
                TrafficFinding(
                    "nta-susp-private-to-public",
                    "medium",
                    f"Unusual private→public pattern from {src}",
                    f"Internal source contacted {len(dsts)} distinct public destinations ({cnt} events) — "
                    f"review for scanning, C2, or data exfil (heuristic).",
                    evidence={
                        "src": src,
                        "distinct_public_dsts": len(dsts),
                        "events": cnt,
                        "sample_dsts": sorted(dsts)[:20],
                    },
                    category="suspicious_ip",
                )
            )

    # --- Unauthorized access attempts (restricted ports; internal services exposed to Internet) ---
    unauth_ports = ADMIN_PANEL_PORTS | RESTRICTED_UNAUTH_PORTS
    unauth_groups: dict[tuple[str, str, int], list[FlowRecord]] = defaultdict(list)
    exposure_src: dict[tuple[str, int], set[str]] = defaultdict(set)
    for r in tcp_recs:
        if r.dport is None or r.dport not in unauth_ports:
            continue
        if not is_public_ipv4(r.src_ip) or not is_private_ipv4(r.dst_ip):
            continue
        key = (r.src_ip, r.dst_ip, r.dport)
        unauth_groups[key].append(r)
        exposure_src[(r.dst_ip, r.dport)].add(r.src_ip)

    for (src, dst, dport), grp in unauth_groups.items():
        tss = [r.ts for r in grp if r.ts is not None]
        total = len(grp)
        if tss:
            peak = _max_events_in_sliding_window(tss, BRUTE_WINDOW_SEC)
            if peak < UNAUTH_MIN_IN_60S:
                continue
            if dport in ADMIN_PANEL_PORTS:
                title = "[ALERT] Unauthorized attempt to access admin panel"
                detail = (
                    f"Public source {src} toward internal {dst}:{dport} — ~{peak} connection events in 60s "
                    f"(admin-style port; verify intent and access controls)."
                )
            else:
                title = "[ALERT] Unauthorized attempt to access restricted service"
                detail = (
                    f"Public source {src} toward internal {dst}:{dport} — ~{peak} events in 60s "
                    f"(restricted port heuristic)."
                )
            findings.append(
                TrafficFinding(
                    "nta-unauth-restricted-access",
                    "high" if peak >= 20 else "medium",
                    title,
                    detail,
                    evidence={
                        "src": src,
                        "dst": dst,
                        "dport": dport,
                        "events_in_60s": peak,
                        "admin_panel_port": dport in ADMIN_PANEL_PORTS,
                    },
                    category="unauthorized_access",
                )
            )
        elif total >= UNAUTH_MIN_TOTAL_NO_TS:
            title = (
                "[ALERT] Unauthorized attempt to access admin panel"
                if dport in ADMIN_PANEL_PORTS
                else "[ALERT] Unauthorized attempt to access restricted service"
            )
            detail = f"Public {src} → private {dst}:{dport} — {total} events (timestamps sparse; review logs)."
            findings.append(
                TrafficFinding(
                    "nta-unauth-restricted-access",
                    "medium",
                    title,
                    detail,
                    evidence={"src": src, "dst": dst, "dport": dport, "total_events": total},
                    category="unauthorized_access",
                )
            )

    for (dst, dport), pub_srcs in exposure_src.items():
        if dport not in unauth_ports:
            continue
        if len(pub_srcs) < UNAUTH_EXPOSURE_MIN_PUBLIC_SOURCES:
            continue
        findings.append(
            TrafficFinding(
                "nta-unauth-internal-exposure",
                "high" if len(pub_srcs) >= 6 else "medium",
                "[ALERT] Unexpected internal service exposure",
                f"Internal host {dst} on port {dport} was reached from {len(pub_srcs)} distinct public sources "
                f"(possible unintended exposure of a management or sensitive service).",
                evidence={
                    "dst": dst,
                    "dport": dport,
                    "distinct_public_sources": len(pub_srcs),
                    "sample_sources": sorted(pub_srcs)[:16],
                },
                category="unauthorized_access",
            )
        )

    # --- DNS anomalies (volume / tunneling heuristics; suspicious FQDN shapes when qname is known) ---
    def _is_dns_traffic(r: FlowRecord) -> bool:
        if r.dns_qname:
            return True
        if r.proto == "udp" and (r.dport == 53 or r.sport == 53):
            return True
        if r.proto == "tcp" and (r.dport == 53 or r.sport == 53):
            return True
        return False

    dns_rows = [r for r in records if _is_dns_traffic(r)]
    dns_ts_by_src: dict[str, list[float]] = defaultdict(list)
    for r in dns_rows:
        if r.ts is not None:
            dns_ts_by_src[r.src_ip].append(r.ts)
    for src, tss in dns_ts_by_src.items():
        peak = _max_events_in_sliding_window(tss, 60.0)
        if peak >= DNS_TUNNEL_MIN_QPS:
            findings.append(
                TrafficFinding(
                    "nta-dns-high-frequency",
                    "high" if peak >= 85 else "medium",
                    "[ALERT] Possible DNS tunneling or excessive queries",
                    f"~{peak} DNS-related events in 60s from {src} (high frequency — rule out misconfiguration and malware).",
                    evidence={"src": src, "events_per_60s": peak, "threshold": DNS_TUNNEL_MIN_QPS},
                    category="dns_anomaly",
                )
            )

    susp_by_src: dict[str, list[str]] = defaultdict(list)
    for r in records:
        if not r.dns_qname:
            continue
        if is_suspicious_domain(r.dns_qname):
            susp_by_src[r.src_ip].append(r.dns_qname)
    for src, names in susp_by_src.items():
        uniq = list(dict.fromkeys(names))
        if len(uniq) >= DNS_SUSPICIOUS_MIN_SAMPLES:
            findings.append(
                TrafficFinding(
                    "nta-dns-suspicious-domains",
                    "medium",
                    f"Suspicious / random-looking DNS query names from {src}",
                    f"Observed {len(uniq)} distinct unusual FQDN shapes (high frequency + unusual labels — heuristic).",
                    evidence={"src": src, "sample_queries": uniq[:24]},
                    category="dns_anomaly",
                )
            )

    # --- Data exfiltration heuristics (large outbound private→public, upload-heavy ratio) ---
    outbound_bytes: dict[str, list[tuple[float, int]]] = defaultdict(list)
    out_total: Counter[str] = Counter()
    in_total: Counter[str] = Counter()
    for r in records:
        sz = max(0, r.pkt_size)
        if is_private_ipv4(r.src_ip) and is_public_ipv4(r.dst_ip):
            out_total[r.src_ip] += sz
            if r.ts is not None:
                outbound_bytes[r.src_ip].append((r.ts, sz))
        if is_public_ipv4(r.src_ip) and is_private_ipv4(r.dst_ip):
            in_total[r.dst_ip] += sz

    for src, evs in outbound_bytes.items():
        if not evs:
            continue
        max_b, w0, w1 = _max_bytes_in_sliding_window(evs, EXFIL_WINDOW_SEC)
        if max_b < EXFIL_MIN_BYTES_ALERT:
            continue
        mb = max_b / (1024.0 * 1024.0)
        span = max(w1 - w0, 0.001)
        sev = "high" if max_b >= EXFIL_HIGH_BYTES else "medium"
        findings.append(
            TrafficFinding(
                "nta-exfil-outbound-volume",
                sev,
                "[ALERT] Possible Data Exfiltration",
                f"Outbound traffic: {mb:.1f}MB in 2 minutes (sliding window peak from internal host {src} toward the Internet).",
                evidence={
                    "src": src,
                    "bytes_in_window": max_b,
                    "window_sec": EXFIL_WINDOW_SEC,
                    "window_peak_start": w0,
                    "window_peak_end": w1,
                    "span_sec": round(span, 3),
                },
                category="data_exfil",
            )
        )

    for priv, ob in out_total.items():
        ib = in_total.get(priv, 0)
        tot = ob + ib
        if tot < EXFIL_UPLOAD_RATIO_MIN_BYTES:
            continue
        if ob / (tot + 1) < EXFIL_UPLOAD_RATIO_OUT_SHARE:
            continue
        findings.append(
            TrafficFinding(
                "nta-exfil-upload-bias",
                "medium",
                "[ALERT] Possible Data Exfiltration",
                f"Unusual upload-heavy behavior from {priv}: ~{100 * ob / (tot + 1):.0f}% of observed bytes are outbound "
                f"to the public Internet vs inbound (~{ob / (1024*1024):.1f}MB out, ~{ib / (1024*1024):.1f}MB in).",
                evidence={
                    "private_host": priv,
                    "outbound_bytes": ob,
                    "inbound_bytes": ib,
                    "out_share": round(ob / (tot + 1), 4),
                },
                category="data_exfil",
            )
        )

    # --- Protocol anomalies (sizes, rare IP protocols, alternate service ports) ---
    impossible = [r for r in records if r.pkt_size > 65535]
    if impossible:
        findings.append(
            TrafficFinding(
                "nta-proto-impossible-length",
                "high",
                "Malformed / impossible packet lengths observed",
                f"{len(impossible)} events report total length > 65535 bytes (invalid for IPv4 on the wire — capture or parsing artifact).",
                evidence={"count": len(impossible)},
                category="protocol_anomaly",
            )
        )

    tiny_by_src: Counter[str] = Counter()
    for r in records:
        if 0 < r.pkt_size < PROTO_TINY_BYTES:
            tiny_by_src[r.src_ip] += 1
    for src, c in tiny_by_src.most_common(12):
        if c >= PROTO_TINY_MIN_EVENTS:
            findings.append(
                TrafficFinding(
                    "nta-proto-tiny-packets",
                    "medium",
                    f"Many abnormally small packets from {src}",
                    f"{c} packets under {PROTO_TINY_BYTES} bytes (possible fragmentation, malformed frames, or measurement noise).",
                    evidence={"src": src, "tiny_packet_count": c, "threshold_bytes": PROTO_TINY_BYTES},
                    category="protocol_anomaly",
                )
            )

    rare_proto_counts: Counter[int] = Counter()
    for r in records:
        if r.ip_proto is not None and r.ip_proto in RARE_IP_PROTOS:
            rare_proto_counts[r.ip_proto] += 1
    for pnum, c in rare_proto_counts.items():
        if c >= 5:
            findings.append(
                TrafficFinding(
                    "nta-proto-rare-ip-protocol",
                    "medium",
                    f"Unexpected IP protocol usage (proto={pnum})",
                    f"Observed {c} packets using a non-TCP/UDP/ICMP IP protocol number ({pnum}) — review tunnels/VPNs (GRE, ESP, etc.).",
                    evidence={"ip_protocol": pnum, "packet_count": c},
                    category="protocol_anomaly",
                )
            )

    large_icmp = [r for r in icmp_recs if r.pkt_size >= PROTO_ICMP_LARGE_BYTES]
    if large_icmp:
        mx = max(r.pkt_size for r in large_icmp)
        ex = large_icmp[0]
        findings.append(
            TrafficFinding(
                "nta-proto-large-icmp",
                "low",
                f"Unusually large ICMP payloads (max {mx} bytes)",
                f"Example: {ex.src_ip} → {ex.dst_ip}. Large ICMP may indicate tunneling or fragmentation (heuristic).",
                evidence={
                    "max_bytes": mx,
                    "count": len(large_icmp),
                    "example_src": ex.src_ip,
                    "example_dst": ex.dst_ip,
                },
                category="protocol_anomaly",
            )
        )

    alt_groups: dict[tuple[str, str, int], int] = defaultdict(int)
    for r in tcp_recs:
        if r.dport is None:
            continue
        if r.dport in ALT_SSH_PORTS | ALT_RDP_PORTS:
            alt_groups[(r.src_ip, r.dst_ip, r.dport)] += 1
    for (src, dst, dport), c in alt_groups.items():
        if c < PROTO_ALT_PORT_MIN_EVENTS:
            continue
        svc = "SSH" if dport in ALT_SSH_PORTS else "RDP"
        findings.append(
            TrafficFinding(
                "nta-proto-nonstandard-service-port",
                "low",
                f"Non-standard {svc} port in use ({dport})",
                f"{c} TCP events {src} → {dst}:{dport} — common alternate ports for {svc}; validate policy (may be legitimate).",
                evidence={"src": src, "dst": dst, "dport": dport, "events": c, "service_guess": svc},
                category="protocol_anomaly",
            )
        )

    seen_sym: set[tuple[str, str, int]] = set()
    for r in tcp_recs:
        if r.sport is None or r.dport is None:
            continue
        if r.sport != r.dport or r.dport not in PROTO_SYM_SERVICE_PORTS:
            continue
        k = (r.src_ip, r.dst_ip, r.dport)
        if k in seen_sym:
            continue
        seen_sym.add(k)
        findings.append(
            TrafficFinding(
                "nta-proto-symmetric-ports",
                "medium",
                f"Unexpected symmetric TCP ports ({r.dport})",
                f"{r.src_ip} ↔ {r.dst_ip} both use port {r.dport} — unusual for typical client/server services.",
                evidence={"src": r.src_ip, "dst": r.dst_ip, "port": r.dport},
                category="protocol_anomaly",
            )
        )

    # --- HTTP User-Agent / automated client behavior (cleartext HTTP in TCP only) ---
    http_rows = [r for r in tcp_recs if r.http_method is not None]
    _HIGH_RISK_AUTO = (
        "nmap",
        "sqlmap",
        "masscan",
        "nikto",
        "zgrab",
        "nessus",
        "acunetix",
        "openvas",
    )
    if http_rows:
        missing_by_src: Counter[str] = Counter()
        auto_by_src: dict[str, list[FlowRecord]] = defaultdict(list)
        weird_by_src: dict[str, list[str]] = defaultdict(list)
        for r in http_rows:
            ua = r.http_user_agent
            if ua == "":
                missing_by_src[r.src_ip] += 1
            elif ua:
                if is_automated_user_agent(ua):
                    auto_by_src[r.src_ip].append(r)
                if is_weird_user_agent(ua) and len(weird_by_src[r.src_ip]) < 8:
                    weird_by_src[r.src_ip].append(ua[:400])

        for src, c in missing_by_src.items():
            if c < 2:
                continue
            sev = "medium" if c >= 5 else "low"
            findings.append(
                TrafficFinding(
                    "nta-http-ua-missing",
                    sev,
                    f"HTTP requests without User-Agent from {src}",
                    f"{c} cleartext HTTP requests had no User-Agent header — may indicate scripted clients, legacy stacks, or misconfigured tools.",
                    evidence={"src": src, "requests_without_ua": c},
                    category="http_behavior",
                )
            )

        for src, rows in auto_by_src.items():
            if not rows:
                continue
            uas = [r.http_user_agent or "" for r in rows]
            uniq = list(dict.fromkeys(uas))[:8]
            high = any(any(x in (u or "").lower() for x in _HIGH_RISK_AUTO) for u in uniq)
            if len(rows) < 2 and not high:
                continue
            sev = "high" if high else ("medium" if len(rows) >= 6 else "low")
            findings.append(
                TrafficFinding(
                    "nta-http-ua-automated",
                    sev,
                    f"Automated tool / scanner–like User-Agent from {src}",
                    "Cleartext HTTP with User-Agent strings typical of scripts, CLI clients, or security scanners.",
                    evidence={
                        "src": src,
                        "observations": len(rows),
                        "sample_user_agents": uniq,
                    },
                    category="http_behavior",
                )
            )

        for src, samples in weird_by_src.items():
            tiny = any(len(s.strip()) <= 2 for s in samples)
            if len(samples) < 2 and not tiny:
                continue
            findings.append(
                TrafficFinding(
                    "nta-http-ua-weird",
                    "low",
                    f"Unusual User-Agent strings from {src}",
                    "Short, placeholder, or mostly non-printable User-Agent values in cleartext HTTP.",
                    evidence={"src": src, "samples": samples[:5]},
                    category="http_behavior",
                )
            )

    # --- Port misuse: cleartext HTTP on non-standard ports; TLS on unusual or plain-HTTP ports ---
    http_ns: Counter[tuple[str, str, int]] = Counter()
    tls_un: Counter[tuple[str, str, int]] = Counter()
    tls_pl: Counter[tuple[str, str, int]] = Counter()
    for r in tcp_recs:
        if r.http_nonstandard_port:
            http_ns[(r.src_ip, r.dst_ip, int(r.dport))] += 1
        if r.tls_unusual_port:
            tls_un[(r.src_ip, r.dst_ip, int(r.dport))] += 1
        if r.tls_on_plain_http_port:
            tls_pl[(r.src_ip, r.dst_ip, int(r.dport))] += 1

    for (src, dst, dport), c in http_ns.items():
        findings.append(
            TrafficFinding(
                "nta-port-misuse-http-nonstandard",
                "medium",
                f"Cleartext HTTP on non-standard port {dport}",
                f"HTTP request line detected toward {dst}:{dport} — typical cleartext web ports are listed in engine "
                f"constants (e.g. 80, 8080); other ports may indicate tunnels, admin tools, or policy bypass.",
                evidence={"src": src, "dst": dst, "dport": dport, "observations": c},
                category="port_misuse",
            )
        )

    for (src, dst, dport), c in tls_un.items():
        findings.append(
            TrafficFinding(
                "nta-port-misuse-tls-unusual",
                "medium",
                f"TLS (ClientHello) on non-standard port {dport}",
                f"TLS handshake toward {dst}:{dport} — encrypted traffic on a port not in the usual HTTPS/TLS set "
                f"(heuristic). Review for covert channels, custom apps, or misconfiguration.",
                evidence={"src": src, "dst": dst, "dport": dport, "observations": c},
                category="port_misuse",
            )
        )

    for (src, dst, dport), c in tls_pl.items():
        findings.append(
            TrafficFinding(
                "nta-port-misuse-tls-on-plain-port",
                "medium",
                f"TLS on port commonly used for cleartext HTTP ({dport})",
                f"TLS ClientHello toward {dst}:{dport} — this port often carries cleartext HTTP; encrypted traffic here "
                f"may be legitimate HTTPS-on-8080 or worth validating against policy.",
                evidence={"src": src, "dst": dst, "dport": dport, "observations": c},
                category="port_misuse",
            )
        )

    # --- Malware / beaconing — small packets, same src→dst:port, regular inter-arrival times ---
    beacon_groups: dict[tuple[str, str, int], list[FlowRecord]] = defaultdict(list)
    for r in records:
        if r.proto not in ("tcp", "udp") or r.dport is None or r.ts is None:
            continue
        if r.pkt_size > BEACON_MAX_PKT_BYTES:
            continue
        dst = r.dst_ip
        if dst.startswith("224.") or dst.startswith("239.") or dst == "255.255.255.255":
            continue
        beacon_groups[(r.src_ip, dst, r.dport)].append(r)

    for (src, dst, dport), recs in beacon_groups.items():
        if len(recs) < BEACON_MIN_EVENTS_MERGED:
            continue
        ts_sorted = sorted(r.ts for r in recs if r.ts is not None)
        if len(ts_sorted) < BEACON_MIN_EVENTS_MERGED:
            continue
        merged = _merge_burst_timestamps(ts_sorted, BEACON_BURST_MERGE_SEC)
        if len(merged) < BEACON_MIN_EVENTS_MERGED:
            continue
        gaps = [merged[i + 1] - merged[i] for i in range(len(merged) - 1)]
        gaps = [g for g in gaps if g >= BEACON_MIN_GAP_SEC]
        if len(gaps) < BEACON_MIN_INTERVALS:
            continue
        regular, mean_g, cv = _beaconing_gaps_regular(gaps)
        if not regular:
            continue
        sev = "high" if cv < 0.12 and len(merged) >= 8 else "medium"
        findings.append(
            TrafficFinding(
                "nta-beaconing-regular-interval",
                sev,
                f"Possible beaconing / C2-style pattern: {src} → {dst}:{dport}",
                f"Repeated small packets (≤{BEACON_MAX_PKT_BYTES} bytes) to the same destination with similar spacing "
                f"(mean interval ~{mean_g:.1f}s, interval regularity CV≈{cv:.2f}) — review for malware callbacks or scripted checks.",
                evidence={
                    "src": src,
                    "dst": dst,
                    "dport": dport,
                    "merged_pulse_count": len(merged),
                    "mean_interval_sec": round(mean_g, 3),
                    "interval_cv": round(cv, 4),
                    "sample_gaps_sec": [round(g, 3) for g in gaps[:8]],
                    "max_packet_bytes": BEACON_MAX_PKT_BYTES,
                },
                category="beaconing",
            )
        )

    # --- ARP spoofing / IP–MAC conflict (same IPv4 claimed by multiple MACs) ---
    ip_to_macs: dict[str, set[str]] = defaultdict(set)
    for r in records:
        if r.proto != "arp" or not r.mac_src:
            continue
        if r.mac_src == "ff:ff:ff:ff:ff:ff" or r.mac_src == "00:00:00:00:00:00":
            continue
        ip_to_macs[r.src_ip].add(r.mac_src)
    for ip, macs in ip_to_macs.items():
        if len(macs) < 2:
            continue
        findings.append(
            TrafficFinding(
                "nta-arp-ip-mac-conflict",
                "high",
                "[ALERT] ARP Spoofing suspected",
                "IP conflict detected: the same IPv4 address is associated with multiple sender MAC addresses in ARP traffic.",
                evidence={
                    "ip": ip,
                    "mac_addresses": sorted(macs),
                    "distinct_macs": len(macs),
                },
                category="arp_spoofing",
            )
        )

    # --- SYN-heavy ratio (possible SYN flood or scan) ---
    syn_by_src: Counter[str] = Counter()
    tcp_by_src: Counter[str] = Counter()
    for r in tcp_recs:
        tcp_by_src[r.src_ip] += 1
        if r.tcp_syn and not r.tcp_rst:
            syn_by_src[r.src_ip] += 1

    for src, syn_c in syn_by_src.most_common(20):
        total = tcp_by_src.get(src, 0)
        if total < 35:
            continue
        ratio = syn_c / total
        if ratio >= 0.85:
            findings.append(
                TrafficFinding(
                    "nta-syn-heavy",
                    "medium",
                    f"SYN scan–like pattern (half-open / probe-heavy) from {src}",
                    f"About {ratio:.0%} of TCP packets from this source are SYN ({syn_c}/{total}) — typical of SYN scans or incomplete handshakes.",
                    evidence={"src": src, "syn_packets": syn_c, "tcp_packets": total},
                    category="reconnaissance",
                )
            )

    # --- ICMP ping sweep: one source → many distinct targets (host discovery) ---
    icmp_targets_by_src: dict[str, set[str]] = defaultdict(set)
    for r in icmp_recs:
        if r.icmp_type == 0:
            continue
        icmp_targets_by_src[r.src_ip].add(r.dst_ip)
    for src, dsts in icmp_targets_by_src.items():
        if len(dsts) >= 10:
            findings.append(
                TrafficFinding(
                    "nta-recon-ping-sweep",
                    "medium",
                    f"Possible ICMP ping sweep / host discovery from {src}",
                    f"Same source sent ICMP to {len(dsts)} distinct destination addresses (echo-reply packets excluded when type is known).",
                    evidence={"src": src, "distinct_icmp_targets": len(dsts), "sample_targets": sorted(dsts)[:24]},
                    category="reconnaissance",
                )
            )

    # --- ICMP flood ---
    icmp_by_src = Counter(r.src_ip for r in icmp_recs)
    for src, c in icmp_by_src.most_common(10):
        if c >= 50 and n >= 100:
            findings.append(
                TrafficFinding(
                    "nta-icmp-volume",
                    "medium",
                    f"High ICMP volume from {src}",
                    f"{c} ICMP packets in capture.",
                    evidence={"src": src, "icmp_packets": c},
                    category="traffic_anomaly",
                )
            )

    # --- Per-second buckets & DDoS / traffic flood (need timestamps) ---
    ts_records = [r for r in records if r.ts is not None]
    if len(ts_records) >= DDOS_MIN_RECORDS_FOR_BUCKETS:
        buckets: dict[int, list[FlowRecord]] = defaultdict(list)
        for r in ts_records:
            bi = int(r.ts)
            buckets[bi].append(r)

        counts = [len(v) for v in buckets.values()]
        peak_sec = max(buckets.keys(), key=lambda b: len(buckets[b]))
        peak_rows = buckets[peak_sec]
        mx = max(counts) if counts else 0
        med = statistics.median(counts) if len(counts) >= 3 else 0.0

        # --- DDoS / traffic flood (absolute rates; "requests" = packet/flow events in window) ---
        if mx >= DDOS_PEAK_PPS_MEDIUM:
            sev = "high" if mx >= DDOS_PEAK_PPS_HIGH else "medium"
            findings.append(
                TrafficFinding(
                    "nta-ddos-peak-pps",
                    sev,
                    "[ALERT] Possible DDoS detected",
                    f"Traffic spike: {mx} requests/sec",
                    evidence={
                        "peak_second_epoch": peak_sec,
                        "requests_per_sec": mx,
                        "threshold_medium": DDOS_PEAK_PPS_MEDIUM,
                        "threshold_high": DDOS_PEAK_PPS_HIGH,
                    },
                    category="ddos_flood",
                )
            )

        if peak_rows and len(peak_rows) >= DDOS_SINGLE_IP_MIN_PEAK_EVENTS and mx >= DDOS_SINGLE_IP_MIN_PPS:
            src_counts = Counter(r.src_ip for r in peak_rows)
            top_src, top_n = src_counts.most_common(1)[0]
            share = top_n / len(peak_rows)
            if share >= DDOS_SINGLE_IP_SHARE:
                findings.append(
                    TrafficFinding(
                        "nta-ddos-single-ip",
                        "high" if share >= 0.65 and mx >= DDOS_PEAK_PPS_MEDIUM else "medium",
                        "[ALERT] Possible DDoS detected",
                        f"Too many requests from one IP: {top_src} ({share:.0%} of events in the busiest second, {mx} req/sec total).",
                        evidence={
                            "src": top_src,
                            "share_busiest_second": round(share, 4),
                            "events_in_peak_second": len(peak_rows),
                            "requests_per_sec_peak_second": mx,
                        },
                        category="ddos_flood",
                    )
                )

        tmin_ts = min(r.ts for r in ts_records if r.ts is not None)
        tmax_ts = max(r.ts for r in ts_records if r.ts is not None)
        span_ts = float(tmax_ts - tmin_ts)
        if span_ts >= DDOS_MIN_SPAN_SEC:
            overall_pps = len(ts_records) / span_ts
            if overall_pps >= DDOS_OVERALL_PPS:
                findings.append(
                    TrafficFinding(
                        "nta-ddos-overall-rate",
                        "medium",
                        "[ALERT] Possible DDoS detected",
                        f"Too many requests overall: ~{overall_pps:.0f} requests/sec averaged across the capture window.",
                        evidence={
                            "avg_requests_per_sec": round(overall_pps, 2),
                            "time_span_sec": round(span_ts, 3),
                            "events_with_timestamps": len(ts_records),
                            "threshold_avg_pps": DDOS_OVERALL_PPS,
                        },
                        category="ddos_flood",
                    )
                )

        # --- Relative traffic spike (baseline comparison) ---
        if len(ts_records) >= 30 and len(counts) >= 3:
            if med > 0 and mx >= med * 5 and mx >= 50:
                findings.append(
                    TrafficFinding(
                        "nta-traffic-spike",
                        "medium",
                        "Traffic volume spike (packets per second)",
                        f"Peak second had {mx} packets vs median {med:.1f} packets/sec across {len(buckets)} seconds.",
                        evidence={"peak_second_epoch": peak_sec, "peak_pps": mx, "median_pps": med},
                        category="traffic_anomaly",
                    )
                )

        # --- Traffic pattern anomaly (smart baseline): peak vs normal rate excluding busiest second ---
        if (
            len(ts_records) >= PATTERN_MIN_RECORDS_WITH_TS
            and len(counts) >= PATTERN_MIN_SECOND_BUCKETS
        ):
            baseline = _normal_traffic_baseline_pps(counts)
            if baseline >= PATTERN_MIN_NORMAL_BASELINE_PPS and mx >= PATTERN_MIN_PEAK_PPS:
                ratio = mx / baseline if baseline > 0 else 0.0
                if ratio >= PATTERN_RATIO_WARN:
                    sev = "high" if ratio >= PATTERN_RATIO_HIGH else "medium"
                    findings.append(
                        TrafficFinding(
                            "nta-traffic-pattern-baseline",
                            sev,
                            "Traffic pattern anomaly — deviation from normal baseline",
                            f"Peak second ~{mx} req/sec vs estimated normal baseline ~{baseline:.1f} req/sec "
                            f"(~{ratio:.0f}× baseline). Example: if normal is ~{baseline:.0f}/s and the peak second is ~{mx}/s, review for abuse or misconfiguration.",
                            evidence={
                                "peak_second_epoch": peak_sec,
                                "peak_pps": mx,
                                "normal_baseline_pps": round(baseline, 2),
                                "ratio_peak_to_baseline": round(ratio, 2),
                                "seconds_with_traffic": len(counts),
                            },
                            category="traffic_pattern",
                        )
                    )

        if len(ts_records) >= 30 and peak_rows:
            src_counts = Counter(r.src_ip for r in peak_rows)
            top_src, top_n = src_counts.most_common(1)[0]
            if top_n >= 0.5 * len(peak_rows) and len(peak_rows) >= 40:
                findings.append(
                    TrafficFinding(
                        "nta-dominant-source",
                        "low",
                        f"Dominant talker during busiest second: {top_src}",
                        f"In the busiest second, {top_n}/{len(peak_rows)} packets were from this source.",
                        evidence={"src": top_src, "share": top_n / len(peak_rows)},
                        category="traffic_anomaly",
                    )
                )

    # --- Large single-source volume (overall) ---
    overall_src = Counter(r.src_ip for r in records)
    if n >= 200:
        top_src, top_c = overall_src.most_common(1)[0]
        if top_c / n >= 0.45:
            findings.append(
                TrafficFinding(
                    "nta-single-source-volume",
                    "low",
                    f"Single source dominates traffic: {top_src}",
                    f"{top_c}/{n} packets ({100 * top_c / n:.1f}%) from one address.",
                    evidence={"src": top_src, "packets": top_c, "fraction": top_c / n},
                    category="traffic_anomaly",
                )
            )

    # --- RST sweep (possible scan or IDS) ---
    rst_by_pair: dict[tuple[str, str], int] = defaultdict(int)
    for r in tcp_recs:
        if r.tcp_rst:
            rst_by_pair[(r.src_ip, r.dst_ip)] += 1
    for (src, dst), c in rst_by_pair.items():
        if c >= 40:
            findings.append(
                TrafficFinding(
                    "nta-rst-volume",
                    "low",
                    f"Many TCP RST between {src} and {dst}",
                    f"{c} RST-flagged packets observed.",
                    evidence={"src": src, "dst": dst, "rst_packets": c},
                    category="traffic_anomaly",
                )
            )

    if not findings:
        findings.append(
            TrafficFinding(
                "nta-clean",
                "info",
                "No strong anomalies vs built-in thresholds",
                "Heuristics did not flag port scans, spikes, or floods at current sensitivity. "
                "Try longer capture, a busier log slice, or lower thresholds in a future release.",
                evidence={"records": n},
                category="info",
            )
        )

    stats: dict[str, Any] = {
        "records": n,
        "tcp": len(tcp_recs),
        "udp": len(udp_recs),
        "icmp": len(icmp_recs),
        "dns_events": len(dns_rows),
        "http_requests_parsed": sum(1 for r in tcp_recs if r.http_method is not None),
        "port_misuse_http_nonstandard": sum(1 for r in tcp_recs if r.http_nonstandard_port),
        "port_misuse_tls_unusual": sum(1 for r in tcp_recs if r.tls_unusual_port),
        "port_misuse_tls_on_plain": sum(1 for r in tcp_recs if r.tls_on_plain_http_port),
        "lateral_movement_findings": sum(1 for f in findings if f.category == "lateral_movement"),
        "arp_frames": sum(1 for r in records if r.proto == "arp"),
        "time_span_sec": None,
    }
    if ts_records:
        tmin = min(r.ts for r in ts_records if r.ts is not None)
        tmax = max(r.ts for r in ts_records if r.ts is not None)
        stats["time_span_sec"] = round(tmax - tmin, 3)

    # Sort: reconnaissance-style findings first, then severity, then code
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    cat_order = {
        "reconnaissance": 0,
        "brute_force": 1,
        "ddos_flood": 2,
        "suspicious_ip": 3,
        "unauthorized_access": 4,
        "dns_anomaly": 5,
        "data_exfil": 6,
        "protocol_anomaly": 7,
        "arp_spoofing": 8,
        "http_behavior": 9,
        "beaconing": 10,
        "traffic_pattern": 11,
        "port_misuse": 12,
        "lateral_movement": 13,
        "traffic_anomaly": 14,
        "info": 15,
        "general": 16,
    }
    findings.sort(key=lambda f: (cat_order.get(f.category, 3), sev_order.get(f.severity, 5), f.code))

    return TrafficReport(findings=findings, stats=stats, records_used=n)


def load_records_from_path(path: str) -> tuple[list[FlowRecord], dict, str | None]:
    """
    Load FlowRecords from a .pcap/.pcapng (Scapy) or text log (Zeek / iptables / generic).
    Returns (records, parse_meta, pcap_error).
    """
    from pathlib import Path

    from .log_parser import parse_network_log

    suf = Path(path).suffix.lower()
    if suf in (".pcap", ".pcapng"):
        flows, err = flows_from_pcap(path)
        return flows, {"kind": "pcap", "path": path}, err
    flows, meta = parse_network_log(path)
    return flows, meta, None


def format_tool_status() -> str:
    """Human-readable Scapy / capture capability."""
    lines = ["Network Traffic Analyzer — dependencies"]
    try:
        import scapy  # noqa: F401

        lines.append("  • scapy: OK")
    except ImportError:
        lines.append("  • scapy: MISSING (pip install scapy)")
    lines.append("  • Live capture: requires Npcap (Windows) or libpcap; run app as administrator if capture fails.")
    return "\n".join(lines)

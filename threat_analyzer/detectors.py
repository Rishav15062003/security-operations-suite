from __future__ import annotations

import ipaddress
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Sequence, Tuple

from .models import EventKind, Finding, ParsedEvent


def _is_private_ip(ip: str) -> bool:
    """True for RFC1918 / typical non-routable (not documentation TEST-NET, which is_private may include)."""
    try:
        addr = ipaddress.ip_address(ip.split("%")[0])
        if isinstance(addr, ipaddress.IPv4Address):
            return addr in ipaddress.ip_network("10.0.0.0/8") or addr in ipaddress.ip_network(
                "172.16.0.0/12"
            ) or addr in ipaddress.ip_network("192.168.0.0/16")
        return addr.is_private
    except ValueError:
        return False


def detect_brute_force(
    events: Sequence[ParsedEvent],
    *,
    fail_threshold: int = 5,
    window_minutes: int = 5,
    per_user_threshold: int = 8,
) -> List[Finding]:
    """Flag many failures from one IP in a short window, or many failures targeting one user."""
    findings: List[Finding] = []
    failures = [e for e in events if e.kind == EventKind.LOGIN_FAILURE and e.ip and e.ts]

    by_ip: Dict[str, List[ParsedEvent]] = defaultdict(list)
    by_user: Dict[str, List[ParsedEvent]] = defaultdict(list)
    for e in failures:
        by_ip[e.ip].append(e)
        if e.user:
            by_user[e.user].append(e)

    window = timedelta(minutes=window_minutes)

    for ip, evs in by_ip.items():
        evs_sorted = sorted(evs, key=lambda x: x.ts or datetime.min)
        for i, start_ev in enumerate(evs_sorted):
            if not start_ev.ts:
                continue
            end_t = start_ev.ts + window
            in_win = [x for x in evs_sorted[i:] if x.ts and x.ts <= end_t]
            if len(in_win) >= fail_threshold:
                sample = [x.raw[:120] for x in in_win[:5]]
                findings.append(
                    Finding(
                        category="brute_force",
                        severity="high" if len(in_win) >= fail_threshold * 2 else "medium",
                        title=f"Possible brute force from {ip}",
                        detail=f"{len(in_win)} failed attempts within {window_minutes} minutes (threshold {fail_threshold}).",
                        evidence=sample,
                    )
                )
                break

    for user, evs in by_user.items():
        if len(evs) < per_user_threshold:
            continue
        ips = {e.ip for e in evs if e.ip}
        if len(ips) >= 5:
            findings.append(
                Finding(
                    category="suspicious_ip",
                    severity="medium",
                    title=f"Same username '{user}' from many sources ({len(ips)} IPs)",
                    detail="Possible credential spray or horizontal scan across a subnet.",
                    evidence=[e.raw[:120] for e in evs[:5]],
                )
            )
        else:
            findings.append(
                Finding(
                    category="brute_force",
                    severity="medium",
                    title=f"Repeated failures targeting user '{user}'",
                    detail=f"{len(evs)} failures from {len(ips)} source(s).",
                    evidence=[e.raw[:120] for e in evs[:5]],
                )
            )

    return findings


def detect_unusual_login_times(
    events: Sequence[ParsedEvent],
    *,
    business_start: int = 8,
    business_end: int = 18,
    off_hours_severity: str = "low",
) -> List[Finding]:
    """Flag successful logins outside typical business hours (configurable)."""
    findings: List[Finding] = []
    successes = [
        e
        for e in events
        if e.kind == EventKind.LOGIN_SUCCESS and e.ts and e.user and e.ip
    ]
    for e in successes:
        h = e.ts.hour
        if h < business_start or h >= business_end:
            findings.append(
                Finding(
                    category="unusual_time",
                    severity=off_hours_severity,
                    title=f"Off-hours login: {e.user}",
                    detail=f"Success at {e.ts.strftime('%Y-%m-%d %H:%M')} (outside {business_start:02d}:00-{business_end:02d}:00). IP {e.ip}",
                    evidence=[e.raw[:120]],
                )
            )
    return findings


def _subnet24(ip: str) -> Optional[str]:
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
        if isinstance(a, ipaddress.IPv4Address):
            return ".".join(str(a).split(".")[:3]) + ".0/24"
    except ValueError:
        pass
    return None


def detect_suspicious_ip_patterns(
    events: Sequence[ParsedEvent],
    *,
    subnet_fail_threshold: int = 15,
    accounts_per_ip_threshold: int = 4,
) -> List[Finding]:
    """
    - Many failures across a /24 (scan/spray).
    - One IP logging into many distinct accounts (credential stuffing / pivot).
    - Successful login from private IP (context flag; often benign for internal jump hosts).
    """
    findings: List[Finding] = []
    failures = [e for e in events if e.kind == EventKind.LOGIN_FAILURE and e.ip]
    subnet_fails: Dict[str, int] = defaultdict(int)
    for e in failures:
        s = _subnet24(e.ip)
        if s:
            subnet_fails[s] += 1
    for subnet, n in subnet_fails.items():
        if n >= subnet_fail_threshold:
            findings.append(
                Finding(
                    category="suspicious_ip",
                    severity="medium",
                    title=f"High failure volume in subnet {subnet}",
                    detail=f"{n} failed attempts observed in this /24.",
                    evidence=[],
                )
            )

    success_by_ip: Dict[str, set] = defaultdict(set)
    for e in events:
        if e.kind == EventKind.LOGIN_SUCCESS and e.ip and e.user:
            success_by_ip[e.ip].add(e.user)
    for ip, users in success_by_ip.items():
        if len(users) >= accounts_per_ip_threshold:
            findings.append(
                Finding(
                    category="suspicious_ip",
                    severity="high",
                    title=f"One IP authenticating many accounts: {ip}",
                    detail=f"{len(users)} distinct users: {', '.join(sorted(users)[:10])}{'...' if len(users) > 10 else ''}",
                    evidence=[],
                )
            )

    private_success = [
        e
        for e in events
        if e.kind == EventKind.LOGIN_SUCCESS and e.ip and _is_private_ip(e.ip)
    ]
    if private_success:
        findings.append(
            Finding(
                category="suspicious_ip",
                severity="info",
                title="Successful logins from private / loopback ranges",
                detail=f"{len(private_success)} event(s); validate if external-facing services should see these sources.",
                evidence=[e.raw[:100] for e in private_success[:5]],
            )
        )

    return findings


def run_all_detectors(
    events: Sequence[ParsedEvent],
    **kwargs,
) -> Tuple[List[Finding], Dict[str, List[Finding]]]:
    """Run built-in rules; kwargs forwarded to :class:`engine.AnalysisConfig`."""
    from .engine import AnalysisConfig, run_analysis

    cfg = AnalysisConfig(
        fail_threshold=kwargs.get("fail_threshold", 5),
        window_minutes=kwargs.get("window_minutes", 5),
        per_user_threshold=kwargs.get("per_user_threshold", 8),
        business_start=kwargs.get("business_start", 8),
        business_end=kwargs.get("business_end", 18),
        off_hours_severity=kwargs.get("off_hours_severity", "low"),
        subnet_fail_threshold=kwargs.get("subnet_fail_threshold", 15),
        accounts_per_ip_threshold=kwargs.get("accounts_per_ip_threshold", 4),
        ml_contamination=kwargs.get("ml_contamination", 0.12),
        ml_enabled=kwargs.get("ml_enabled", True),
    )
    return run_analysis(events, cfg)

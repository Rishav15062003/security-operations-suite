from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta
from statistics import median
from typing import List, Sequence

from .models import EventKind, Finding, ParsedEvent


def detect_root_targeting(
    events: Sequence[ParsedEvent],
    *,
    threshold: int = 4,
) -> List[Finding]:
    """Repeated failed authentication attempts against the root account."""
    findings: List[Finding] = []
    root_fails = [
        e
        for e in events
        if e.kind == EventKind.LOGIN_FAILURE
        and e.target_is_root
        and e.ip
    ]
    by_ip: dict[str, list[ParsedEvent]] = defaultdict(list)
    for e in root_fails:
        by_ip[e.ip].append(e)
    for ip, evs in by_ip.items():
        if len(evs) >= threshold:
            findings.append(
                Finding(
                    category="privilege",
                    severity="high",
                    title=f"Repeated root login failures from {ip}",
                    detail=f"{len(evs)} failed attempts targeting root (possible privilege escalation probe).",
                    evidence=[x.raw[:120] for x in evs[:5]],
                )
            )
    return findings


def detect_user_enumeration(
    events: Sequence[ParsedEvent],
    *,
    invalid_per_ip: int = 6,
    invalid_total: int = 15,
) -> List[Finding]:
    """Invalid username attempts — common during SSH user enumeration."""
    findings: List[Finding] = []
    inv = [e for e in events if e.kind == EventKind.LOGIN_FAILURE and e.invalid_user and e.ip]
    by_ip: dict[str, list[ParsedEvent]] = defaultdict(list)
    for e in inv:
        by_ip[e.ip].append(e)
    hit_per_ip = False
    for ip, evs in by_ip.items():
        if len(evs) >= invalid_per_ip:
            hit_per_ip = True
            findings.append(
                Finding(
                    category="enumeration",
                    severity="medium",
                    title=f"User enumeration from {ip}",
                    detail=f"{len(evs)} 'invalid user' failures — attacker may be probing valid account names.",
                    evidence=[x.raw[:120] for x in evs[:5]],
                )
            )
    if not hit_per_ip and len(inv) >= invalid_total:
        findings.append(
            Finding(
                category="enumeration",
                severity="medium",
                title="High volume of invalid username attempts",
                detail=f"{len(inv)} events across the log — review sources and usernames.",
                evidence=[x.raw[:120] for x in inv[:5]],
            )
        )
    return findings


def detect_success_after_failures(
    events: Sequence[ParsedEvent],
    *,
    min_prior_fails: int = 3,
    window_minutes: int = 20,
) -> List[Finding]:
    """
    Successful login from a source after multiple failures — possible guessed or stuffed password.
    """
    findings: List[Finding] = []
    by_ip: dict[str, list[ParsedEvent]] = defaultdict(list)
    for e in events:
        if e.ip and e.ts and e.kind in (EventKind.LOGIN_SUCCESS, EventKind.LOGIN_FAILURE):
            by_ip[e.ip].append(e)

    window = timedelta(minutes=window_minutes)
    for ip, evs in by_ip.items():
        evs_sorted = sorted(evs, key=lambda x: x.ts or datetime.min)
        for ev in evs_sorted:
            if ev.kind != EventKind.LOGIN_SUCCESS or not ev.ts:
                continue
            start = ev.ts - window
            prior = [
                x
                for x in evs_sorted
                if x.kind == EventKind.LOGIN_FAILURE
                and x.ts
                and start <= x.ts < ev.ts
            ]
            if len(prior) >= min_prior_fails:
                findings.append(
                    Finding(
                        category="credential",
                        severity="high",
                        title=f"Login success after failures: {ev.user} from {ip}",
                        detail=f"{len(prior)} failures within {window_minutes} min before success — verify legitimacy.",
                        evidence=[ev.raw[:120], prior[-1].raw[:120]],
                    )
                )
                break
    return findings


def detect_privilege_auth_failures(
    events: Sequence[ParsedEvent],
    *,
    threshold: int = 5,
) -> List[Finding]:
    """Many sudo/su authentication failures — possible privilege escalation attempts."""
    findings: List[Finding] = []
    sudo_fails = [
        e
        for e in events
        if e.kind == EventKind.LOGIN_FAILURE and e.service in ("sudo", "su")
    ]
    if len(sudo_fails) >= threshold:
        by_svc = Counter(e.service or "unknown" for e in sudo_fails)
        detail = ", ".join(f"{k}: {v}" for k, v in by_svc.items())
        findings.append(
            Finding(
                category="privilege",
                severity="medium",
                title="Elevated privilege authentication failures",
                detail=f"{len(sudo_fails)} sudo/su failures ({detail}).",
                evidence=[x.raw[:120] for x in sudo_fails[:5]],
            )
        )
    return findings


def detect_global_failure_spike(
    events: Sequence[ParsedEvent],
    *,
    multiplier: float = 2.5,
    min_events: int = 20,
) -> List[Finding]:
    """Hour with far more auth failures than typical — coordinated attack or misconfiguration."""
    findings: List[Finding] = []
    fails = [e for e in events if e.kind == EventKind.LOGIN_FAILURE and e.ts]
    if len(fails) < min_events:
        return findings
    by_hour: dict[int, int] = Counter()
    for e in fails:
        by_hour[e.ts.hour] += 1
    counts = list(by_hour.values())
    med = float(median(counts)) if counts else 0.0
    if med < 1.0:
        med = 1.0
    for hour, n in sorted(by_hour.items()):
        if n >= med * multiplier and n >= 10:
            findings.append(
                Finding(
                    category="volume",
                    severity="medium",
                    title=f"Failure spike in hour {hour:02d}:00",
                    detail=f"{n} failures vs ~{med:.1f} median per active hour — investigate sources.",
                    evidence=[],
                )
            )
            break
    return findings


def detect_burst_failures(
    events: Sequence[ParsedEvent],
    *,
    window_seconds: int = 60,
    threshold: int = 15,
) -> List[Finding]:
    """Very dense burst of failures — password spray or automated tooling."""
    findings: List[Finding] = []
    fails = [e for e in events if e.kind == EventKind.LOGIN_FAILURE and e.ts]
    fails_sorted = sorted(fails, key=lambda x: x.ts or datetime.min)
    win = timedelta(seconds=window_seconds)
    for i, start_ev in enumerate(fails_sorted):
        if not start_ev.ts:
            continue
        end_t = start_ev.ts + win
        burst = [x for x in fails_sorted[i:] if x.ts and x.ts <= end_t]
        if len(burst) >= threshold:
            findings.append(
                Finding(
                    category="volume",
                    severity="high",
                    title="Extremely dense authentication failure burst",
                    detail=f"{len(burst)} failures within {window_seconds}s — likely automated attack.",
                    evidence=[x.raw[:100] for x in burst[:5]],
                )
            )
            break
    return findings


def detect_lockout_events(
    events: Sequence[ParsedEvent],
    *,
    threshold: int = 3,
) -> List[Finding]:
    """Account lockout / tally lock events — often follows brute force."""
    findings: List[Finding] = []
    locks = [e for e in events if e.kind == EventKind.ACCOUNT_LOCKOUT]
    if len(locks) >= threshold:
        users = {e.user for e in locks if e.user}
        findings.append(
            Finding(
                category="account_abuse",
                severity="high",
                title="Multiple account lockout events",
                detail=f"{len(locks)} lockout-related lines for user(s): {', '.join(sorted(users)[:8]) or 'unknown'}",
                evidence=[x.raw[:120] for x in locks[:5]],
            )
        )
    elif len(locks) >= 1:
        findings.append(
            Finding(
                category="account_abuse",
                severity="low",
                title="Account lockout observed",
                detail=f"{len(locks)} event(s) — correlate with authentication failures.",
                evidence=[x.raw[:120] for x in locks[:3]],
            )
        )
    return findings


def detect_password_changes(
    events: Sequence[ParsedEvent],
    *,
    window_minutes: int = 30,
    threshold: int = 3,
) -> List[Finding]:
    """Several password changes in a short window — possible takeover or bulk admin action."""
    findings: List[Finding] = []
    pcs_sorted = sorted(
        [e for e in events if e.kind == EventKind.PASSWORD_CHANGE and e.ts],
        key=lambda x: x.ts or datetime.min,
    )
    if not pcs_sorted:
        return findings
    if len(pcs_sorted) >= threshold:
        win = timedelta(minutes=window_minutes)
        for i, start in enumerate(pcs_sorted):
            if not start.ts:
                continue
            in_win = [x for x in pcs_sorted[i:] if x.ts and x.ts <= start.ts + win]
            if len(in_win) >= threshold:
                findings.append(
                    Finding(
                        category="account_change",
                        severity="medium",
                        title="Clustered password changes",
                        detail=f"{len(in_win)} changes within {window_minutes} minutes — verify authorized maintenance.",
                        evidence=[x.raw[:120] for x in in_win[:5]],
                    )
                )
                return findings
    findings.append(
        Finding(
            category="account_change",
            severity="info",
            title="Password change events in log",
            detail=f"{len(pcs_sorted)} password change(s) recorded — review change tickets.",
            evidence=[x.raw[:120] for x in pcs_sorted[:5]],
        )
    )
    return findings


def detect_network_probes(
    events: Sequence[ParsedEvent],
    *,
    per_ip: int = 8,
) -> List[Finding]:
    """SSH banner / protocol probes (reconnaissance)."""
    findings: List[Finding] = []
    probes = [e for e in events if e.kind == EventKind.NETWORK_PROBE and e.ip]
    by_ip: dict[str, list[ParsedEvent]] = defaultdict(list)
    for e in probes:
        by_ip[e.ip].append(e)
    for ip, evs in by_ip.items():
        if len(evs) >= per_ip:
            findings.append(
                Finding(
                    category="reconnaissance",
                    severity="low",
                    title=f"Repeated SSH banner/protocol probes from {ip}",
                    detail=f"{len(evs)} events — often scanners or misconfigured clients.",
                    evidence=[x.raw[:120] for x in evs[:5]],
                )
            )
    return findings


def detect_repeated_disconnects(
    events: Sequence[ParsedEvent],
    *,
    threshold: int = 25,
) -> List[Finding]:
    """Many connection closures without auth — noise or reconnaissance."""
    findings: List[Finding] = []
    disc = [e for e in events if e.kind == EventKind.CONNECTION_CLOSED]
    if len(disc) >= threshold:
        findings.append(
            Finding(
                category="reconnaissance",
                severity="info",
                title="High volume of connection closures",
                detail=f"{len(disc)} disconnect/close events — may indicate scanning or network noise.",
                evidence=[x.raw[:100] for x in disc[:5]],
            )
        )
    return findings

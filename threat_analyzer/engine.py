from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Set

from .detectors import (
    detect_brute_force,
    detect_suspicious_ip_patterns,
    detect_unusual_login_times,
)
from .detectors_wireshark import detect_wireshark_patterns
from .detectors_advanced import (
    detect_burst_failures,
    detect_global_failure_spike,
    detect_lockout_events,
    detect_network_probes,
    detect_password_changes,
    detect_privilege_auth_failures,
    detect_repeated_disconnects,
    detect_root_targeting,
    detect_success_after_failures,
    detect_user_enumeration,
)
from .ml_anomaly import detect_anomalies_ml
from .models import Finding, ParsedEvent
from .registry import DETECTOR_INFOS, EXTENSION_DETECTOR_INFOS, EXTENSION_RUNNERS, DetectorInfo


@dataclass
class AnalysisConfig:
    """Parameters for rule engine and ML."""

    year: int = 2026
    fail_threshold: int = 5
    window_minutes: int = 5
    per_user_threshold: int = 8
    business_start: int = 8
    business_end: int = 18
    off_hours_severity: str = "low"
    subnet_fail_threshold: int = 15
    accounts_per_ip_threshold: int = 4
    ml_contamination: float = 0.12
    ml_enabled: bool = True
    # None or empty set = run all built-in detectors
    enabled_detector_ids: Optional[Set[str]] = None


def _all_infos() -> List[DetectorInfo]:
    return list(DETECTOR_INFOS) + list(EXTENSION_DETECTOR_INFOS)


def _should_run(spec_id: str, config: AnalysisConfig) -> bool:
    en = config.enabled_detector_ids
    if en is None:
        return True
    return spec_id in en


def run_analysis(
    events: Sequence[ParsedEvent],
    config: AnalysisConfig,
) -> tuple[List[Finding], Dict[str, List[Finding]]]:
    """Run selected detectors and optional ML; group findings by category."""
    findings: List[Finding] = []

    def add_from(spec_id: str, fn) -> None:
        if _should_run(spec_id, config):
            findings.extend(fn())

    add_from(
        "brute_force",
        lambda: detect_brute_force(
            events,
            fail_threshold=config.fail_threshold,
            window_minutes=config.window_minutes,
            per_user_threshold=config.per_user_threshold,
        ),
    )
    add_from(
        "unusual_time",
        lambda: detect_unusual_login_times(
            events,
            business_start=config.business_start,
            business_end=config.business_end,
            off_hours_severity=config.off_hours_severity,
        ),
    )
    add_from(
        "suspicious_ip",
        lambda: detect_suspicious_ip_patterns(
            events,
            subnet_fail_threshold=config.subnet_fail_threshold,
            accounts_per_ip_threshold=config.accounts_per_ip_threshold,
        ),
    )
    add_from("root_targeting", lambda: detect_root_targeting(events))
    add_from("enumeration", lambda: detect_user_enumeration(events))
    add_from("credential_success", lambda: detect_success_after_failures(events))
    add_from("privilege_escalation", lambda: detect_privilege_auth_failures(events))
    add_from("volume_spike", lambda: detect_global_failure_spike(events))
    add_from("burst", lambda: detect_burst_failures(events))
    add_from("lockout", lambda: detect_lockout_events(events))
    add_from("password_change", lambda: detect_password_changes(events))
    add_from("reconnaissance", lambda: detect_network_probes(events))
    add_from("disconnect_noise", lambda: detect_repeated_disconnects(events))
    add_from("wireshark_patterns", lambda: detect_wireshark_patterns(events))

    for info in EXTENSION_DETECTOR_INFOS:
        fn = EXTENSION_RUNNERS.get(info.id)
        if fn is not None and _should_run(info.id, config):
            findings.extend(fn(events))

    if config.ml_enabled and _should_run("ml_anomaly", config):
        findings.extend(detect_anomalies_ml(events, contamination=config.ml_contamination))

    grouped: Dict[str, List[Finding]] = {}
    for f in findings:
        grouped.setdefault(f.category, []).append(f)
    return findings, grouped


def list_detector_metadata() -> List[DetectorInfo]:
    """UI / CLI: show available detectors."""
    return _all_infos()

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, Dict, List, Optional, Sequence

if TYPE_CHECKING:
    from .models import Finding, ParsedEvent

EXTENSION_DETECTOR_INFOS: List["DetectorInfo"] = []
EXTENSION_RUNNERS: Dict[str, Callable[[Sequence["ParsedEvent"]], List["Finding"]]] = {}


@dataclass(frozen=True, slots=True)
class DetectorInfo:
    """Metadata for a detection module (shown in UI; engine maps id → logic)."""

    id: str
    name: str
    description: str
    default_enabled: bool = True


DETECTOR_INFOS: List[DetectorInfo] = [
    DetectorInfo(
        "brute_force",
        "Brute force & password spray",
        "Many failed logins from one IP in a short window; repeated failures for one username from few sources.",
    ),
    DetectorInfo(
        "unusual_time",
        "Unusual login times",
        "Successful sessions outside configured business hours.",
    ),
    DetectorInfo(
        "suspicious_ip",
        "Suspicious IP patterns",
        "Subnet-wide failure spikes, one IP opening many accounts, RFC1918 success sources.",
    ),
    DetectorInfo(
        "root_targeting",
        "Root account targeting",
        "Failed authentication attempts specifically against root.",
    ),
    DetectorInfo(
        "enumeration",
        "User enumeration",
        "Invalid username probes (common SSH scanning pattern).",
    ),
    DetectorInfo(
        "credential_success",
        "Success after failures",
        "Login success shortly after multiple failures from the same source (guessed or stuffed credentials).",
    ),
    DetectorInfo(
        "privilege_escalation",
        "Sudo / su failures",
        "Repeated elevated-privilege authentication failures.",
    ),
    DetectorInfo(
        "volume_spike",
        "Hourly failure spike",
        "One hour with far more failures than the baseline for the file.",
    ),
    DetectorInfo(
        "burst",
        "Ultra-tight failure burst",
        "Many failures within one minute — typical of automation.",
    ),
    DetectorInfo(
        "lockout",
        "Account lockout",
        "pam_tally / faillock / lockout messages.",
    ),
    DetectorInfo(
        "password_change",
        "Password changes",
        "passwd events; clustered changes may warrant review.",
    ),
    DetectorInfo(
        "reconnaissance",
        "SSH reconnaissance",
        "Banner / protocol probes (e.g. no SSH identification string).",
    ),
    DetectorInfo(
        "disconnect_noise",
        "Connection churn",
        "High volume of connection closes without full auth.",
    ),
    DetectorInfo(
        "ml_anomaly",
        "ML behavioral outliers",
        "Isolation Forest on per-IP feature vectors (optional; requires scikit-learn).",
    ),
    DetectorInfo(
        "wireshark_patterns",
        "Packet capture heuristics",
        "Wireshark/tshark exports: dominant source, many destinations per source, TLS alert strings in Info.",
    ),
]


def register_extension(
    info: DetectorInfo,
    run: Optional[Callable[[Sequence["ParsedEvent"]], List["Finding"]]] = None,
) -> None:
    """
    Register a custom detector for the UI. Pass ``run(events)`` to plug in logic
    without editing ``engine.run_analysis``.
    """
    EXTENSION_DETECTOR_INFOS.append(info)
    if run is not None:
        EXTENSION_RUNNERS[info.id] = run

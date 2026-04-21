from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class EventKind(str, Enum):
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    PASSWORD_CHANGE = "password_change"
    ACCOUNT_LOCKOUT = "account_lockout"
    NETWORK_PROBE = "network_probe"
    CONNECTION_CLOSED = "connection_closed"
    PACKET_RECORD = "packet_record"  # Wireshark / tshark export row
    UNKNOWN = "unknown"


@dataclass
class ParsedEvent:
    """One parsed line from an auth-style log."""

    raw: str
    line_no: int
    ts: Optional[datetime]
    kind: EventKind
    user: Optional[str]
    ip: Optional[str]
    service: Optional[str] = None
    invalid_user: bool = False
    target_is_root: bool = False
    # Wireshark / PCAP text exports (optional)
    dst_ip: Optional[str] = None
    protocol: Optional[str] = None
    info_snippet: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    """A security-relevant observation."""

    category: str
    severity: str  # info, low, medium, high, critical
    title: str
    detail: str
    evidence: list[str] = field(default_factory=list)

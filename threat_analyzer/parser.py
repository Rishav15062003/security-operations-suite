from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Optional

from dateutil import parser as date_parser

from .models import EventKind, ParsedEvent
from .wireshark_parser import is_wireshark_csv_header_line, try_parse_wireshark_line

# SSH / PAM style (Linux auth.log, common distros)
_RE_FAILED = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+|[\da-fA-F:]+) "
    r"port \d+",
    re.I,
)
_RE_ACCEPTED = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+|[\da-fA-F:]+) "
    r"port \d+",
    re.I,
)
_RE_AUTH_FAIL = re.compile(
    r"authentication failure.*rhost=(?P<ip>[\d.]+|[\da-fA-F:]+).*user=(?P<user>\S+)",
    re.I,
)
_RE_AUTH_FAIL_ALT = re.compile(
    r"authentication failure.*user=(?P<user>\S+).*rhost=(?P<ip>[\d.]+|[\da-fA-F:]+)",
    re.I,
)
_RE_PASSWORD_CHANGED = re.compile(r"password changed for (?P<user>\S+)", re.I)
_RE_LOCKOUT = re.compile(
    r"(?:pam_tally|faillock|pam_faillock).*(?:locked|LOCKED)|account locked|User account locked",
    re.I,
)
_RE_LOCK_USER = re.compile(
    r"(?:user=|user )(?P<user>\S+)",
    re.I,
)
_RE_SSH_PROBE = re.compile(
    r"Didn't receive identification from (?P<ip>[\d.]+|[\da-fA-F:]+)",
    re.I,
)
_RE_CONN_CLOSED = re.compile(
    r"Connection closed by (?P<ip>[\d.]+|[\da-fA-F:]+) port",
    re.I,
)
_RE_SUDO_FAIL = re.compile(
    r"sudo:.*(?:authentication failure|incorrect password attempts)",
    re.I,
)
_RE_SU_FAIL = re.compile(
    r"su(?:\[\d+\])?:.*(?:authentication failure|FAILED)",
    re.I,
)
# Generic: "user X from IP" with success/fail keywords
_RE_GENERIC_FAIL = re.compile(
    r"(?P<fail>fail|denied|invalid).{0,80}?(?P<user>\w+).{0,40}?(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
    re.I,
)
_RE_GENERIC_OK = re.compile(
    r"(?P<ok>success|accepted|granted).{0,80}?(?P<user>\w+).{0,40}?(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
    re.I,
)

_TS_PREFIX = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"
)


def _parse_ts(line: str, default_year: int) -> Optional[datetime]:
    m = _TS_PREFIX.match(line.strip())
    if not m:
        return None
    raw = m.group("ts")
    try:
        if raw[0].isdigit() and len(raw) >= 10:
            return date_parser.parse(raw, fuzzy=False)
        return date_parser.parse(f"{default_year} {raw}", fuzzy=False)
    except (ValueError, TypeError):
        try:
            return date_parser.parse(raw, fuzzy=False)
        except (ValueError, TypeError):
            return None


def _extract_user_loose(line: str) -> Optional[str]:
    for pat in (
        r"user=(?P<u>\S+)",
        r"for (?P<u>\S+)(?:\s+from|\s+on)",
        r"sudo:\s+(?P<u>\S+)\s*:",
    ):
        m = re.search(pat, line, re.I)
        if m:
            return m.group("u")
    return None


def parse_line(line: str, line_no: int, default_year: int = 2026) -> ParsedEvent:
    raw = line.rstrip("\n\r")
    ws = try_parse_wireshark_line(raw, line_no, default_year=default_year)
    if ws is not None:
        return ws

    ts = _parse_ts(raw, default_year)
    lower = raw.lower()

    m = _RE_PASSWORD_CHANGED.search(raw)
    if m:
        return ParsedEvent(
            raw=raw,
            line_no=line_no,
            ts=ts,
            kind=EventKind.PASSWORD_CHANGE,
            user=m.group("user"),
            ip=None,
            service="passwd",
        )

    if _RE_LOCKOUT.search(raw):
        um = _RE_LOCK_USER.search(raw)
        user = um.group("user") if um else _extract_user_loose(raw)
        return ParsedEvent(
            raw=raw,
            line_no=line_no,
            ts=ts,
            kind=EventKind.ACCOUNT_LOCKOUT,
            user=user,
            ip=None,
            service="pam",
        )

    m = _RE_SSH_PROBE.search(raw)
    if m:
        return ParsedEvent(
            raw=raw,
            line_no=line_no,
            ts=ts,
            kind=EventKind.NETWORK_PROBE,
            user=None,
            ip=m.group("ip"),
            service="sshd",
        )

    m = _RE_CONN_CLOSED.search(raw)
    if m:
        return ParsedEvent(
            raw=raw,
            line_no=line_no,
            ts=ts,
            kind=EventKind.CONNECTION_CLOSED,
            user=None,
            ip=m.group("ip"),
            service="sshd",
        )

    m = _RE_FAILED.search(raw)
    if m:
        user = m.group("user")
        inv = "invalid user" in lower
        tr = (not inv) and user.lower() == "root"
        return ParsedEvent(
            raw=raw,
            line_no=line_no,
            ts=ts,
            kind=EventKind.LOGIN_FAILURE,
            user=user,
            ip=m.group("ip"),
            service="sshd",
            invalid_user=inv,
            target_is_root=tr,
        )

    m = _RE_ACCEPTED.search(raw)
    if m:
        return ParsedEvent(
            raw=raw,
            line_no=line_no,
            ts=ts,
            kind=EventKind.LOGIN_SUCCESS,
            user=m.group("user"),
            ip=m.group("ip"),
            service="sshd",
        )

    if _RE_SUDO_FAIL.search(raw):
        user = _extract_user_loose(raw)
        return ParsedEvent(
            raw=raw,
            line_no=line_no,
            ts=ts,
            kind=EventKind.LOGIN_FAILURE,
            user=user,
            ip=None,
            service="sudo",
        )

    if _RE_SU_FAIL.search(raw):
        user = _extract_user_loose(raw)
        return ParsedEvent(
            raw=raw,
            line_no=line_no,
            ts=ts,
            kind=EventKind.LOGIN_FAILURE,
            user=user,
            ip=None,
            service="su",
        )

    for pattern in (_RE_AUTH_FAIL, _RE_AUTH_FAIL_ALT):
        m = pattern.search(raw)
        if m:
            user = m.group("user")
            return ParsedEvent(
                raw=raw,
                line_no=line_no,
                ts=ts,
                kind=EventKind.LOGIN_FAILURE,
                user=user,
                ip=m.group("ip"),
                service="pam",
                target_is_root=(user or "").lower() == "root",
            )

    if "fail" in lower or "denied" in lower or "invalid" in lower:
        m = _RE_GENERIC_FAIL.search(raw)
        if m:
            return ParsedEvent(
                raw=raw,
                line_no=line_no,
                ts=ts,
                kind=EventKind.LOGIN_FAILURE,
                user=m.group("user"),
                ip=m.group("ip"),
            )

    if "success" in lower or "accepted" in lower or "granted" in lower:
        m = _RE_GENERIC_OK.search(raw)
        if m:
            return ParsedEvent(
                raw=raw,
                line_no=line_no,
                ts=ts,
                kind=EventKind.LOGIN_SUCCESS,
                user=m.group("user"),
                ip=m.group("ip"),
            )

    return ParsedEvent(
        raw=raw,
        line_no=line_no,
        ts=ts,
        kind=EventKind.UNKNOWN,
        user=None,
        ip=None,
    )


def parse_file(
    path: str,
    default_year: int = 2026,
    encoding: str = "utf-8",
    *,
    max_pcap_packets: int | None = None,
) -> List[ParsedEvent]:
    suffix = Path(path).suffix.lower()
    if suffix in (".pcapng", ".pcap"):
        from .pcap_io import DEFAULT_MAX_PCAP_PACKETS, parse_pcap_file

        cap = max_pcap_packets
        if cap is None:
            cap = DEFAULT_MAX_PCAP_PACKETS
        if cap == 0:
            cap = None
        return parse_pcap_file(path, max_packets=cap)

    events: List[ParsedEvent] = []
    with open(path, encoding=encoding, errors="replace") as f:
        lines = f.readlines()
    start = 0
    if lines and is_wireshark_csv_header_line(lines[0]):
        start = 1
    for i, line in enumerate(lines[start:], start=start + 1):
        events.append(parse_line(line, i, default_year=default_year))
    return events


def iter_parse_lines(lines: Iterable[str], default_year: int = 2026) -> List[ParsedEvent]:
    return [parse_line(line, i, default_year=default_year) for i, line in enumerate(lines, start=1)]

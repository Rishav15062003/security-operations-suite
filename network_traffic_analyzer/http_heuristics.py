"""
HTTP request parsing and User-Agent heuristics (cleartext HTTP in TCP payloads only).
"""
from __future__ import annotations

import re
from typing import Final

# Common cleartext HTTP ports (HTTPS/TLS on 443 is not parsed here).
HTTP_PARSE_PORTS: Final[frozenset[int]] = frozenset(
    {
        80,
        81,
        8080,
        8000,
        8888,
        3000,
        3128,
        8008,
        8081,
        9000,
        9090,
    }
)

# Typical TLS service ports (HTTPS and common alternates) — ClientHello here is usually expected.
HTTPS_TLS_PORTS: Final[frozenset[int]] = frozenset(
    {
        443,
        8443,
        9443,
        10443,
        4443,
        4433,
        8444,
        5443,
        6443,
        7443,
        5553,
        8883,
        9444,
    }
)

# Substrings typical of automated scanners, CLI tools, and bots (case-insensitive).
AUTOMATED_UA_SUBSTRINGS: Final[tuple[str, ...]] = (
    "curl/",
    "wget/",
    "wget ",
    "python-requests",
    "aiohttp/",
    "httpx/",
    "go-http-client",
    "java/",
    "okhttp",
    "masscan",
    "nmap",
    "nikto",
    "sqlmap",
    "zgrab",
    "zmap",
    "dirbuster",
    "gobuster",
    "ffuf",
    "feroxbuster",
    "nuclei",
    "openvas",
    "nessus",
    "qualys",
    "burp suite",
    "burp collaborator",
    "owasp zap",
    "w3af",
    "havij",
    "whatweb",
    "httpie/",
    "libwww-perl",
    "lwp-trivial",
    "axios/",
    "rest-client",
    "scrapy",
    "mechanize",
    "phantomjs",
    "headlesschrome",
    "selenium",
    "petals",
    "vulnerability scanner",
    "acunetix",
    "appscan",
)

_RE_REQ_LINE = re.compile(
    r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|CONNECT|TRACE|PATCH)\s+\S+\s+HTTP/",
    re.I,
)


def looks_like_tls_client_hello(raw: bytes) -> bool:
    """TLS record Handshake (0x16), version 3.x — start of a typical ClientHello."""
    if len(raw) < 5:
        return False
    return raw[0] == 0x16 and raw[1] == 0x03 and raw[2] in (0x00, 0x01, 0x02, 0x03, 0x04)


def parse_http_request_user_agent(payload: bytes) -> tuple[str | None, str | None]:
    """
    If payload looks like an HTTP/1.x request, return (method, user_agent).

    user_agent is None only when the payload is not recognized as HTTP.
    For HTTP without a User-Agent header before the body, user_agent is "".
    """
    if not payload or len(payload) < 10:
        return None, None
    try:
        chunk = payload[:32768]
        text = chunk.decode("utf-8", errors="replace")
    except Exception:
        return None, None
    if "\r\n\r\n" in text:
        head, _ = text.split("\r\n\r\n", 1)
    elif "\n\n" in text:
        head, _ = text.split("\n\n", 1)
    else:
        head = text
    lines = head.splitlines()
    if not lines:
        return None, None
    if not _RE_REQ_LINE.match(lines[0].strip()):
        return None, None
    method = lines[0].strip().split(None, 1)[0].upper()
    ua_val: str | None = None
    for line in lines[1:]:
        if not line.strip():
            break
        m = re.match(r"^User-Agent:\s*(.*)$", line, re.I)
        if m:
            ua_val = m.group(1).strip()
            break
    if ua_val is None:
        return method, ""
    return method, ua_val


def is_automated_user_agent(ua: str) -> bool:
    """Likely bot, scanner, or scripted client (not exhaustive)."""
    if not ua or not ua.strip():
        return False
    low = ua.lower()
    return any(s in low for s in AUTOMATED_UA_SUBSTRINGS)


def is_weird_user_agent(ua: str) -> bool:
    """Suspicious but non-empty UA (too short, placeholder, non-printable)."""
    if not ua:
        return False
    s = ua.strip()
    if len(s) <= 1:
        return True
    if s in ("-", "?", "n/a", "na", "none", "null", "unknown", "xxx"):
        return True
    if len(s) < 4 and not any(c.isalpha() for c in s):
        return True
    if sum(1 for c in s if c.isprintable() and not c.isspace()) < max(1, len(s) // 2):
        return True
    return False

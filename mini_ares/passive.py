"""Passive subdomain discovery via crt.sh certificate transparency logs."""
from __future__ import annotations

from typing import Set
from urllib.parse import quote

import httpx


def crt_sh_subdomains(domain: str, timeout: float = 45.0) -> Set[str]:
    """Return unique hostnames seen in CT logs for *.domain."""
    found: Set[str] = set()
    q = f"%.{domain.strip().lower().rstrip('.')}"
    url = f"https://crt.sh/?q={quote(q)}&output=json"
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            r = client.get(url)
            r.raise_for_status()
            data = r.json()
    except Exception:
        return found
    if not isinstance(data, list):
        return found
    for row in data:
        if not isinstance(row, dict):
            continue
        name = row.get("name_value") or row.get("common_name")
        if not name:
            continue
        for part in str(name).split("\n"):
            h = part.strip().lower().rstrip(".")
            if h.endswith(domain.lower()) and "*" not in h:
                found.add(h)
    return found

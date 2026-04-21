"""Optional subfinder CLI integration."""
from __future__ import annotations

import subprocess
from typing import Set

from .tool_paths import resolve_subfinder_executable


def subfinder_subdomains(domain: str, timeout: int = 180) -> Set[str]:
    """Run subfinder if installed; return empty set otherwise."""
    exe = resolve_subfinder_executable()
    if not exe:
        return set()
    try:
        p = subprocess.run(
            [exe, "-d", domain, "-silent"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return set()
    out: Set[str] = set()
    for line in (p.stdout or "").splitlines():
        h = line.strip().lower().rstrip(".")
        if h:
            out.add(h)
    return out

"""Optional deps for phishing module (httpx) + VirusTotal API key hint."""
from __future__ import annotations

import os
import platform
import subprocess
import sys


def format_phishing_tool_status() -> str:
    lines = [
        f"Platform: {platform.system()} ({platform.machine()})",
        "  httpx:       "
        + ("found (HTTP redirects + VirusTotal)" if _has_httpx() else "NOT FOUND — use Install or: pip install httpx"),
        "  certifi:     " + ("found" if _has_certifi() else "optional (TLS bundle)"),
        "  EML parsing: stdlib email (no install)",
        "  VirusTotal:  set VT_API_KEY or paste key in UI (https://www.virustotal.com/gui/my-apikey)",
    ]
    key = (os.environ.get("VT_API_KEY") or "").strip()
    lines.append(f"  VT env key:  {'set' if key else 'not set'}")
    return "\n".join(lines)


def _has_httpx() -> bool:
    try:
        import httpx  # noqa: F401

        return True
    except ImportError:
        return False


def _has_certifi() -> bool:
    try:
        import certifi  # noqa: F401

        return True
    except ImportError:
        return False


def run_phishing_auto_install() -> str:
    """Best-effort pip install for phishing module network stack."""
    log: list[str] = ["=== Phishing module install ===\n"]
    try:
        cmd = [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--upgrade",
            "httpx",
            "certifi",
        ]
        log.append("$ " + " ".join(cmd))
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if p.stdout:
            log.append(p.stdout[-3000:])
        if p.stderr:
            log.append("stderr: " + p.stderr[-2000:])
        log.append(f"  exit code: {p.returncode}")
    except Exception as e:
        log.append(f"{type(e).__name__}: {e}")
    log.append("\n" + format_phishing_tool_status())
    return "\n".join(log)

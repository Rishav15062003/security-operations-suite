"""VirusTotal API v3 lookups (URL reports + file hash reports). Requires VT_API_KEY."""
from __future__ import annotations

import base64
import time
from typing import Any

import httpx

VT_API = "https://www.virustotal.com/api/v3"


def _url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode("utf-8", errors="replace")).decode("ascii").strip("=")


def _stats_summary(data: dict[str, Any]) -> str:
    attr = data.get("data", {}).get("attributes", {})
    stats = attr.get("last_analysis_stats") or {}
    mal = stats.get("malicious", 0)
    sus = stats.get("suspicious", 0)
    und = stats.get("undetected", 0)
    harm = stats.get("harmless", 0)
    tot = mal + sus + und + harm + stats.get("timeout", 0) + stats.get("confirmed-timeout", 0) + stats.get("failure", 0)
    rep = attr.get("reputation")
    last = attr.get("last_analysis_date")
    parts = [f"malicious={mal}", f"suspicious={sus}", f"undetected={und}", f"harmless={harm}"]
    if tot:
        parts.append(f"engines_sampled≈{tot}")
    if rep is not None:
        parts.append(f"reputation={rep}")
    if last:
        parts.append(f"last_analysis_date={last}")
    return "; ".join(parts)


def lookup_url(client: httpx.Client, url: str, api_key: str) -> tuple[dict | None, str]:
    """Returns (signal_dict_components, log line)."""
    uid = _url_id(url)
    headers = {"x-apikey": api_key}
    r = client.get(f"{VT_API}/urls/{uid}", headers=headers, timeout=30.0)
    if r.status_code == 200:
        js = r.json()
        line = f"URL {url[:120]}… → {_stats_summary(js)}"
        attr = js.get("data", {}).get("attributes", {})
        stats = attr.get("last_analysis_stats") or {}
        mal = int(stats.get("malicious", 0) or 0)
        sus = int(stats.get("suspicious", 0) or 0)
        sev = "info"
        w = 4
        if mal >= 5:
            sev = "critical"
            w = 28
        elif mal >= 1:
            sev = "high"
            w = 18
        elif sus >= 3:
            sev = "medium"
            w = 12
        title = f"VirusTotal URL: {mal} malicious / {sus} suspicious"
        detail = _stats_summary(js)
        return (
            {"code": "vt_url", "severity": sev, "title": title, "detail": detail[:500], "weight": w},
            line,
        )
    if r.status_code == 404:
        # submit for analysis
        r2 = client.post(f"{VT_API}/urls", data={"url": url}, headers=headers, timeout=30.0)
        if r2.status_code in (200, 202):
            line = f"URL {url[:80]}… submitted to VT (not yet in database); poll later."
            return (
                {
                    "code": "vt_url_queued",
                    "severity": "info",
                    "title": "VirusTotal: URL submitted (pending analysis)",
                    "detail": r2.text[:400],
                    "weight": 2,
                },
                line,
            )
        return (
            None,
            f"VT URL 404 + submit failed: {r2.status_code} {r2.text[:200]}",
        )
    if r.status_code == 429:
        return (None, "VT rate limit (429) — wait and retry.")
    return (None, f"VT URL error {r.status_code}: {r.text[:200]}")


def lookup_file_hash(client: httpx.Client, sha256_hex: str, api_key: str, filename: str) -> tuple[dict | None, str]:
    headers = {"x-apikey": api_key}
    r = client.get(f"{VT_API}/files/{sha256_hex}", headers=headers, timeout=30.0)
    if r.status_code == 200:
        js = r.json()
        line = f"File {filename[:60]} ({sha256_hex[:16]}…) → {_stats_summary(js)}"
        stats = js.get("data", {}).get("attributes", {}).get("last_analysis_stats") or {}
        mal = int(stats.get("malicious", 0) or 0)
        sus = int(stats.get("suspicious", 0) or 0)
        sev = "info"
        w = 4
        if mal >= 3:
            sev = "critical"
            w = 26
        elif mal >= 1:
            sev = "high"
            w = 16
        elif sus >= 2:
            sev = "medium"
            w = 10
        title = f"VirusTotal file {filename[:40]}: {mal} malicious / {sus} suspicious"
        detail = _stats_summary(js)
        return (
            {"code": "vt_file", "severity": sev, "title": title, "detail": detail[:500], "weight": w},
            line,
        )
    if r.status_code == 404:
        return (
            None,
            f"File hash not in VT: {filename} ({sha256_hex[:16]}…)",
        )
    if r.status_code == 429:
        return (None, "VT rate limit (429)")
    return (None, f"VT file error {r.status_code}: {r.text[:200]}")


def run_vt_batch(
    urls: list[str],
    attachments: list[tuple[str, str]],
    api_key: str,
    *,
    max_urls: int = 4,
    max_files: int = 6,
    delay_sec: float = 1.0,
) -> tuple[list[dict], str]:
    """
    attachments: list of (filename, sha256_hex)
    Returns (list of signal dicts, log text).
    """
    lines: list[str] = []
    sigs: list[dict] = []
    if not api_key.strip():
        return [], "VirusTotal: no API key (set VT_API_KEY or paste in UI)."
    if not urls and not attachments:
        return [], "VirusTotal: no URLs or attachment hashes to query (load .eml or paste links)."

    with httpx.Client() as client:
        for u in urls[:max_urls]:
            sig, line = lookup_url(client, u, api_key)
            lines.append(line)
            if sig:
                sigs.append(sig)
            time.sleep(delay_sec)
        for fn, h in attachments[:max_files]:
            sig, line = lookup_file_hash(client, h, api_key, fn)
            lines.append(line)
            if sig:
                sigs.append(sig)
            time.sleep(delay_sec)

    return sigs, "\n".join(lines)

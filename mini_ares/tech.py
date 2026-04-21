"""Lightweight HTTP fingerprinting (headers + title snippet)."""
from __future__ import annotations

import re
from typing import Any, Dict
import httpx


def fingerprint_url(url: str, timeout: float = 12.0) -> Dict[str, Any]:
    """Fetch URL and extract tech indicators."""
    out: Dict[str, Any] = {"url": url, "error": None}
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True, verify=True) as client:
            r = client.get(url, headers={"User-Agent": "MiniARES-SecurityScanner/1.0"})
            out["status"] = r.status_code
            out["final_url"] = str(r.url)
            out["server"] = r.headers.get("Server", "")
            out["x_powered_by"] = r.headers.get("X-Powered-By", "")
            out["via"] = r.headers.get("Via", "")
            ct = r.headers.get("Content-Type", "")
            out["content_type"] = ct
            text = r.text[:8000] if r.text else ""
            m = re.search(r"<title[^>]*>([^<]{1,200})", text, re.I)
            out["title"] = m.group(1).strip() if m else ""
            # crude framework hints
            body_l = text.lower()
            hints = []
            if "wp-content" in body_l:
                hints.append("WordPress")
            if "drupal" in body_l or "sites/default" in body_l:
                hints.append("Drupal")
            if "react" in body_l and "reactroot" in body_l.replace(" ", ""):
                hints.append("React (SPA hints)")
            if "angular" in body_l:
                hints.append("Angular hints")
            out["framework_hints"] = hints
    except Exception as e:
        out["error"] = str(e)[:300]
    return out

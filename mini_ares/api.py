"""
FastAPI service for Mini ARES (optional API mode).

  uvicorn mini_ares.api:app --host 127.0.0.1 --port 8765
"""
from __future__ import annotations

from dataclasses import asdict
from typing import Any

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware

from .recon import run_attack_surface_scan

app = FastAPI(
    title="Mini ARES",
    description="Rule-based attack surface mapper — recon + analysis only.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _safe_extra(extra: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in (extra or {}).items():
        if isinstance(v, (str, int, float, bool, type(None))):
            out[k] = v
        else:
            out[k] = str(v)[:2000]
    return out


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "mini-ares"}


@app.get("/scan")
def scan(
    domain: str = Query(..., description="Apex domain, e.g. example.com"),
    max_hosts: int = Query(15, ge=1, le=80),
    use_subfinder: bool = Query(True),
    prefer_nmap: bool = Query(True),
    deep_scan: bool = Query(False, description="nmap -sV + NSE scripts (requires nmap)"),
    os_detection: bool = Query(False, description="nmap -O (may require admin)"),
) -> dict[str, Any]:
    findings = run_attack_surface_scan(
        domain,
        max_hosts=max_hosts,
        use_subfinder=use_subfinder,
        prefer_nmap=prefer_nmap,
        deep_scan=deep_scan,
        os_detection=os_detection,
    )
    rows = []
    for f in findings:
        d = asdict(f)
        d["extra"] = _safe_extra(d.get("extra") or {})
        rows.append(d)
    return {"domain": domain, "findings": rows, "count": len(rows)}

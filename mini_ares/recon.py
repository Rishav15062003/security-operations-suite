"""
Orchestrate passive subdomains, port scan, optional nmap deep scan (-sV, NSE, -O),
HTTP fingerprinting, and hostname DNS intel.
Only use against assets you are authorized to test.
"""
from __future__ import annotations

import re
from typing import List, Set

from .deep_scan import (
    format_os_detail,
    format_port_detail,
    nmap_host_scan_to_dict,
    run_nmap_deep_scan,
    summarize_tech_stack,
)
from .dns_intel import format_hostname_intel, hostname_intel
from .models import SurfaceFinding
from .passive import crt_sh_subdomains
from .ports import DEFAULT_PORTS, scan_ports
from .risks import (
    explain_open_port,
    explain_subdomain,
    explain_tech_header,
    severity_for_port,
)
from .subfinder_runner import subfinder_subdomains
from .tech import fingerprint_url
from .tool_paths import resolve_nmap_executable


def _normalize_domain(raw: str) -> str:
    s = raw.strip().lower()
    s = re.sub(r"^https?://", "", s)
    s = s.split("/")[0]
    if s.startswith("www."):
        s = s[4:]
    return s.rstrip(".")


def run_attack_surface_scan(
    domain: str,
    *,
    max_hosts: int = 15,
    use_subfinder: bool = True,
    prefer_nmap: bool = True,
    ports: List[int] | None = None,
    deep_scan: bool = False,
    os_detection: bool = False,
) -> List[SurfaceFinding]:
    findings: List[SurfaceFinding] = []
    apex = _normalize_domain(domain)
    if not apex or "." not in apex:
        return [
            SurfaceFinding(
                category="risk",
                title="Invalid target",
                detail="Enter a DNS name like example.com",
                severity="high",
                why_risky="Invalid input prevents a meaningful, authorized assessment.",
                target=domain,
            )
        ]

    subs: Set[str] = {apex}
    subs |= crt_sh_subdomains(apex)
    if use_subfinder:
        subs |= subfinder_subdomains(apex)

    findings.append(
        SurfaceFinding(
            category="subdomain",
            title=f"Discovered {len(subs)} hostname(s) (passive + optional subfinder)",
            detail=f"Apex: {apex}. Sources: crt.sh certificate transparency" + ("; subfinder" if use_subfinder else ""),
            severity="info",
            why_risky=(
                "A broad hostname inventory expands the attack surface: each host may run different software, "
                "certificates, and exposure rules. Review which names are intentional and decommission stale DNS."
            ),
            target=apex,
            extra={"count": len(subs)},
        )
    )

    sorted_subs = sorted(subs)
    sample = sorted_subs[:80]
    list_detail = ", ".join(sample)
    if len(subs) > 80:
        list_detail += f" … (+{len(subs) - 80} more)"
    findings.append(
        SurfaceFinding(
            category="subdomain",
            title=f"Subdomain / hostname inventory ({len(subs)} names)",
            detail=list_detail[:20000],
            severity="info",
            why_risky=(
                "Each hostname may resolve to different IPs, certificates, and services. "
                "Compare against your DNS inventory and remove abandoned records."
            ),
            target=apex,
            extra={"hostnames_sample": sample, "total": len(subs)},
        )
    )

    hosts = sorted_subs[: max(1, max_hosts)]
    port_list = ports or list(DEFAULT_PORTS)
    nmap_ok = resolve_nmap_executable() is not None
    use_deep = bool(deep_scan and prefer_nmap and nmap_ok)

    for host in hosts:
        hint = explain_subdomain(host)
        if hint:
            findings.append(
                SurfaceFinding(
                    category="risk",
                    title=f"Naming pattern worth review: {host}",
                    detail="Hostname suggests a sensitive role (heuristic).",
                    severity="medium",
                    why_risky=hint,
                    target=host,
                )
            )

        hi = hostname_intel(host)
        findings.append(
            SurfaceFinding(
                category="host_intel",
                title=f"DNS resolution — {host}",
                detail=format_hostname_intel(hi),
                severity="info",
                why_risky=(
                    "IP and PTR context helps spot unexpected hosting, CDNs, or mismatches between brand names "
                    "and infrastructure."
                ),
                target=host,
                extra=hi,
            )
        )

        nh = None
        open_p: Set[int] = set()

        if use_deep:
            nh = run_nmap_deep_scan(host, port_list, os_detection=os_detection)
            if nh and nh.ports:
                open_p = {p.port for p in nh.ports}
            else:
                open_p = scan_ports(host, port_list, prefer_nmap=prefer_nmap)
                nh = None
        else:
            open_p = scan_ports(host, port_list, prefer_nmap=prefer_nmap)

        if nh and (nh.os_matches or nh.os_classes):
            findings.append(
                SurfaceFinding(
                    category="os",
                    title=f"OS fingerprint (nmap) — {host}",
                    detail=format_os_detail(nh),
                    severity="info",
                    why_risky=(
                        "OS guesses are heuristic and may be wrong, but they inform patch expectations and "
                        "hardening baselines."
                    ),
                    target=host,
                    extra={"os_matches": nh.os_matches, "os_classes": nh.os_classes},
                )
            )

        if nh:
            findings.append(
                SurfaceFinding(
                    category="nmap",
                    title=f"In-depth nmap result (services, versions, scripts) — {host}",
                    detail="Structured scan output (XML-derived). See per-port findings below.",
                    severity="info",
                    why_risky=(
                        "Service versions and NSE script output reveal patch levels, certificates, and banners—"
                        "useful for defenders and reconnaissance alike."
                    ),
                    target=host,
                    extra=nmap_host_scan_to_dict(nh),
                )
            )

        for port in sorted(open_p):
            sev = severity_for_port(port)
            pinfo = None
            if nh:
                for p in nh.ports:
                    if p.port == port:
                        pinfo = p
                        break
            if pinfo:
                detail = format_port_detail(pinfo)
                title = f"TCP {port} open — {pinfo.service_name or 'unknown'} — {host}"
                if pinfo.product or pinfo.version:
                    title = f"TCP {port} — {pinfo.product} {pinfo.version}".strip() + f" — {host}"
                findings.append(
                    SurfaceFinding(
                        category="port",
                        title=title[:200],
                        detail=detail[:12000],
                        severity=sev,
                        why_risky=explain_open_port(port)
                        + " Service/version data refines exposure and patch priority.",
                        target=f"{host}:{port}",
                        extra={
                            "port": port,
                            "service": pinfo.service_name,
                            "product": pinfo.product,
                            "version": pinfo.version,
                            "scripts": [{"id": s.script_id, "output": s.output[:2000]} for s in pinfo.scripts],
                        },
                    )
                )
            else:
                findings.append(
                    SurfaceFinding(
                        category="port",
                        title=f"TCP {port} open — {host}",
                        detail=f"Probe: {'nmap' if prefer_nmap else 'socket'} scan on selected ports.",
                        severity=sev,
                        why_risky=explain_open_port(port),
                        target=f"{host}:{port}",
                        extra={"port": port},
                    )
                )

        if 80 in open_p and 443 not in open_p:
            findings.append(
                SurfaceFinding(
                    category="risk",
                    title=f"HTTP without HTTPS on {host}",
                    detail="Port 80 open but 443 not in scanned set or closed.",
                    severity="medium",
                    why_risky=(
                        "Serving web traffic only over HTTP can expose credentials and session tokens. "
                        "Prefer HTTPS everywhere with redirects."
                    ),
                    target=host,
                )
            )

        fp = None
        if 443 in open_p or 80 in open_p:
            scheme = "https" if 443 in open_p else "http"
            url = f"{scheme}://{host}/"
            fp = fingerprint_url(url)
            if fp.get("error"):
                findings.append(
                    SurfaceFinding(
                        category="technology",
                        title=f"HTTP probe incomplete — {host}",
                        detail=fp.get("error", "unknown")[:200],
                        severity="low",
                        why_risky=(
                            "Could not fingerprint the app (TLS errors, timeouts, or blocking). "
                            "Manual review and browser inspection may still be needed."
                        ),
                        target=host,
                    )
                )
            else:
                srv = fp.get("server") or ""
                xpb = fp.get("x_powered_by") or ""
                title = fp.get("title") or ""
                findings.append(
                    SurfaceFinding(
                        category="technology",
                        title=f"Web fingerprint — {host}",
                        detail=f"Status {fp.get('status')}; Server: {srv or 'n/a'}; X-Powered-By: {xpb or 'n/a'}; Title: {title[:80]}",
                        severity="low",
                        why_risky=explain_tech_header(srv, xpb),
                        target=host,
                        extra=fp,
                    )
                )
                if fp.get("framework_hints"):
                    findings.append(
                        SurfaceFinding(
                            category="technology",
                            title=f"Possible stack hints — {host}",
                            detail=", ".join(fp["framework_hints"]),
                            severity="info",
                            why_risky=(
                                "Framework hints help defenders prioritize patching and secure configuration; "
                                "attackers use the same signals to choose exploits."
                            ),
                            target=host,
                        )
                    )

        if nh:
            http_ok = fp and not fp.get("error")
            if http_ok:
                findings.append(
                    SurfaceFinding(
                        category="technology",
                        title=f"Combined tech stack summary — {host}",
                        detail=summarize_tech_stack(nh, fp),
                        severity="info",
                        why_risky=(
                            "Correlate nmap service banners with HTTP headers to spot inconsistencies and "
                            "prioritize patching (e.g. nginx on 443 vs Apache in X-Powered-By)."
                        ),
                        target=host,
                        extra={"http_fingerprint": fp, "nmap_summary": nmap_host_scan_to_dict(nh)},
                    )
                )
            else:
                findings.append(
                    SurfaceFinding(
                        category="technology",
                        title=f"Service-level stack (nmap services/versions) — {host}",
                        detail=summarize_tech_stack(nh, {}),
                        severity="info",
                        why_risky="Version and product strings from nmap help scope patching and exposure.",
                        target=host,
                        extra={"nmap_summary": nmap_host_scan_to_dict(nh)},
                    )
                )

    return findings

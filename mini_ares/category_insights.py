"""Per-category intelligence text and HTML reports for attack-surface findings."""
from __future__ import annotations

from collections import defaultdict
from typing import List

from .models import SurfaceFinding
from .report_html import document, esc

CATEGORY_AI: dict[str, str] = {
    "subdomain": (
        "Subdomain discovery expands the inventory of hosts that may run different applications, certificates, "
        "and patch levels. Certificate transparency logs reveal historical names—some may be stale DNS or "
        "forgotten services that are still reachable. Prioritize decommissioning unused names and monitoring "
        "high-value patterns (admin, vpn, ci, api)."
    ),
    "port": (
        "Open TCP ports indicate reachable services. Each exposed service is a potential patch, configuration, "
        "or credential weakness. Administrative protocols (SSH, RDP, SMB, databases) on the public Internet "
        "are disproportionately targeted in automated campaigns. Align exposure with architecture intent."
    ),
    "technology": (
        "Web stack fingerprinting (servers, frameworks, CMS hints) helps both defenders and attackers prioritize "
        "work. Reduce unnecessary banner disclosure where possible, and ensure components match your vulnerability "
        "management and patch cadence."
    ),
    "risk": (
        "Heuristic risk findings combine naming patterns, HTTP/TLS behavior, and exposure context. They are "
        "starting points for human review: validate against architecture, change tickets, and threat intel."
    ),
    "host_intel": (
        "Hostname intelligence ties DNS names to IPv4 addresses and optional reverse DNS (PTR). Mismatches, "
        "unexpected providers, or missing PTR can warrant follow-up with your DNS and hosting inventory."
    ),
    "os": (
        "Operating system guesses from nmap are probabilistic and may be wrong, especially without raw sockets "
        "or sufficient probes. Use them as soft signals for patch expectations and hardening baselines."
    ),
    "nmap": (
        "Structured nmap output aggregates addresses, OS classes, and per-port service detection with optional "
        "NSE script output (titles, certificates, headers). Treat as sensitive reconnaissance data."
    ),
}


def category_title(cat: str) -> str:
    return cat.replace("_", " ").title()


def build_category_insights_text(findings: List[SurfaceFinding]) -> str:
    by_cat: dict[str, List[SurfaceFinding]] = defaultdict(list)
    for f in findings:
        by_cat[f.category].append(f)
    lines: list[str] = []
    for cat in sorted(by_cat.keys()):
        narrative = CATEGORY_AI.get(
            cat,
            "Review these findings in the context of your authorized assessment scope and change management.",
        )
        n = len(by_cat[cat])
        lines.append(f"=== {category_title(cat)} ({n} finding(s)) ===\n{narrative}\n")
    if not lines:
        return "No findings yet — run a surface scan.\n"
    return "\n".join(lines)


def build_html_surface_report(findings: List[SurfaceFinding]) -> str:
    by_cat: dict[str, List[SurfaceFinding]] = defaultdict(list)
    for f in findings:
        by_cat[f.category].append(f)

    summary = f"Total findings: {len(findings)}"
    toc = ['<nav class="toc"><strong>Sections</strong><ul>']
    parts = [f'<section><h2>Executive summary</h2><div class="ai">{esc(summary)}</div></section>']

    for cat in sorted(by_cat.keys()):
        cid = esc(cat)
        toc.append(f'<li><a href="#cat-{cid}">{esc(category_title(cat))}</a></li>')
        narrative = CATEGORY_AI.get(cat, "Review findings with your security baseline.")
        rows = []
        for f in by_cat[cat]:
            rows.append(
                f"<tr><td class='sev-{esc(f.severity)}'>{esc(f.severity)}</td>"
                f"<td>{esc(f.title)}</td><td>{esc(f.target)}</td>"
                f"<td>{esc(f.detail[:400])}</td><td>{esc(f.why_risky[:500])}</td></tr>"
            )
        tbl = (
            "<table><thead><tr><th>Severity</th><th>Title</th><th>Target</th><th>Detail</th><th>Why risky</th></tr></thead><tbody>"
            + "".join(rows)
            + "</tbody></table>"
        )
        parts.append(
            f'<section id="cat-{cid}"><h2>{esc(category_title(cat))}</h2>'
            f'<div class="ai"><strong>Category intelligence</strong><br/>{esc(narrative)}</div>{tbl}</section>'
        )
    toc.append("</ul></nav>")
    return document("Attack surface report (Mini ARES)", "".join(toc) + "".join(parts))

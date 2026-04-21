"""
Category-level intelligence narratives (rule-based expert analysis, suitable for reports).
"""
from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING, List

from .report_html import document, esc

if TYPE_CHECKING:
    from .models import Finding, ParsedEvent

# Finding.category -> long-form "AI-style" explanation
CATEGORY_AI: dict[str, str] = {
    "brute_force": (
        "Automated or manual password guessing against authentication services is one of the most common "
        "precursors to account takeover. High volumes of failures from a single address often indicate a dedicated "
        "attacker or botnet, while repeated failures against one username may signal a targeted credential attack. "
        "Correlate these alerts with successful logons, account lockouts, and geographic context."
    ),
    "unusual_time": (
        "Human attackers and some malware operate outside business hours to avoid immediate detection. "
        "Off-hours successful logins are not inherently malicious (on-call, travel) but deserve verification "
        "against change tickets and expected behavior baselines for each account."
    ),
    "suspicious_ip": (
        "Network-level patterns—such as many failures across a subnet, one host authenticating to many accounts, "
        "or success from private ranges on perimeter-facing systems—can indicate lateral movement preparation, "
        "credential stuffing, or misconfigured trust boundaries. Validate against architecture diagrams and VPC/VNet design."
    ),
    "privilege": (
        "Attempts against root or elevated mechanisms (sudo/su) often precede privilege escalation. "
        "Treat these as high priority for correlation with vulnerability management, patch state, and admin access policies."
    ),
    "enumeration": (
        "Probing for invalid or common usernames helps attackers build username lists for password sprays. "
        "High volumes of 'invalid user' events typically come from internet-facing SSH. Consider rate limiting, "
        "fail2ban-style controls, and moving management access behind VPN or bastion hosts."
    ),
    "credential": (
        "A successful login immediately after many failures can mean a guessed password, credential stuffing success, "
        "or a legitimate user who mistyped a password repeatedly. Force step-up verification or password reset when "
        "this pattern appears on sensitive accounts."
    ),
    "volume": (
        "Statistical spikes in authentication failures may indicate coordinated attacks, automation, or a misconfigured "
        "client repeatedly attempting bad passwords. Compare the time window to maintenance windows and known scanners."
    ),
    "account_abuse": (
        "Lockout events indicate authentication controls are engaging. They often follow brute force or spray activity. "
        "Review whether lockout thresholds balance security with availability, and whether alerting reaches the right team."
    ),
    "account_change": (
        "Password or account metadata changes are normal during resets and administration but can also signal takeover "
        "if unexpected. Clustered changes in a short period may indicate bulk admin work or compromise—verify with ticketing."
    ),
    "reconnaissance": (
        "Banner and protocol probes and high connection churn often precede targeted attacks. They may also reflect "
        "internet-wide scanning. Use network telemetry and honeypot context to separate noise from focused reconnaissance."
    ),
    "ml_anomaly": (
        "Unsupervised models surface behavioral outliers (unusual mixes of failures, successes, and timing per source). "
        "They are triage aids, not verdicts: always validate outliers against business context and known infrastructure."
    ),
    "network_capture": (
        "Packet capture exports summarize traffic at a point in time. Dominant sources, wide destination fan-out, "
        "and TLS or handshake anomalies can indicate scanning, misconfiguration, or client bugs — but they "
        "require correlation with firewall rules, known endpoints, and application baselines."
    ),
}


def category_display_name(cat: str) -> str:
    return cat.replace("_", " ").title()


def build_category_insights_text(findings: List["Finding"]) -> str:
    """Plain-text block: one narrative per category present in findings."""
    by_cat: dict[str, List["Finding"]] = defaultdict(list)
    for f in findings:
        by_cat[f.category].append(f)
    lines: list[str] = []
    for cat in sorted(by_cat.keys()):
        title = category_display_name(cat)
        narrative = CATEGORY_AI.get(
            cat,
            "This category groups related detections. Review each finding, map to your control framework, "
            "and document exceptions with compensating monitoring.",
        )
        n = len(by_cat[cat])
        lines.append(f"=== {title} ({n} finding(s)) ===\n{narrative}\n")
    if not lines:
        return "No findings yet — run analysis to populate category intelligence.\n"
    return "\n".join(lines)


def build_html_log_report(
    log_path: str | None,
    events: List["ParsedEvent"],
    findings: List["Finding"],
) -> str:
    from .models import EventKind

    by_cat: dict[str, List["Finding"]] = defaultdict(list)
    for f in findings:
        by_cat[f.category].append(f)

    parsed = [e for e in events if e.kind != EventKind.UNKNOWN]
    summary = (
        f"Log file: {esc(log_path or 'N/A')}<br/>"
        f"Parsed events: {len(parsed)}<br/>"
        f"Total findings: {len(findings)}"
    )

    toc = [
        '<nav class="toc"><strong>Sections</strong><ul>',
        '<li><a href="#exec">Executive summary</a></li>',
        '<li><a href="#log-info">Log file information</a></li>',
    ]
    body_parts = [f'<section id="exec"><h2>Executive summary</h2><div class="ai">{summary}</div></section>']

    from pathlib import Path

    from .log_file_info import build_log_file_info_text

    lp = Path(log_path) if log_path else Path("unknown")
    info_html = esc(build_log_file_info_text(events, lp, ""))
    body_parts.append(
        f'<section id="log-info"><h2>Log file information</h2><pre class="lab">{info_html}</pre></section>'
    )

    for cat in sorted(by_cat.keys()):
        cid = esc(cat)
        toc.append(f'<li><a href="#cat-{cid}">{esc(category_display_name(cat))}</a></li>')
        narrative = CATEGORY_AI.get(cat, "Review findings in this category against your security baseline.")
        rows = []
        for f in by_cat[cat]:
            rows.append(
                f"<tr><td class='sev-{esc(f.severity)}'>{esc(f.severity)}</td>"
                f"<td>{esc(f.title)}</td><td>{esc(f.detail[:500])}</td></tr>"
            )
        table = (
            "<table><thead><tr><th>Severity</th><th>Title</th><th>Detail</th></tr></thead><tbody>"
            + "".join(rows)
            + "</tbody></table>"
        )
        body_parts.append(
            f'<section id="cat-{cid}"><h2>{esc(category_display_name(cat))}</h2>'
            f'<div class="ai"><strong>Category intelligence</strong><br/>{esc(narrative)}</div>{table}</section>'
        )
    toc.append("</ul></nav>")
    inner = "".join(toc) + "".join(body_parts)
    return document("Log analysis report", inner)

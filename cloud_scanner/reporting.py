"""Category groupings, intelligence narratives, and HTML reports for cloud findings."""
from __future__ import annotations

from collections import defaultdict
from typing import List

from .models import Finding
from .report_html import document, esc


# Report section key -> (display title, AI-style narrative for the whole category)
GROUP_AI: dict[str, tuple[str, str]] = {
    "aws_storage": (
        "AWS — Object storage exposure",
        "Public or overly permissive S3 buckets remain a leading cause of data leaks. Attackers and scanners "
        "routinely hunt for buckets listing objects or policies granting wide read access. Even when intentional "
        "(static sites), you should pair public buckets with CloudFront/OAC, least-privilege policies, and monitoring "
        "for object-level changes.",
    ),
    "aws_network": (
        "AWS — Security groups & network exposure",
        "Security groups are your first line for instance-level access control. Rules allowing 0.0.0.0/0 to "
        "administrative or database ports are frequently exploited. Prefer jump hosts, Session Manager, private "
        "subnets, and defense-in-depth with WAF/ALB for HTTP workloads.",
    ),
    "aws_api": (
        "AWS — APIs & serverless exposure",
        "HTTP APIs and Lambda URLs without strong authentication can expose business logic and data. Anonymous "
        "routes should be rare and documented. Apply authorizers, usage plans, and WAF where APIs face the internet.",
    ),
    "azure_storage": (
        "Azure — Storage accounts",
        "Blob public access allows anonymous data reads when containers are misconfigured. Disable account-level "
        "public access unless required, use private endpoints, and verify container ACLs during CI/CD.",
    ),
    "azure_network": (
        "Azure — NSGs & perimeter",
        "Overly broad inbound rules from Internet or * mirror the risk of wide-open AWS security groups. Align "
        "with Zero Trust: explicit sources, service tags, ASGs, and Bastion for RDP/SSH.",
    ),
    "azure_api": (
        "Azure — API Management",
        "APIs without subscription requirements can be abused for scraping and abuse. Ensure OAuth, keys, or "
        "Azure AD protect sensitive operations.",
    ),
    "static_analysis": (
        "Offline JSON analysis",
        "These results come from exported configuration (no live API calls). Treat them as strong signals for "
        "review in your actual cloud tenant—reconcile with current state because exports may be stale.",
    ),
}


def _group_key_for_code(code: str) -> str:
    if code.startswith("AWS_S3"):
        return "aws_storage"
    if code.startswith("AWS_SG") or code.startswith("AWS_EC2"):
        return "aws_network"
    if code.startswith("AWS_API") or code.startswith("AWS_LAMBDA"):
        return "aws_api"
    if code.startswith("AZURE_STORAGE"):
        return "azure_storage"
    if code.startswith("AZURE_NSG"):
        return "azure_network"
    if code.startswith("AZURE_API"):
        return "azure_api"
    if code.startswith("STATIC_"):
        return "static_analysis"
    return "aws_network"


def build_category_insights_text(findings: List[Finding]) -> str:
    by_g: dict[str, List[Finding]] = defaultdict(list)
    for f in findings:
        by_g[_group_key_for_code(f.code)].append(f)
    lines: list[str] = []
    for gkey in sorted(by_g.keys(), key=lambda k: GROUP_AI.get(k, ("", ""))[0]):
        title, narrative = GROUP_AI.get(gkey, ("Other", "Review these findings in context of your cloud architecture."))
        n = len(by_g[gkey])
        lines.append(f"=== {title} ({n} finding(s)) ===\n{narrative}\n")
    if not lines:
        return "No findings — run a scan to populate category intelligence.\n"
    return "\n".join(lines)


def build_html_cloud_report(findings: List[Finding]) -> str:
    by_g: dict[str, List[Finding]] = defaultdict(list)
    for f in findings:
        by_g[_group_key_for_code(f.code)].append(f)

    summary = f"Total findings: {len(findings)}"
    toc = ['<nav class="toc"><strong>Sections</strong><ul>']
    parts = [f'<section><h2>Executive summary</h2><div class="ai">{esc(summary)}</div></section>']

    for gkey in sorted(by_g.keys(), key=lambda k: GROUP_AI.get(k, ("", ""))[0]):
        title, narrative = GROUP_AI.get(gkey, ("Other findings", "Review in cloud console."))
        gid = esc(gkey)
        toc.append(f'<li><a href="#grp-{gid}">{esc(title)}</a></li>')
        rows = []
        for f in by_g[gkey]:
            rows.append(
                f"<tr><td class='sev-{esc(f.severity.value)}'>{esc(f.severity.value)}</td>"
                f"<td>{esc(f.code)}</td><td>{esc(f.title)}</td><td>{esc(f.detail[:400])}</td></tr>"
            )
        table = (
            "<table><thead><tr><th>Severity</th><th>Code</th><th>Title</th><th>Detail</th></tr></thead><tbody>"
            + "".join(rows)
            + "</tbody></table>"
        )
        parts.append(
            f'<section id="grp-{gid}"><h2>{esc(title)}</h2>'
            f'<div class="ai"><strong>Category intelligence</strong><br/>{esc(narrative)}</div>{table}</section>'
        )
    toc.append("</ul></nav>")
    return document("Cloud misconfiguration report", "".join(toc) + "".join(parts))

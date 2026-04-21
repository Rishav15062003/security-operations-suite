from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .config_loader import ScanConfig, apply_env_defaults, load_config
from .json_analyzer import analyze_json_file
from .models import Finding, Severity
from .remediation import format_remediation_block, suggestions_for_code


def _severity_sort_key(f: Finding) -> tuple:
    order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
    return (order.get(f.severity, 5), f.provider.value, f.title)


def render_findings(findings: list[Finding], show_remediation: bool, console: Console | None = None) -> None:
    console = console or Console()
    if not findings:
        console.print(Panel("[green]No misconfigurations detected in scope.[/green]", title="Results"))
        return

    table = Table(title=f"Findings ({len(findings)})", show_lines=True)
    table.add_column("Severity", style="bold", max_width=10)
    table.add_column("Provider", max_width=8)
    table.add_column("Code", max_width=22)
    table.add_column("Title")
    table.add_column("Resource", overflow="fold")

    for f in sorted(findings, key=_severity_sort_key):
        color = {
            Severity.CRITICAL: "red",
            Severity.HIGH: "bright_red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.INFO: "dim",
        }.get(f.severity, "white")
        table.add_row(
            f"[{color}]{f.severity.value.upper()}[/{color}]",
            f.provider.value,
            f.code,
            f.title,
            f"{f.resource_type}: {f.resource_id}" + (f" ({f.region})" if f.region else ""),
        )
    console.print(table)

    if show_remediation:
        console.print()
        seen: set[str] = set()
        for f in sorted(findings, key=_severity_sort_key):
            if f.code in seen:
                continue
            seen.add(f.code)
            console.print(
                Panel(
                    format_remediation_block(f.code),
                    title=f"[bold]Remediation: {f.code}[/bold]",
                    border_style="cyan",
                )
            )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Cloud misconfiguration scanner (AWS / Azure) + offline JSON analysis.",
    )
    p.add_argument(
        "--config",
        "-c",
        type=Path,
        default=None,
        help="Path to JSON config (regions, profile, subscription).",
    )
    p.add_argument("--aws", action="store_true", help="Run AWS checks (S3, SG, API Gateway v2, Lambda URLs).")
    p.add_argument("--azure", action="store_true", help="Run Azure checks (storage, NSG, optional APIM).")
    p.add_argument(
        "--json-file",
        type=Path,
        default=None,
        help="Offline: analyze exported JSON (security groups, bucket policy, NSG).",
    )
    p.add_argument(
        "--no-remediation",
        action="store_true",
        help="Hide auto-remediation suggestion panels.",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    console = Console()

    if args.config is not None:
        cfg = load_config(args.config)
    else:
        cfg = ScanConfig()
    apply_env_defaults(cfg)

    findings: list[Finding] = []

    if args.json_file:
        if not args.json_file.is_file():
            console.print(f"[red]File not found: {args.json_file}[/red]")
            return 2
        findings.extend(analyze_json_file(args.json_file))

    run_aws = args.aws
    run_azure = args.azure
    if not run_aws and not run_azure and args.json_file is None:
        run_aws = True

    if run_aws:
        try:
            from .aws_scanner import scan_aws

            findings.extend(scan_aws(cfg))
        except Exception as e:
            console.print(f"[red]AWS scan failed: {e}[/red]")
            return 1

    if run_azure:
        try:
            from .azure_scanner import scan_azure

            findings.extend(scan_azure(cfg))
        except Exception as e:
            console.print(f"[red]Azure scan failed: {e}[/red]")
            return 1

    render_findings(findings, show_remediation=not args.no_remediation, console=console)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

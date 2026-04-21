from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Sequence

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .models import EventKind, Finding, ParsedEvent


def _bar(label: str, value: int, max_val: int, width: int = 24) -> str:
    # ASCII only so legacy Windows consoles (cp1252) do not raise on render
    if max_val <= 0:
        return f"{label:12} " + "-" * width
    filled = int(round(width * value / max_val))
    bar = "#" * filled + "-" * (width - filled)
    return f"{label:12} {bar} {value}"


def render_dashboard(
    events: Sequence[ParsedEvent],
    findings: Sequence[Finding],
    console: Console | None = None,
) -> None:
    console = console or Console()
    parsed = [e for e in events if e.kind != EventKind.UNKNOWN]
    total = len(parsed)
    fails = sum(1 for e in parsed if e.kind == EventKind.LOGIN_FAILURE)
    oks = sum(1 for e in parsed if e.kind == EventKind.LOGIN_SUCCESS)
    packets = sum(1 for e in parsed if e.kind == EventKind.PACKET_RECORD)
    other = total - fails - oks - packets

    by_hour = Counter()
    for e in parsed:
        if e.ts:
            by_hour[e.ts.hour] += 1
    max_h = max(by_hour.values()) if by_hour else 1

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(findings, key=lambda f: (sev_order.get(f.severity, 5), f.category))

    top_ips = Counter()
    for e in parsed:
        if e.ip:
            top_ips[e.ip] += 1
    top_list = top_ips.most_common(8)

    summary = Table.grid(padding=(0, 2))
    summary.add_row(
        Panel(
            f"[bold]Parsed events[/bold]: {total}\n"
            f"[red]Auth failures[/red]: {fails}  [green]Auth success[/green]: {oks}\n"
            f"[yellow]Packet rows[/yellow] (Wireshark/tshark): {packets}\n"
            f"[cyan]Other parsed[/cyan]: {other} (e.g. password changes, lockouts, probes)",
            title="Summary",
            border_style="cyan",
        ),
        Panel(
            "\n".join(
                _bar(f"{h:02d}:00", by_hour.get(h, 0), max_h)
                for h in range(24)
            ),
            title="Activity by hour (UTC/local as in log)",
            border_style="magenta",
        ),
    )
    console.print(summary)

    if top_list:
        ip_table = Table(title="Top source IPs (all parsed events)", box=box.ROUNDED)
        ip_table.add_column("IP", style="cyan")
        ip_table.add_column("Count", justify="right")
        for ip, c in top_list:
            ip_table.add_row(ip, str(c))
        console.print(ip_table)

    if sorted_findings:
        ft = Table(title="Findings", box=box.HEAVY_EDGE, show_lines=True)
        ft.add_column("Severity", style="bold")
        ft.add_column("Category")
        ft.add_column("Title")
        ft.add_column("Detail", overflow="fold", max_width=56)
        for f in sorted_findings:
            sev_style = {
                "critical": "red",
                "high": "bright_red",
                "medium": "yellow",
                "low": "blue",
                "info": "dim",
            }.get(f.severity, "white")
            ft.add_row(
                Text(f.severity.upper(), style=sev_style),
                f.category,
                f.title,
                f.detail,
            )
        console.print(ft)
    else:
        console.print(Panel("[dim]No findings from current rules / ML.[/dim]", title="Findings"))

    console.print(
        Text(
            f"Run timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            style="dim",
        )
    )

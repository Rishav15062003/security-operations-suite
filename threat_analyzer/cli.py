from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console

from .dashboard import render_dashboard
from .detectors import run_all_detectors
from .parser import parse_file


def _ensure_utf8_stdout() -> None:
    out = getattr(sys.stdout, "reconfigure", None)
    if callable(out):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except (OSError, ValueError):
            pass


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Blue Team log analyzer — brute force, unusual times, suspicious IPs, optional ML.",
    )
    p.add_argument(
        "log_file",
        type=Path,
        help="Path to auth-style log (e.g. /var/log/auth.log or a sample file).",
    )
    p.add_argument(
        "--year",
        type=int,
        default=2026,
        help="Year for syslog lines without year (default: 2026).",
    )
    p.add_argument(
        "--fail-threshold",
        type=int,
        default=5,
        help="Failed attempts from one IP in window to flag brute force (default: 5).",
    )
    p.add_argument(
        "--window-minutes",
        type=int,
        default=5,
        help="Rolling window for brute-force detection (default: 5).",
    )
    p.add_argument(
        "--business-start",
        type=int,
        default=8,
        help="Business hour start (0-23) for off-hours login flags (default: 8).",
    )
    p.add_argument(
        "--business-end",
        type=int,
        default=18,
        help="Business hour end (default: 18).",
    )
    p.add_argument(
        "--max-pcap-packets",
        type=int,
        default=None,
        metavar="N",
        help="For .pcap/.pcapng: load at most N packets (default 250000). Use 0 for no limit.",
    )
    p.add_argument(
        "--no-ml",
        action="store_true",
        help="Disable IsolationForest anomaly scoring.",
    )
    p.add_argument(
        "--ml-contamination",
        type=float,
        default=0.12,
        help="IsolationForest contamination (default: 0.12).",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    _ensure_utf8_stdout()
    args = build_parser().parse_args(argv)
    path = args.log_file
    if not path.is_file():
        print(f"File not found: {path}", file=sys.stderr)
        return 2

    events = parse_file(str(path), default_year=args.year, max_pcap_packets=args.max_pcap_packets)
    findings, _ = run_all_detectors(
        events,
        fail_threshold=args.fail_threshold,
        window_minutes=args.window_minutes,
        business_start=args.business_start,
        business_end=args.business_end,
        ml_contamination=args.ml_contamination,
        ml_enabled=not args.no_ml,
    )

    render_dashboard(events, findings, console=Console())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

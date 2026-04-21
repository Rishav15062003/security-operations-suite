"""Shared HTML report helpers (no external deps)."""
from __future__ import annotations

from datetime import datetime


def esc(s: str) -> str:
    return (
        (s or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def document(title: str, body_inner: str) -> str:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>{esc(title)}</title>
<style>
  body {{ font-family: Segoe UI, system-ui, sans-serif; background:#0f0f1a; color:#e4e4e7; margin:0; padding:24px; line-height:1.5; }}
  h1 {{ color:#93c5fd; font-size:1.5rem; }}
  h2 {{ color:#a5b4fc; font-size:1.15rem; margin-top:2rem; border-bottom:1px solid #27273a; padding-bottom:6px; }}
  .meta {{ color:#8892a6; font-size:0.9rem; margin-bottom:1.5rem; }}
  .ai {{ background:#1a1a2e; border-left:4px solid #6366f1; padding:12px 16px; margin:12px 0; border-radius:4px; }}
  table {{ border-collapse:collapse; width:100%; margin:12px 0; font-size:0.9rem; }}
  th, td {{ border:1px solid #27273a; padding:8px; text-align:left; vertical-align:top; }}
  th {{ background:#1e1e2e; color:#c4b5fd; }}
  tr:nth-child(even) {{ background:#14141f; }}
  .toc a {{ color:#93c5fd; }}
  .sev-critical {{ color:#f87171; }} .sev-high {{ color:#fb923c; }} .sev-medium {{ color:#fbbf24; }}
  .sev-low {{ color:#60a5fa; }} .sev-info {{ color:#94a3b8; }}
  pre.lab {{ white-space: pre-wrap; background:#14141f; padding:16px; border-radius:6px; overflow:auto; font-size:0.85rem; line-height:1.45; }}
</style>
</head>
<body>
<h1>{esc(title)}</h1>
<p class="meta">Generated {esc(ts)} · Security Operations Suite</p>
{body_inner}
</body>
</html>
"""

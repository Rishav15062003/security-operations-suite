from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class SurfaceFinding:
    """One attack-surface observation with rule-based risk rationale."""

    category: str  # subdomain | port | technology | risk
    title: str
    detail: str
    severity: str  # critical, high, medium, low, info
    why_risky: str
    target: str
    extra: dict[str, Any] = field(default_factory=dict)

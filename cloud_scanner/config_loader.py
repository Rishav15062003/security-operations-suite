from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List, Optional


@dataclass
class ScanConfig:
    """Loaded from JSON config file."""

    aws_regions: List[str] = field(default_factory=lambda: ["us-east-1"])
    aws_profile: Optional[str] = None
    aws_skip_buckets: List[str] = field(default_factory=list)
    azure_subscription_id: Optional[str] = None
    azure_resource_groups: List[str] = field(default_factory=list)  # empty = all accessible


def load_config(path: str | Path) -> ScanConfig:
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Config not found: {p}")
    with open(p, encoding="utf-8") as f:
        data: dict[str, Any] = json.load(f)
    aws = data.get("aws") or {}
    az = data.get("azure") or {}
    regions = aws.get("regions") or ["us-east-1"]
    return ScanConfig(
        aws_regions=regions if isinstance(regions, list) else [str(regions)],
        aws_profile=aws.get("profile"),
        aws_skip_buckets=list(aws.get("skip_buckets") or []),
        azure_subscription_id=az.get("subscription_id") or _env_sub(),
        azure_resource_groups=list(az.get("resource_groups") or []),
    )


def _env_sub() -> Optional[str]:
    import os

    return os.environ.get("AZURE_SUBSCRIPTION_ID")


def apply_env_defaults(cfg: ScanConfig) -> None:
    """Fill subscription ID from environment when missing."""
    if cfg.azure_subscription_id is None:
        cfg.azure_subscription_id = _env_sub()

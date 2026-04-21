from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CloudProvider(str, Enum):
    AWS = "aws"
    AZURE = "azure"
    STATIC = "static"


@dataclass
class Finding:
    """One misconfiguration or exposure finding."""

    code: str
    title: str
    detail: str
    severity: Severity
    provider: CloudProvider
    resource_id: str
    resource_type: str
    region: Optional[str] = None
    raw: dict[str, Any] = field(default_factory=dict)

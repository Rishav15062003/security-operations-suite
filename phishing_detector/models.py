"""Data models for phishing / URL risk analysis."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class RiskVerdict(str, Enum):
    LIKELY_SAFE = "likely_safe"
    LOW_RISK = "low_risk"
    MIXED = "mixed"
    SUSPICIOUS = "suspicious"
    LIKELY_PHISHING = "likely_phishing"


@dataclass
class PhishingSignal:
    code: str
    severity: str  # info | low | medium | high | critical
    title: str
    detail: str
    weight: int = 0


@dataclass
class EMLAttachmentInfo:
    filename: str
    content_type: str
    size_bytes: int
    sha256: str


@dataclass
class PhishingReport:
    """Full analysis for one primary URL (plus optional EML + VirusTotal context)."""

    input_text: str
    primary_url: str
    normalized_url: str
    host: str
    risk_score: int  # 0–100
    verdict: RiskVerdict
    signals: list[PhishingSignal] = field(default_factory=list)
    ai_summary: str = ""
    extracted_urls: list[str] = field(default_factory=list)
    # Optional EML / VT
    eml_path: str | None = None
    eml_subject: str | None = None
    eml_from: str | None = None
    eml_to: str | None = None
    eml_reply_to: str | None = None
    eml_return_path: str | None = None
    eml_attachments: list[EMLAttachmentInfo] = field(default_factory=list)
    virustotal_text: str = ""

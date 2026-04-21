"""Phishing / URL risk heuristics (TLS, DNS, redirects, typosquat, keywords, EML, VirusTotal)."""
from __future__ import annotations

from .analyzer import analyze_phishing, analyze_url, extract_urls_and_emails
from .models import EMLAttachmentInfo, PhishingReport, PhishingSignal, RiskVerdict
from .phishing_toolchain import format_phishing_tool_status, run_phishing_auto_install

__all__ = [
    "analyze_phishing",
    "analyze_url",
    "extract_urls_and_emails",
    "EMLAttachmentInfo",
    "PhishingReport",
    "PhishingSignal",
    "RiskVerdict",
    "format_phishing_tool_status",
    "run_phishing_auto_install",
]

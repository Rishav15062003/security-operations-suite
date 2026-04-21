"""Heuristic checks on parsed .eml (headers, subject, attachments)."""
from __future__ import annotations

import re

from .eml_parser import ParsedEML, domain_from_address
from .models import EMLAttachmentInfo, PhishingSignal

_SUBJECT_LURES = frozenset(
    {
        "urgent",
        "verify",
        "suspended",
        "locked",
        "invoice",
        "payment",
        "unusual activity",
        "action required",
        "confirm",
        "security alert",
        "password",
        "tax refund",
        "gift card",
        "wire transfer",
    }
)

_RISKY_ATTACH_EXT = frozenset(
    {
        ".exe",
        ".scr",
        ".bat",
        ".cmd",
        ".com",
        ".pif",
        ".msi",
        ".ps1",
        ".vbs",
        ".js",
        ".jse",
        ".wsf",
        ".jar",
        ".app",
        ".dmg",
        ".apk",
        ".docm",
        ".xlsm",
        ".pptm",
        ".htm",
        ".html",
        ".zip",
        ".rar",
        ".7z",
        ".iso",
    }
)

_BRAND_WORDS = (
    "microsoft",
    "google",
    "paypal",
    "amazon",
    "apple",
    "netflix",
    "bank",
    "chase",
    "wells fargo",
    "irs",
    "fedex",
    "dhl",
    "linkedin",
)


def _add(signals: list[PhishingSignal], code: str, sev: str, title: str, detail: str, w: int) -> None:
    signals.append(PhishingSignal(code=code, severity=sev, title=title, detail=detail, weight=w))


def analyze_eml_headers_and_attachments(eml: ParsedEML) -> list[PhishingSignal]:
    signals: list[PhishingSignal] = []

    subj = (eml.subject or "").lower()
    for lure in _SUBJECT_LURES:
        if lure in subj:
            _add(
                signals,
                f"eml_subj_{lure.replace(' ', '_')}",
                "medium",
                f"Phishing-style subject phrase: “{lure}”",
                "Common in social-engineering email subjects.",
                10,
            )
            break

    from_dom = domain_from_address(eml.from_raw)
    reply_dom = domain_from_address(eml.reply_to)
    if eml.reply_to.strip() and from_dom and reply_dom and from_dom != reply_dom:
        _add(
            signals,
            "eml_reply_to_mismatch",
            "high",
            "Reply-To domain differs from From domain",
            f"From domain: {from_dom}; Reply-To domain: {reply_dom}",
            22,
        )

    rp = eml.return_path.strip()
    if rp and from_dom:
        rp_email = re.search(r"<([^>]+)>", rp) or re.search(r"([\w.+-]+@[\w.-]+)", rp)
        if rp_email:
            rp_addr = rp_email.group(1)
            if "@" in rp_addr:
                rp_dom = rp_addr.split("@", 1)[1].lower()
                if rp_dom != from_dom and "mail" not in rp_dom:
                    _add(
                        signals,
                        "eml_return_path_mismatch",
                        "medium",
                        "Return-Path domain differs from From",
                        f"From: {from_dom}; Return-Path: {rp_dom}",
                        14,
                    )

    # Display-name brand impersonation (heuristic)
    from_lower = (eml.from_raw or "").lower()
    name_part = eml.from_raw.split("<")[0].lower() if "<" in eml.from_raw else ""
    if from_dom:
        for brand in _BRAND_WORDS:
            if brand in name_part and brand not in from_dom:
                _add(
                    signals,
                    "eml_display_name_brand",
                    "high",
                    f"Display name references “{brand}” but sender domain is different",
                    f"Sender domain: {from_dom}",
                    20,
                )
                break

    if not eml.message_id.strip():
        _add(signals, "eml_no_message_id", "low", "Missing or empty Message-ID", "Unusual for legitimate bulk mail.", 4)

    auth = (eml.authentication_results or "").lower()
    if auth:
        if "spf=fail" in auth or "spf=softfail" in auth:
            _add(signals, "eml_spf_fail", "medium", "SPF failure in Authentication-Results", eml.authentication_results[:300], 12)
        if "dkim=fail" in auth:
            _add(signals, "eml_dkim_fail", "medium", "DKIM failure in Authentication-Results", eml.authentication_results[:300], 10)
        if "dmarc=fail" in auth:
            _add(signals, "eml_dmarc_fail", "high", "DMARC failure in Authentication-Results", eml.authentication_results[:300], 16)
    else:
        _add(signals, "eml_no_auth_results", "info", "No Authentication-Results header", "Cannot assess SPF/DKIM/DMARC from headers.", 2)

    for att in eml.attachments:
        signals.extend(_attachment_signals(att))

    if len(eml.all_urls) > 8:
        _add(
            signals,
            "eml_many_links",
            "medium",
            f"Many distinct URLs in message ({len(eml.all_urls)})",
            "Phishing emails often contain multiple redirect or tracking links.",
            8,
        )

    return signals


def _attachment_signals(att: EMLAttachmentInfo) -> list[PhishingSignal]:
    out: list[PhishingSignal] = []
    fn = (att.filename or "").lower()

    for ext in _RISKY_ATTACH_EXT:
        if fn.endswith(ext):
            _add(
                out,
                f"att_ext_{ext.replace('.', '')}",
                "high",
                f"High-risk attachment type: {ext}",
                f"{att.filename} ({att.size_bytes} bytes, {att.content_type})",
                18,
            )
            break

    if re.search(r"\.(pdf|docx?|xlsx?|txt|jpg|png)\.(exe|scr|bat|zip)", fn):
        _add(
            out,
            "att_double_ext",
            "critical",
            "Double extension (e.g. document.pdf.exe)",
            att.filename,
            28,
        )

    if att.size_bytes == 0:
        _add(out, "att_empty", "low", "Zero-byte attachment", att.filename, 3)

    if att.size_bytes > 25 * 1024 * 1024:
        _add(out, "att_huge", "low", f"Very large attachment ({att.size_bytes // 1024 // 1024} MiB)", att.filename, 5)

    return out

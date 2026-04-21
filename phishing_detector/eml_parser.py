"""Parse .eml files: headers, bodies, attachments, embedded URLs."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path

from .models import EMLAttachmentInfo

_HREF_RE = re.compile(r'(?i)href\s*=\s*["\']([^"\']+)["\']')
_SRC_RE = re.compile(r'(?i)(?:src|data-url)\s*=\s*["\']([^"\']+)["\']')


@dataclass
class ParsedEML:
    subject: str
    from_raw: str
    to_raw: str
    reply_to: str
    return_path: str
    message_id: str
    authentication_results: str
    received_lines: list[str]
    raw_headers_sample: str
    body_plain: str
    body_html: str
    attachments: list[EMLAttachmentInfo] = field(default_factory=list)
    all_urls: list[str] = field(default_factory=list)

    def combined_text_for_analysis(self) -> str:
        parts = [
            self.subject,
            self.from_raw,
            self.body_plain,
            self.body_html[:200_000] if self.body_html else "",
            " ".join(self.all_urls),
        ]
        return "\n".join(p for p in parts if p)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _extract_urls_from_html(html: str) -> list[str]:
    urls: list[str] = []
    for rx in (_HREF_RE, _SRC_RE):
        urls.extend(m.group(1) for m in rx.finditer(html))
    # crude script url=
    for m in re.finditer(r"(?i)https?://[^\s\"'<>]+", html):
        urls.append(m.group(0).rstrip(").,;"))
    return urls


def parse_eml_file(path: Path | str) -> ParsedEML:
    p = Path(path)
    raw = p.read_bytes()
    return parse_eml_bytes(raw, source_name=str(p))


def parse_eml_bytes(raw: bytes, *, source_name: str = "") -> ParsedEML:
    msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(raw)

    def _hdr(name: str) -> str:
        v = msg.get(name)
        if v is None:
            return ""
        return str(v)

    subject = _hdr("Subject")
    from_raw = _hdr("From")
    to_raw = _hdr("To")
    reply_to = _hdr("Reply-To")
    return_path = _hdr("Return-Path")
    message_id = _hdr("Message-ID")
    auth_res = _hdr("Authentication-Results")
    received = []
    for k, v in msg.items():
        if k.lower() == "received":
            received.append(str(v)[:500])

    headers_sample = ""
    for k, v in list(msg.items())[:40]:
        headers_sample += f"{k}: {str(v)[:200]}\n"

    body_plain = ""
    body_html = ""
    attachments: list[EMLAttachmentInfo] = []
    url_set: set[str] = set()

    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        ctype = part.get_content_type()
        main = part.get_content_maintype()
        disp = (part.get_content_disposition() or "").lower()
        fn = part.get_filename()
        payload = part.get_payload(decode=True)
        if payload is None:
            continue

        is_attachment = disp == "attachment" or (
            fn and main not in ("text", "multipart") and disp != "inline"
        )

        if is_attachment:
            name = fn or "unnamed.bin"
            sz = len(payload)
            h = _sha256_bytes(payload)
            attachments.append(
                EMLAttachmentInfo(
                    filename=name,
                    content_type=ctype,
                    size_bytes=sz,
                    sha256=h,
                )
            )
            continue

        if main == "text" and "plain" in ctype:
            try:
                body_plain += payload.decode(part.get_content_charset() or "utf-8", errors="replace")
            except Exception:
                body_plain += str(payload)[:50_000]
        elif main == "text" and "html" in ctype:
            try:
                dec = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
            except Exception:
                dec = str(payload)[:200_000]
            body_html += dec
            for u in _extract_urls_from_html(dec):
                url_set.add(u.strip())

    # URLs from plain
    for m in re.finditer(r"(?i)https?://[^\s<>\s\"']+", body_plain):
        url_set.add(m.group(0).rstrip(").,;"))

    all_urls = list(url_set)
    return ParsedEML(
        subject=subject,
        from_raw=from_raw,
        to_raw=to_raw,
        reply_to=reply_to,
        return_path=return_path,
        message_id=message_id,
        authentication_results=auth_res,
        received_lines=received[:12],
        raw_headers_sample=headers_sample[:8000],
        body_plain=body_plain,
        body_html=body_html,
        attachments=attachments,
        all_urls=all_urls,
    )


def domain_from_address(addr_field: str) -> str | None:
    if not addr_field:
        return None
    _, email = parseaddr(addr_field)
    if "@" in email:
        return email.split("@", 1)[1].lower().strip()
    return None

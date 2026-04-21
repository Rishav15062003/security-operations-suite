"""
Heuristic + network phishing / URL risk analysis (no paid API required).

Combines: SSL/TLS, DNS, redirects, typosquatting, IDN abuse, keyword patterns,
IP hosts, suspicious TLDs, URL structure, and rule-based narrative (AI-style summary).
"""
from __future__ import annotations

import ipaddress
import os
import re
import socket
import ssl
import unicodedata
from datetime import datetime, timezone
from urllib.parse import parse_qs, unquote, urlparse

import httpx

from .models import PhishingReport, PhishingSignal, RiskVerdict

# --- Known brand apex domains for typosquat / homoglyph checks (expandable) ---
BRAND_DOMAINS: frozenset[str] = frozenset(
    {
        "paypal.com",
        "paypal.de",
        "google.com",
        "gmail.com",
        "microsoft.com",
        "live.com",
        "outlook.com",
        "office.com",
        "amazon.com",
        "amazon.co.uk",
        "apple.com",
        "icloud.com",
        "facebook.com",
        "instagram.com",
        "netflix.com",
        "linkedin.com",
        "twitter.com",
        "x.com",
        "chase.com",
        "bankofamerica.com",
        "wellsfargo.com",
        "citibank.com",
        "stripe.com",
        "coinbase.com",
        "binance.com",
        "dropbox.com",
        "docusign.com",
        "adobe.com",
        "norton.com",
        "mcafee.com",
        "irs.gov",
        "gov.uk",
    }
)

# Cheap / abuse-prone TLDs (heuristic, not exhaustive)
SUSPICIOUS_TLDS: frozenset[str] = frozenset(
    {
        "tk",
        "ml",
        "ga",
        "cf",
        "gq",
        "xyz",
        "top",
        "work",
        "click",
        "link",
        "zip",
        "mov",
        "rest",
        "buzz",
        "gq",
        "cam",
        "bar",
        "beauty",
        "autos",
    }
)

SHORTENER_HOSTS: frozenset[str] = frozenset(
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "buff.ly",
        "is.gd",
        "tiny.cc",
        "rebrand.ly",
        "cutt.ly",
        "short.link",
        "rb.gy",
    }
)

SUSPICIOUS_PATH_KEYWORDS: frozenset[str] = frozenset(
    {
        "login",
        "signin",
        "sign-in",
        "verify",
        "verification",
        "confirm",
        "account",
        "update",
        "secure",
        "suspended",
        "locked",
        "password",
        "passwd",
        "wallet",
        "billing",
        "invoice",
        "payment",
        "auth",
        "oauth",
        "token",
        "reset",
        "recover",
        "validate",
        "kyc",
        "support",
        "helpdesk",
        "security-alert",
        "webscr",
        "cmd",
    }
)

SUSPICIOUS_QUERY_KEYS: frozenset[str] = frozenset(
    {
        "redirect",
        "url",
        "next",
        "dest",
        "destination",
        "continue",
        "return",
        "returnurl",
        "goto",
        "target",
    }
)

# Common phishing lure terms in path/query (English)
LURE_TERMS: frozenset[str] = frozenset(
    {
        "urgent",
        "action-required",
        "unusual-activity",
        "unauthorized",
        "click-here",
        "your-account",
        "verify-now",
        "document",
        "invoice",
        "tax-refund",
        "gift-card",
        "prize",
        "winner",
        "crypto",
        "bitcoin",
    }
)

# Homoglyph / confusable: map lookalikes to ASCII for brand comparison
_CONFUSABLE_MAP = str.maketrans(
    {
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "х": "x",
        "у": "y",
        "і": "i",
        "ј": "j",
        "ѕ": "s",
        "ԁ": "d",
        "ɡ": "g",
        "ɑ": "a",
        "０": "0",
        "１": "1",
        "２": "2",
        "３": "3",
        "４": "4",
        "５": "5",
        "６": "6",
        "７": "7",
        "８": "8",
        "９": "9",
    }
)

URL_IN_TEXT = re.compile(
    r"(?i)\b(?:https?://|www\.)[^\s<>\'\"`]+|\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b",
)


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        return _levenshtein(b, a)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        cur = [i + 1]
        for j, cb in enumerate(b):
            ins = cur[j] + 1
            delete = prev[j + 1] + 1
            sub = prev[j] + (ca != cb)
            cur.append(min(ins, delete, sub))
        prev = cur
    return prev[-1]


def _fold_domain(s: str) -> str:
    s = unicodedata.normalize("NFKC", s).lower().translate(_CONFUSABLE_MAP)
    return s.encode("ascii", "ignore").decode("ascii")


_MULTI_TLD = frozenset(
    {
        "co.uk",
        "co.jp",
        "co.kr",
        "co.nz",
        "co.za",
        "com.au",
        "com.br",
        "com.cn",
        "com.mx",
        "com.tw",
        "com.hk",
        "com.sg",
        "com.ar",
        "ne.jp",
        "or.jp",
        "gov.uk",
        "ac.uk",
        "net.au",
    }
)


def apex_domain(hostname: str) -> str:
    h = hostname.lower().strip(".")
    parts = h.split(".")
    if len(parts) < 2:
        return h
    pair = ".".join(parts[-2:])
    if pair in _MULTI_TLD and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _normalize_url(raw: str) -> str:
    t = raw.strip()
    if not t:
        return ""
    if t.lower().startswith("www."):
        t = "http://" + t
    if "://" not in t:
        if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?", t):
            t = "http://" + t
    return t


def extract_urls_and_emails(text: str) -> tuple[list[str], list[str]]:
    urls: list[str] = []
    emails: list[str] = []
    for m in URL_IN_TEXT.finditer(text or ""):
        s = m.group(0).rstrip(").,;]")
        if "@" in s and "://" not in s:
            emails.append(s)
        else:
            urls.append(_normalize_url(s))
    # dedupe preserve order
    seen: set[str] = set()
    u2: list[str] = []
    for u in urls:
        if u and u not in seen:
            seen.add(u)
            u2.append(u)
    e2: list[str] = []
    seen_e: set[str] = set()
    for e in emails:
        if e.lower() not in seen_e:
            seen_e.add(e.lower())
            e2.append(e)
    return u2, e2


def _add(signals: list[PhishingSignal], code: str, sev: str, title: str, detail: str, w: int) -> None:
    signals.append(PhishingSignal(code=code, severity=sev, title=title, detail=detail, weight=w))


def _score_signals(signals: list[PhishingSignal]) -> int:
    total = 0
    for s in signals:
        total += max(0, s.weight)
    return min(100, total)


def _verdict_from_score(score: int) -> RiskVerdict:
    if score <= 12:
        return RiskVerdict.LIKELY_SAFE
    if score <= 28:
        return RiskVerdict.LOW_RISK
    if score <= 45:
        return RiskVerdict.MIXED
    if score <= 65:
        return RiskVerdict.SUSPICIOUS
    return RiskVerdict.LIKELY_PHISHING


def _check_ip_literal(host: str, signals: list[PhishingSignal]) -> None:
    try:
        ipaddress.ip_address(host)
        _add(
            signals,
            "host_is_ip",
            "high",
            "Host is a raw IP address",
            "Phishing often uses IPs instead of domains to evade reputation systems.",
            22,
        )
    except ValueError:
        pass


def _check_dns(host: str, signals: list[PhishingSignal]) -> None:
    try:
        socket.getaddrinfo(host, None, socket.AF_UNSPEC)
    except OSError as e:
        _add(
            signals,
            "dns_fail",
            "medium",
            "Hostname does not resolve (DNS failure)",
            str(e)[:200],
            15,
        )


def _check_ssl(host: str, port: int, signals: list[PhishingSignal]) -> None:
    if port != 443:
        return
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    _add(signals, "ssl_no_cert", "high", "No peer certificate presented", "", 18)
                    return
                not_after = cert.get("notAfter")
                if not_after:
                    try:
                        exp = ssl.cert_time_to_seconds(not_after)
                        days = (exp - datetime.now(timezone.utc).timestamp()) / 86400
                        if days < 0:
                            _add(
                                signals,
                                "ssl_expired",
                                "high",
                                "TLS certificate is expired",
                                f"Expired approximately {int(-days)} days ago.",
                                20,
                            )
                        elif days < 14:
                            _add(
                                signals,
                                "ssl_expiring",
                                "low",
                                "TLS certificate expires soon",
                                f"Expires in about {int(days)} days.",
                                6,
                            )
                    except (ValueError, OSError):
                        pass
                subj = dict(x[0] for x in cert.get("subject", ()))
                cn = subj.get("commonName", "")
                names: set[str] = set()
                if cn:
                    names.add(cn.lower())
                for t, v in cert.get("subjectAltName", ()) or ():
                    if t == "DNS" and v:
                        names.add(v.lower())
                hl = host.lower()
                ok = False
                if hl in names:
                    ok = True
                else:
                    for n in names:
                        if n.startswith("*.") and hl.endswith(n[1:]) and hl.count(".") >= n.count(".") - 1:
                            ok = True
                            break
                if not ok and names:
                    _add(
                        signals,
                        "ssl_name_mismatch",
                        "high",
                        "Certificate hostname does not match",
                        f"Expected {host}; cert CN/SAN: {', '.join(sorted(names))[:300]}",
                        24,
                    )
    except ssl.SSLError as e:
        _add(
            signals,
            "ssl_error",
            "high",
            "TLS handshake or verification failed",
            str(e)[:220],
            20,
        )
    except OSError as e:
        _add(
            signals,
            "ssl_connect_fail",
            "medium",
            "Could not establish TLS to port 443",
            str(e)[:200],
            12,
        )


def _check_scheme_port(parsed, signals: list[PhishingSignal]) -> None:
    if parsed.scheme.lower() == "http":
        _add(
            signals,
            "http_not_https",
            "medium",
            "URL uses HTTP (not HTTPS)",
            "Credentials and tokens can be intercepted in transit.",
            14,
        )
    if parsed.port and parsed.port not in (80, 443):
        _add(
            signals,
            "nonstandard_port",
            "medium",
            f"Non-standard port {parsed.port}",
            "Unusual ports are sometimes used to bypass filters or mimic services.",
            10,
        )


def _check_executable_extensions(path: str, signals: list[PhishingSignal]) -> None:
    risky = (".exe", ".scr", ".bat", ".cmd", ".msi", ".ps1", ".vbs", ".jar", ".dmg", ".apk")
    for seg in path.split("/"):
        sl = seg.lower()
        for ext in risky:
            if sl.endswith(ext):
                _add(
                    signals,
                    f"ext{ext.replace('.', '_')}",
                    "high",
                    f"Risky file extension in path segment: {ext}",
                    "Malware and phishing sometimes use executable-like names in URLs.",
                    14,
                )
                return


def _check_noisy_subdomain(host: str, signals: list[PhishingSignal]) -> None:
    parts = host.split(".")
    if len(parts) < 3:
        return
    first = parts[0]
    if len(first) >= 16 and sum(1 for c in first if c.isdigit() or c in "abcdef") >= len(first) * 0.6:
        _add(
            signals,
            "random_subdomain",
            "medium",
            "Long hex-like or random-looking subdomain",
            "Sometimes used for disposable phishing hosts.",
            9,
        )


def _check_structure(parsed, signals: list[PhishingSignal]) -> None:
    host = (parsed.hostname or "").lower()
    if not host:
        return
    labels = host.split(".")
    if len(labels) > 4:
        _add(
            signals,
            "deep_subdomain",
            "low",
            "Many subdomain labels",
            f"{len(labels)} labels — sometimes used to imitate legitimate paths.",
            6,
        )
    _check_executable_extensions(parsed.path, signals)
    _check_noisy_subdomain(host, signals)

    if len(parsed.query) > 400:
        _add(signals, "long_query", "low", "Very long query string", "May encode hidden redirects or tokens.", 5)
    if "@" in parsed.path or "%40" in (parsed.path + parsed.query).lower():
        _add(
            signals,
            "credential_in_url",
            "high",
            "URL contains @ or encoded @ (credential obfuscation)",
            "Classic technique to hide the real host after a fake userinfo section.",
            25,
        )
    full_lower = unquote(parsed.path + "?" + parsed.query).lower()
    if full_lower.count("http://") + full_lower.count("https://") > 1:
        _add(signals, "nested_url", "high", "Nested http(s) strings in path/query", "May hide the true destination.", 18)
    if re.search(r"%25[0-9a-f]{2}", parsed.path + parsed.query, re.I):
        _add(signals, "double_encoding", "medium", "Double-encoded sequences in URL", "Used to evade filters.", 10)
    kw_hits = [kw for kw in SUSPICIOUS_PATH_KEYWORDS if kw in full_lower]
    for i, kw in enumerate(kw_hits[:5]):
        _add(
            signals,
            f"kw_{kw}",
            "medium",
            f"Sensitive keyword in path/query: “{kw}”",
            "Common in credential-harvesting pages.",
            max(4, 8 - i),
        )
    lure_hits = [t for t in LURE_TERMS if t.replace("-", "") in full_lower.replace("-", "")]
    for term in lure_hits[:4]:
        _add(
            signals,
            f"lure_{term}",
            "medium",
            f"Lure-style term: “{term}”",
            "Often appears in social-engineering pages.",
            6,
        )
    qs = parse_qs(parsed.query)
    for k in qs:
        kl = k.lower()
        if kl in SUSPICIOUS_QUERY_KEYS:
            _add(
                signals,
                f"open_redirect_{kl}",
                "medium",
                f"Open-redirect style query key: {k}",
                "May chain to a malicious site.",
                9,
            )
            break


def _check_tld(host: str, signals: list[PhishingSignal]) -> None:
    apex = apex_domain(host)
    tld = apex.split(".")[-1] if "." in apex else ""
    if tld in SUSPICIOUS_TLDS:
        _add(
            signals,
            "suspicious_tld",
            "medium",
            f"High-risk TLD: .{tld}",
            "Some TLDs are cheap and frequently abused.",
            12,
        )


def _check_typosquat_brand(host: str, signals: list[PhishingSignal]) -> None:
    apex = apex_domain(host)
    folded = _fold_domain(apex)
    for brand in BRAND_DOMAINS:
        b = _fold_domain(brand)
        if folded == b:
            return
        if len(folded) < 4 or len(b) < 4:
            continue
        d = _levenshtein(folded, b)
        if 0 < d <= 2:
            _add(
                signals,
                "typosquat_brand",
                "critical",
                f"Domain is very similar to “{brand}” (edit distance {d})",
                "Possible typosquatting or homoglyph attack.",
                35,
            )
            return


def _check_idn(host: str, signals: list[PhishingSignal]) -> None:
    if "xn--" not in host.lower():
        return
    try:
        decoded = host.encode().decode("idna")
        if any(ord(c) > 127 for c in decoded):
            _add(
                signals,
                "punycode_idn",
                "medium",
                "Internationalized domain (punycode / IDN)",
                f"Decoded: {decoded[:120]} — verify visually; homograph attacks use lookalike scripts.",
                12,
            )
    except (UnicodeError, UnicodeDecodeError):
        _add(signals, "idn_parse", "low", "IDN / punycode present", "Inspect the domain carefully.", 5)


def _check_shortener(host: str, signals: list[PhishingSignal]) -> None:
    h = host.lower()
    if h in SHORTENER_HOSTS or any(h.endswith("." + s) for s in SHORTENER_HOSTS):
        _add(
            signals,
            "url_shortener",
            "medium",
            "Known URL shortener",
            "Destination is hidden until redirect — inspect the final URL after analysis.",
            10,
        )


def _follow_redirects(url: str, signals: list[PhishingSignal]) -> None:
    try:
        with httpx.Client(follow_redirects=True, timeout=15.0, verify=True) as client:
            r = client.head(url, follow_redirects=True)
            if r.status_code >= 400:
                r = client.get(url, follow_redirects=True, timeout=15.0)
            hops = len(r.history)
            if hops >= 4:
                _add(
                    signals,
                    "long_redirect",
                    "medium",
                    f"Long redirect chain ({hops} hops)",
                    "May launder traffic through multiple domains.",
                    10 + min(10, hops),
                )
            final = urlparse(str(r.url))
            init = urlparse(url)
            if final.hostname and init.hostname and apex_domain(final.hostname) != apex_domain(init.hostname):
                _add(
                    signals,
                    "redirect_domain_change",
                    "high",
                    "Redirect changes apex domain",
                    f"Started at {apex_domain(init.hostname)}, ended at {apex_domain(final.hostname)}.",
                    22,
                )
    except httpx.HTTPError as e:
        _add(signals, "head_redirect_fail", "info", "Could not follow redirects", str(e)[:160], 3)
    except Exception as e:
        _add(signals, "head_redirect_fail", "info", "Redirect check skipped", str(e)[:120], 2)


def _build_ai_summary(
    score: int,
    verdict: RiskVerdict,
    signals: list[PhishingSignal],
    url: str,
    *,
    vt_addon: str = "",
    eml_note: str = "",
) -> str:
    lines = [
        "Phishing risk assessment (heuristic + TLS/DNS/redirect + optional EML/VirusTotal).",
        f"Overall risk score: {score}/100 — verdict: {verdict.value.replace('_', ' ')}.",
        f"Primary URL: {url or '(none — see EML/attachments)'}",
    ]
    if eml_note:
        lines.append(eml_note)
    if vt_addon.strip():
        lines.extend(["", "VirusTotal:", vt_addon.strip()])
    lines.extend(
        [
            "",
            "Signals (highest impact first):",
        ]
    )
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_s = sorted(signals, key=lambda x: (-x.weight, sev_order.get(x.severity, 5)))
    for s in sorted_s[:18]:
        lines.append(f"  • [{s.severity.upper()}] {s.title}: {s.detail[:200]}")
    if len(sorted_s) > 18:
        lines.append(f"  … and {len(sorted_s) - 18} more signals.")
    lines.extend(
        [
            "",
            "Recommendations:",
            "  • Prefer official apps or typed-in domains for banking and email.",
            "  • If in doubt, open a new browser tab and navigate to the service manually.",
            "  • This tool uses heuristics; it can flag benign sites and miss novel phishing.",
        ]
    )
    return "\n".join(lines)


def analyze_url(
    raw_input: str,
    *,
    follow_redirects: bool = True,
    primary_url_index: int = 0,
) -> PhishingReport:
    """
    Analyze pasted text: extracts URLs (and notes emails). Uses first URL as primary unless empty.
    """
    text = raw_input or ""
    urls, emails = extract_urls_and_emails(text)
    if not urls:
        # treat whole line as URL attempt
        candidate = _normalize_url(text.strip().split()[0] if text.strip() else "")
        if candidate and "://" in candidate:
            urls = [candidate]
    if not urls:
        signals: list[PhishingSignal] = []
        if emails:
            _add(
                signals,
                "email_only",
                "info",
                "Email address(es) found but no http(s) URL",
                "Paste a full URL or text containing https://… for deeper checks.",
                0,
            )
        return PhishingReport(
            input_text=text,
            primary_url="",
            normalized_url="",
            host="",
            risk_score=min(100, 15 if emails else 0),
            verdict=RiskVerdict.LOW_RISK if emails else RiskVerdict.LIKELY_SAFE,
            signals=signals,
            ai_summary="Paste a URL (https://…) or text containing a link. Optional: raw email with links.",
            extracted_urls=[],
        )

    if primary_url_index < 0 or primary_url_index >= len(urls):
        primary_url_index = 0
    url = urls[primary_url_index]
    parsed = urlparse(url)
    host = parsed.hostname or ""
    signals = []

    if emails:
        _add(
            signals,
            "context_email",
            "info",
            "Email address(es) present in input",
            "Verify sender independently; pasted “From” headers can be spoofed.",
            2,
        )

    if not host:
        _add(signals, "bad_url", "high", "Could not parse hostname", url[:200], 25)
        score = _score_signals(signals)
        v = _verdict_from_score(score)
        return PhishingReport(
            input_text=text,
            primary_url=url,
            normalized_url=url,
            host="",
            risk_score=score,
            verdict=v,
            signals=signals,
            ai_summary=_build_ai_summary(score, v, signals, url),
            extracted_urls=urls,
        )

    _check_ip_literal(host, signals)
    _check_scheme_port(parsed, signals)
    _check_tld(host, signals)
    _check_shortener(host, signals)
    _check_typosquat_brand(host, signals)
    _check_idn(host, signals)
    _check_structure(parsed, signals)
    _check_dns(host, signals)
    if parsed.scheme.lower() == "https" or parsed.port == 443:
        _check_ssl(host, parsed.port or 443, signals)
    elif parsed.scheme.lower() == "http":
        _add(signals, "no_tls_check", "info", "Skipped deep TLS check (not HTTPS)", "Enable HTTPS on the site or use https:// URL.", 0)

    if follow_redirects and parsed.scheme.lower().startswith("http"):
        _follow_redirects(url, signals)

    score = _score_signals(signals)
    v = _verdict_from_score(score)
    return PhishingReport(
            input_text=text,
            primary_url=url,
            normalized_url=url,
            host=host,
            risk_score=score,
            verdict=v,
            signals=sorted(signals, key=lambda s: -s.weight),
            ai_summary=_build_ai_summary(score, v, signals, url),
            extracted_urls=urls,
        )


def analyze_phishing(
    raw_text: str,
    *,
    eml_path: str | None = None,
    vt_api_key: str | None = None,
    use_virustotal: bool = True,
    follow_redirects: bool = True,
) -> PhishingReport:
    """
    Full pipeline: optional .eml file, pasted text, optional VirusTotal (URLs + attachment hashes).
    """
    from pathlib import Path

    from .eml_checks import analyze_eml_headers_and_attachments
    from .eml_parser import parse_eml_file
    from .virustotal import run_vt_batch

    combined = (raw_text or "").strip()
    extra: list[PhishingSignal] = []
    eml = None
    eml_path_str: str | None = None
    vt_text = ""

    if eml_path:
        p = Path(eml_path)
        if p.is_file():
            eml_path_str = str(p.resolve())
            eml = parse_eml_file(p)
            combined = (combined + "\n" + eml.combined_text_for_analysis()).strip()
            extra.extend(analyze_eml_headers_and_attachments(eml))

    if use_virustotal:
        vt_key = (vt_api_key or os.environ.get("VT_API_KEY") or "").strip()
    else:
        vt_key = ""
    urls_for_vt: list[str] = []
    att_for_vt: list[tuple[str, str]] = []

    if eml:
        u1, _ = extract_urls_and_emails(combined)
        seen: set[str] = set()
        for u in u1 + eml.all_urls:
            if u not in seen:
                seen.add(u)
                urls_for_vt.append(u)
        att_for_vt = [(a.filename, a.sha256) for a in eml.attachments]
    else:
        u1, _ = extract_urls_and_emails(combined)
        urls_for_vt = list(dict.fromkeys(u1))

    if vt_key:
        vt_sigs, vt_text = run_vt_batch(urls_for_vt, att_for_vt, vt_key)
        for d in vt_sigs:
            extra.append(
                PhishingSignal(
                    code=d["code"],
                    severity=d["severity"],
                    title=d["title"],
                    detail=d["detail"],
                    weight=int(d.get("weight", 0)),
                )
            )

    urls_extracted, emails_extracted = extract_urls_and_emails(combined)
    if not urls_extracted and eml and eml.all_urls:
        urls_extracted = list(dict.fromkeys(eml.all_urls))

    if not urls_extracted:
        score = _score_signals(extra)
        v = _verdict_from_score(score)
        eml_note = ""
        if eml:
            eml_note = f"EML subject: {eml.subject[:200]}"
        rep = PhishingReport(
            input_text=combined,
            primary_url="",
            normalized_url="",
            host="",
            risk_score=min(100, score),
            verdict=v,
            signals=sorted(extra, key=lambda s: -s.weight),
            ai_summary=_build_ai_summary(score, v, extra, "", vt_addon=vt_text, eml_note=eml_note),
            extracted_urls=urls_extracted,
            eml_path=eml_path_str,
            eml_subject=eml.subject if eml else None,
            eml_from=eml.from_raw if eml else None,
            eml_to=eml.to_raw if eml else None,
            eml_reply_to=eml.reply_to if eml else None,
            eml_return_path=eml.return_path if eml else None,
            eml_attachments=list(eml.attachments) if eml else [],
            virustotal_text=vt_text,
        )
        return rep

    base = analyze_url(combined, follow_redirects=follow_redirects)
    merged = extra + base.signals
    score = _score_signals(merged)
    v = _verdict_from_score(score)
    eml_note = ""
    if eml:
        eml_note = f"EML subject: {eml.subject[:200]}"

    base.signals = sorted(merged, key=lambda s: -s.weight)
    base.risk_score = min(100, score)
    base.verdict = v
    base.input_text = combined
    base.extracted_urls = list(dict.fromkeys(urls_extracted))
    base.ai_summary = _build_ai_summary(score, v, merged, base.primary_url, vt_addon=vt_text, eml_note=eml_note)
    base.eml_path = eml_path_str
    base.eml_subject = eml.subject if eml else None
    base.eml_from = eml.from_raw if eml else None
    base.eml_to = eml.to_raw if eml else None
    base.eml_reply_to = eml.reply_to if eml else None
    base.eml_return_path = eml.return_path if eml else None
    base.eml_attachments = list(eml.attachments) if eml else []
    base.virustotal_text = vt_text
    return base

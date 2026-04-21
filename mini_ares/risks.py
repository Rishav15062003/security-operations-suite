"""
Rule-based risk reasoning (no external LLM) — "why this is risky" strings.
"""
from __future__ import annotations

from typing import Optional


def explain_open_port(port: int, protocol: str = "tcp") -> str:
    """Human-readable rationale for exposed ports."""
    p = {
        21: "FTP often transmits credentials in cleartext and is a common brute-force target.",
        22: "SSH is an administrative entry point; exposure to untrusted networks increases brute-force and exploit risk.",
        23: "Telnet is unencrypted; any credential or session data can be intercepted.",
        25: "SMTP exposure can enable spam relay or reconnaissance if misconfigured.",
        53: "DNS services exposed broadly can be abused for amplification or cache poisoning if not hardened.",
        80: "HTTP without TLS may leak data in transit; often indicates legacy or misconfigured apps.",
        110: "POP3 may expose mail credentials if not protected by TLS.",
        143: "IMAP exposure can widen mail compromise surface if weak auth or no TLS.",
        443: "HTTPS is expected for web apps; still verify certificate validity, TLS versions, and app vulnerabilities.",
        445: "SMB to the Internet is frequently targeted (ransomware, EternalBlue-class issues); should be restricted.",
        3306: "MySQL directly reachable from the Internet is a high-value target for credential attacks and exploits.",
        3389: "RDP exposed to the Internet is a top vector for ransomware and credential stuffing.",
        5432: "PostgreSQL on the public Internet invites automated scanning and exploitation attempts.",
        6379: "Redis without auth/TLS has led to many compromises; public exposure is dangerous.",
        27017: "MongoDB has historically been exposed without auth; public access is a critical risk.",
        8080: "Alternate HTTP ports often host admin panels, dev servers, or proxies with weaker hardening.",
        8443: "HTTPS alternate port — verify it is intentional and patched like primary web.",
        9000: "Often SonarQube, Jenkins, or app servers; may expose management UIs without strong auth.",
    }
    return p.get(
        port,
        f"Unexpected or uncommon service on TCP {port}; verify intent, patch level, and firewall scope. "
        f"Attackers routinely scan for open ports to fingerprint and exploit services.",
    )


def explain_subdomain(name: str) -> Optional[str]:
    """Flag naming patterns that often indicate sensitive or high-value targets."""
    lower = name.lower()
    hints = [
        (("admin", "adm", "portal-admin"), "Admin-style hostnames often gate privileged functions and attract targeted attacks."),
        (("vpn", "remote", "citrix"), "Remote access entry points are valuable targets for credential attacks and exploits."),
        (("jenkins", "gitlab", "ci", "build"), "CI/CD and build systems may leak secrets or allow pipeline abuse if exposed."),
        (("db", "database", "sql", "mysql", "postgres"), "Database hostnames suggest data-plane exposure; verify strict network controls."),
        (("api", "graphql", "rest"), "APIs may expose business logic; ensure auth, rate limits, and schema hardening."),
        (("dev", "test", "staging", "uat"), "Non-production systems are often weaker patched and may hold production-like data."),
        (("mail", "smtp", "owa", "exchange"), "Mail and collaboration endpoints are phishing and password-spray magnets."),
    ]
    for keywords, msg in hints:
        if any(k in lower for k in keywords):
            return msg
    return None


def explain_tech_header(server: str, powered: str) -> str:
    parts = []
    s = (server or "").lower()
    if "apache" in s or "nginx" in s:
        parts.append("Web server banner disclosure helps attackers choose version-specific exploits.")
    if "iis" in s or "microsoft" in s:
        parts.append("IIS/Windows stacks should stay fully patched; historically targeted for web shells and RCE.")
    if "php" in powered.lower():
        parts.append("PHP stacks need disciplined patching; outdated versions are common breach paths.")
    if "asp.net" in powered.lower():
        parts.append("ASP.NET apps should use current frameworks and validate auth on all endpoints.")
    if not parts:
        return (
            "Technology fingerprinting narrows exploit choice for attackers. "
            "Reduce banner leakage where possible and keep components updated."
        )
    return " ".join(parts)


def explain_insecure_redirect_or_http(host: str) -> str:
    return (
        f"Cleartext HTTP to {host} can leak session tokens and credentials. "
        "Enforce HTTPS with HSTS and redirect HTTP to HTTPS where appropriate."
    )


def severity_for_port(port: int) -> str:
    critical = {445, 3389, 23}
    high = {22, 3306, 5432, 6379, 27017, 21}
    medium = {25, 110, 143, 8080, 8443, 9000, 53}
    if port in critical:
        return "critical"
    if port in high:
        return "high"
    if port in medium:
        return "medium"
    if port in (80, 443):
        return "low"
    return "medium"

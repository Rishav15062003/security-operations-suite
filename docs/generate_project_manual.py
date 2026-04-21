"""
Generate docs/Security_Operations_Suite_Project_Manual.pdf (project overview + FAQ).
Run from repo root: python docs/generate_project_manual.py
"""
from __future__ import annotations

import sys
from datetime import date
from pathlib import Path

try:
    from fpdf import FPDF
except ImportError:
    print("Install fpdf2: pip install fpdf2", file=sys.stderr)
    raise


ROOT = Path(__file__).resolve().parents[1]
OUT = Path(__file__).resolve().parent / "Security_Operations_Suite_Project_Manual.pdf"


class ManualPDF(FPDF):
    def __init__(self) -> None:
        super().__init__()
        self.set_margins(18, 18, 18)
        self.set_auto_page_break(auto=True, margin=15)

    def footer(self) -> None:
        self.set_y(-14)
        self.set_font("Helvetica", "I", 8)
        self.cell(0, 10, f"Page {self.page_no()}", align="C")

    def section(self, title: str) -> None:
        self.set_font("Helvetica", "B", 14)
        self.multi_cell(self.epw, 8, title)
        self.ln(2)

    def body_text(self, text: str) -> None:
        self.set_font("Helvetica", "", 10)
        self.multi_cell(self.epw, 5, text)
        self.ln(3)

    def bullet_list(self, items: list[str]) -> None:
        self.set_font("Helvetica", "", 10)
        for item in items:
            self.multi_cell(self.epw, 5, f"- {item}")
        self.ln(3)


def build() -> None:
    pdf = ManualPDF()
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 20)
    pdf.multi_cell(pdf.epw, 10, "Security Operations Suite")
    pdf.set_font("Helvetica", "", 12)
    pdf.multi_cell(pdf.epw, 6, "Blue Team - Security Analysis Desktop Application")
    pdf.ln(8)
    pdf.set_font("Helvetica", "I", 10)
    pdf.multi_cell(pdf.epw, 5, f"Generated: {date.today().isoformat()}")
    pdf.multi_cell(pdf.epw, 5, f"Repository root: {ROOT}")
    pdf.ln(10)

    pdf.section("1. Purpose")
    pdf.body_text(
        "This project is a unified Security Operations Suite: a cross-platform desktop GUI (CustomTkinter) "
        "that bundles log-based threat detection, cloud misconfiguration scanning, external attack-surface "
        "reconnaissance, phishing analysis, and network traffic anomaly detection. It is intended for triage "
        "and awareness, not as a full replacement for a SIEM, IDS, or enterprise cloud posture management suite."
    )

    pdf.section("2. How the application is built")
    pdf.body_text(
        "Entry point: run_gui.py imports threat_analyzer.app_ui.launch(), which instantiates SecuritySuiteApp "
        "from threat_analyzer.suite_app. The main window uses CTkTabview with five tabs: Log analysis, "
        "Cloud security, Attack surface, Phishing detector, Network traffic. Each tab embeds a dedicated frame "
        "module (LogAnalysisFrame, CloudScanFrame, AttackSurfaceFrame, PhishingFrame, NetworkTrafficFrame)."
    )
    pdf.body_text(
        "Distribution: PyInstaller bundles the GUI into a single Windows executable (SecuritySuite.exe) via "
        "SecuritySuite.spec. The spec collects hidden imports for threat_analyzer, cloud_scanner, mini_ares, "
        "phishing_detector, network_traffic_analyzer, scapy, sklearn, cloud SDKs, and related dependencies. "
        "Build command (see spec header): pyinstaller --noconfirm SecuritySuite.spec"
    )
    pdf.body_text(
        "Development run: from the repository root, execute: python run_gui.py "
        "(sys.path is adjusted for non-frozen runs so local packages import correctly)."
    )

    pdf.section("3. Technology stack")
    pdf.bullet_list(
        [
            "Python 3.x",
            "CustomTkinter (dark-themed GUI)",
            "Rule engines + heuristics (pure Python in each module)",
            "scikit-learn (optional ML for log anomaly in threat_analyzer)",
            "Scapy (optional) for pcap/live capture in network_traffic_analyzer",
            "AWS (boto3) and Azure SDKs for live cloud scanning",
            "External CLI tools invoked by mini_ares (e.g. nmap, subfinder) when installed",
        ]
    )

    pdf.section("4. Package and module map")
    pdf.body_text(
        "threat_analyzer/ - Core log threat analysis: parser.py reads auth/syslog-style logs into ParsedEvent; "
        "engine.py runs detectors registered in registry.py with AnalysisConfig thresholds; detectors.py, "
        "detectors_advanced.py, detectors_wireshark.py implement rules; ml_anomaly.py optional Isolation Forest; "
        "app_ui.py LogAnalysisFrame; suite_app.py SecuritySuiteApp shell; dashboard.py, cli.py, report_html.py, "
        "log_category_ai.py for narratives and HTML export."
    )
    pdf.body_text(
        "network_traffic_analyzer/ - FlowRecord model, analyzer.py heuristics (reconnaissance, brute force, DDoS, "
        "DNS, exfiltration, protocol anomalies, ARP, HTTP UA, beaconing, traffic pattern baseline, port misuse, "
        "lateral movement), log_parser.py for Zeek/firewall text, dns_heuristics.py, http_heuristics.py, ip_utils.py."
    )
    pdf.body_text(
        "cloud_scanner/ - AWS/Azure scanners and offline JSON policy analysis; models, remediation text, "
        "reporting and HTML reports."
    )
    pdf.body_text(
        "mini_ares/ - Attack surface: subdomain discovery, nmap-based port/service scans, technology fingerprinting, "
        "optional FastAPI in api.py; coordinated via toolchain and deep_scan."
    )
    pdf.body_text(
        "phishing_detector/ - URL/text/.eml heuristics, optional VirusTotal integration, eml parsing."
    )
    pdf.body_text(
        "tests/ - Unit tests (e.g. network traffic analyzer, deep scan parse). threat_analyzer/cli.py and "
        "cloud_scanner CLI / mini_ares __main__ may exist for headless or alternate entry points."
    )

    pdf.section("5. Rules and conventions (modules)")
    pdf.body_text(
        "Detector registry (threat_analyzer): Each built-in detector has a stable string id (e.g. brute_force, "
        "suspicious_ip) listed in registry.DETECTOR_INFOS with human-readable name and description. "
        "engine.run_analysis() calls add_from(id, lambda) only if AnalysisConfig.enabled_detector_ids is None "
        "or contains that id. Extensions can register EXTENSION_DETECTOR_INFOS and EXTENSION_RUNNERS."
    )
    pdf.body_text(
        "Findings model: threat_analyzer.models.Finding carries severity, category, title, detail, evidence. "
        "Network traffic uses network_traffic_analyzer.models.TrafficFinding with a category string "
        "(reconnaissance, brute_force, ddos_flood, suspicious_ip, unauthorized_access, dns_anomaly, data_exfil, "
        "protocol_anomaly, arp_spoofing, http_behavior, beaconing, traffic_pattern, port_misuse, lateral_movement, "
        "traffic_anomaly, info, general). analyze_flow_records() sorts findings by category order then severity."
    )
    pdf.body_text(
        "Network heuristics: Thresholds are module-level constants in analyzer.py (e.g. port scan counts, "
        "DDoS PPS, beaconing CV). Tuning is code-level; there is no external YAML for NTA thresholds in-tree."
    )
    pdf.body_text(
        "IP classification: network_traffic_analyzer.ip_utils is_private_ipv4 / is_public_ipv4 for RFC1918, "
        "loopback, CGNAT, etc. Many rules require both endpoints to be IPv4-parseable."
    )
    pdf.body_text(
        "Error handling: pcap iteration wraps per-packet decode in try/except so one malformed packet does not "
        "abort the whole file; live sniff prn callback uses the same idea."
    )

    pdf.section("6. User-facing capabilities (summary)")
    pdf.bullet_list(
        [
            "Log analysis: multi-detector rule engine + optional ML + Wireshark export heuristics; JSON/HTML export.",
            "Cloud: AWS/Azure live APIs or offline JSON (SG, bucket policy, NSG); remediation snippets.",
            "Attack surface: subdomains, ports, tech stack, risk findings via mini_ares.",
            "Phishing: URLs, pasted text, .eml, optional VT.",
            "Network traffic: Zeek/logs/pcap/live capture; Full capabilities tab documents each detector family.",
        ]
    )

    pdf.section("7. Network Traffic Analyzer - detection families (reference)")
    pdf.body_text(
        "Implemented in network_traffic_analyzer/analyze_flow_records(). Categories include: reconnaissance "
        "(port scans, SYN-heavy, ping sweeps, horizontal scans); brute-force style connection rates to login ports; "
        "DDoS/flood by PPS; suspicious IP behavior (public to private patterns); unauthorized access attempts; "
        "DNS volume and suspicious FQDN shapes; data exfil heuristics (private to public byte volume); protocol "
        "anomalies; ARP IP/MAC conflicts; HTTP User-Agent and cleartext HTTP behavior; beaconing (regular small "
        "packets to same peer); traffic pattern vs baseline (peak vs trimmed median PPS); port misuse (HTTP on "
        "unusual ports, TLS ClientHello heuristics); lateral movement (many internal targets from one internal host); "
        "general traffic/volume anomalies. Exact thresholds are constants in analyzer.py."
    )

    pdf.section("8. Data flow (typical)")
    pdf.bullet_list(
        [
            "Logs: file -> parse_file / parse -> ParsedEvent list -> run_analysis -> Finding list -> UI tree + export.",
            "Pcap: PcapReader -> packet_to_flow -> FlowRecord list -> analyze_flow_records -> TrafficReport.",
            "Cloud: credentials/config -> cloud_scanner scanners -> CloudFinding list -> remediation text.",
        ]
    )

    pdf.section("9. Frequently asked questions")
    faqs = [
        (
            "Why CustomTkinter?",
            "Single-process desktop app, theming, works on Windows and Linux with manageable dependencies.",
        ),
        (
            "Where are detection thresholds?",
            "Log detectors: AnalysisConfig and constants inside detector modules. Network: analyzer.py constants.",
        ),
        (
            "Does the EXE include Python?",
            "PyInstaller bundles the interpreter and collected dependencies into SecuritySuite.exe (large binary).",
        ),
        (
            "Why does HTTPS not show User-Agent in NTA?",
            "Cleartext HTTP is parsed from TCP payloads; TLS encrypts application data, so UA is not visible without decryption.",
        ),
        (
            "Is cloud scanning safe?",
            "It uses read-only API calls per cloud_scanner design; credentials and regions are operator-controlled.",
        ),
        (
            "How to add a new log detector?",
            "Implement a function returning list[Finding], register id in registry if needed, wire engine.run_analysis add_from.",
        ),
        (
            "How to add a network finding?",
            "Add logic in analyze_flow_records(), use a new TrafficFinding code and category; extend cat_order for sort priority.",
        ),
        (
            "What is needed for live capture?",
            "Npcap on Windows or libpcap on Linux; Scapy installed; often administrator/root for raw sockets.",
        ),
        (
            "Where is the phishing rules logic?",
            "phishing_detector/analyzer.py and related helpers; UI in threat_analyzer/phishing_ui.py.",
        ),
        (
            "What about threading?",
            "Long scans (cloud, attack surface) run in background threads so the GUI stays responsive.",
        ),
        (
            "Can I run without cloud credentials?",
            "Yes: use offline JSON in cloud tab, or use other tabs only.",
        ),
    ]
    for q, a in faqs:
        pdf.set_font("Helvetica", "B", 10)
        pdf.multi_cell(pdf.epw, 5, f"Q: {q}")
        pdf.set_font("Helvetica", "", 10)
        pdf.multi_cell(pdf.epw, 5, f"A: {a}")
        pdf.ln(2)

    pdf.section("10. Limitations (important)")
    pdf.body_text(
        "Heuristics produce false positives and false negatives. Network analysis approximates 'requests' as "
        "packet/flow events. Auth success/failure is not visible in raw network flows for most protocols. "
        "Cloud findings depend on API permissions and resource coverage. Attack-surface scans require "
        "appropriate authorization and may invoke third-party tools."
    )

    pdf.section("11. Testing")
    pdf.body_text(
        "Run: python -m unittest discover -s tests -p 'test_*.py' from the repository root. "
        "Add tests alongside new detectors or parsers."
    )

    OUT.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(OUT))
    print(f"Wrote {OUT}")


if __name__ == "__main__":
    build()

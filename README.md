# Security Operations Suite

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-informational.svg)](https://github.com/Rishav15062003/security-operations-suite)
[![Last Commit](https://img.shields.io/github/last-commit/Rishav15062003/security-operations-suite)](https://github.com/Rishav15062003/security-operations-suite/commits/main)
[![Repo Size](https://img.shields.io/github/repo-size/Rishav15062003/security-operations-suite)](https://github.com/Rishav15062003/security-operations-suite)
[![Issues](https://img.shields.io/github/issues/Rishav15062003/security-operations-suite)](https://github.com/Rishav15062003/security-operations-suite/issues)

A unified desktop application for blue-team workflows, combining log threat detection, cloud misconfiguration scanning, attack-surface analysis, phishing checks, and network traffic analytics in one interface.

## Overview

Security Operations Suite is a Python + CustomTkinter application designed for practical SOC-style triage and reporting.

It provides five dedicated modules in a single GUI:

- **Log Analysis**: rule-based and optional ML-assisted anomaly detection on authentication/system logs.
- **Cloud Security**: AWS/Azure misconfiguration checks (plus offline JSON analysis).
- **Attack Surface**: external reconnaissance and risk findings (Mini ARES integration).
- **Phishing Detector**: URL/text/.eml heuristic phishing analysis.
- **Network Traffic Analyzer**: pcap/pcapng, live capture, and text-log traffic heuristics.

## Module Architecture and Rules

### 1) `threat_analyzer` (log intelligence core)

- Parses log events into structured records.
- Runs detectors from `registry.py` through `engine.py` using `AnalysisConfig`.
- Detector execution is controlled by detector IDs and enabled flags.
- Supports optional ML outlier detection via Isolation Forest.
- Exports findings to JSON/HTML from UI.

**Rule model:**
- Detector metadata lives in the registry.
- Engine executes only enabled detectors.
- Findings are categorized and grouped for triage and reporting.

### 2) `network_traffic_analyzer` (traffic intelligence)

- Accepts `.pcap` / `.pcapng` (Scapy), Zeek/firewall text logs, and live captures.
- Converts packets/rows into `FlowRecord` objects.
- Applies category heuristics in `analyzer.py` (e.g., reconnaissance, brute force, DDoS/flood, DNS anomalies, exfiltration, protocol anomalies, ARP spoofing, HTTP behavior, beaconing, traffic-pattern baseline deviations, port misuse, lateral movement).

**Rule model:**
- Each detector emits `TrafficFinding` with category + severity + evidence.
- Findings are sorted by category/severity for analyst readability.
- Most thresholds are constants in `analyzer.py` (code-level tuning).

### 3) `cloud_scanner` (cloud posture checks)

- Scans AWS/Azure using SDK APIs or analyzes offline JSON policy/config exports.
- Produces normalized findings and remediation guidance.
- Supports HTML/JSON export.

### 4) `mini_ares` (attack-surface module)

- Combines passive and active techniques for subdomains, services, and technologies.
- Can use optional external tools (`nmap`, `subfinder`) when available.
- Falls back to built-in logic when tools are missing.

### 5) `phishing_detector` (email/url checks)

- Analyzes URLs, message text, and `.eml` files.
- Runs heuristic indicators and optional VirusTotal-assisted checks.

## Project Layout

```text
run_gui.py                      # main desktop entry point
threat_analyzer/                # log analysis + unified app shell
network_traffic_analyzer/       # packet/log flow heuristics
cloud_scanner/                  # AWS/Azure/offline cloud checks
mini_ares/                      # attack-surface recon engine
phishing_detector/              # phishing analysis logic
tests/                          # unit tests
SecuritySuite.spec              # PyInstaller one-file build spec
build_windows.ps1               # Windows build helper
build_linux.sh                  # Linux build helper
```

## Step-by-Step: Run in Development Mode

### Prerequisites

- Python **3.10+**
- `pip`
- Windows or Linux

### Steps

1. **Open terminal** in the project root (folder containing `run_gui.py`).
2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
3. **Launch the app** (choose one):
   ```bash
   python run_gui.py
   ```
   or
   ```bash
   python -m threat_analyzer
   ```
   Windows convenience option:
   - Double-click `Start Security Suite.bat`

## Step-by-Step: Build Standalone Executable

### Windows

```powershell
.\build_windows.ps1
```

### Linux

```bash
chmod +x build_linux.sh
./build_linux.sh
```

### Output

- Windows: `dist/SecuritySuite.exe`
- Linux: `dist/SecuritySuite`

## Input Support by Module

### Log Analysis

- Linux/SSH auth-style logs (`auth.log`, syslog lines with sshd/pam patterns)
- Wireshark/tshark text exports (CSV/plain summaries)
- `.pcap` / `.pcapng` when Scapy is installed

### Network Traffic Analyzer

- `.pcap` / `.pcapng`
- Zeek `conn.log` / `dns.log` style rows
- iptables/ufw-like plain text rows
- live capture (requires capture permissions + packet capture driver)

## Optional Tooling (Attack Surface)

Attack-surface accuracy improves if these are installed:

- `nmap`
- `subfinder`
- Go (only if building subfinder from source)

Install helpers:

- Windows:
  ```powershell
  powershell -ExecutionPolicy Bypass -File .\scripts\install_mini_ares_tools.ps1
  ```
- Linux:
  ```bash
  bash scripts/install_mini_ares_tools.sh
  ```

## Performance and Limits

- Large pcap files are bounded by a max packet limit (configurable in UI).
- ML stages may be skipped automatically for very large datasets.
- Network findings are heuristic-based and should be validated with environment context.

## Testing

Run the test suite from repo root:

```bash
python -m unittest discover -s tests -p "test_*.py"
```

## Troubleshooting

- **Scapy/capture errors**: ensure dependencies + Npcap/libpcap + elevation where required.
- **Cloud scan errors**: verify credentials, subscription/account scope, and region settings.
- **Tool not found (`nmap`, `subfinder`)**: run installer scripts or add tools to PATH.
- **GUI startup issues**: reinstall requirements and rerun from a clean virtual environment.

## Security and Operational Notes

- This suite is designed for defensive analysis and triage.
- Findings indicate probable risk patterns; they are not guaranteed compromise evidence.
- Always validate critical alerts with corroborating telemetry.

## Quick FAQ

- **Is this a SIEM replacement?**
  - No. It is a practical analyst workstation tool for focused investigations and reporting.
- **Can it run offline?**
  - Core local modules can; cloud/API-enriched features depend on credentials/network.
- **Can I tune detector thresholds?**
  - Yes, mainly in module constants/config classes (especially `analyzer.py` and `AnalysisConfig`).
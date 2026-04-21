"""
Network traffic analyzer: live Scapy capture and offline log / pcap anomaly detection.
"""
from __future__ import annotations

import json
import sys
import threading
import traceback
from pathlib import Path
import platform
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from .app_ui import _FONT_SMALL, install_scrollable_wheel_fix

_FONT_TAB = ("Segoe UI", 14, "bold") if platform.system() == "Windows" else ("Ubuntu", 14, "bold")


def _list_scapy_interfaces() -> list[str]:
    try:
        from scapy.interfaces import get_if_list

        return list(get_if_list())
    except Exception:
        return []


class NetworkTrafficFrame(ctk.CTkFrame):
    def __init__(self, master: ctk.Misc, **kwargs) -> None:
        super().__init__(master, fg_color=("#0a0a12", "#0a0a12"), **kwargs)
        self._last_report = None
        self._last_meta: dict | None = None
        self._file_path = ctk.StringVar(value="")
        self._iface = ctk.StringVar(value="")
        self._duration = ctk.StringVar(value="15")
        self._bpf = ctk.StringVar(value="")
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self._build()

    def _build(self) -> None:
        side = ctk.CTkFrame(self, width=400, corner_radius=0, fg_color=("#1a1a2e", "#1a1a2e"))
        side.grid(row=0, column=0, sticky="nsew")
        side.grid_propagate(False)
        side.grid_rowconfigure(0, weight=1)
        side.grid_columnconfigure(0, weight=1)

        side_scroll = ctk.CTkScrollableFrame(side, fg_color=("#1a1a2e", "#1a1a2e"), corner_radius=0)
        side_scroll.grid(row=0, column=0, sticky="nsew")

        ctk.CTkLabel(
            side_scroll,
            text="Network traffic analyzer",
            font=_FONT_TAB,
            text_color=("#e8e8f0", "#e8e8f0"),
        ).pack(anchor="w", padx=20, pady=(20, 4))
        ctk.CTkLabel(
            side_scroll,
            text="Reconnaissance + volume anomalies (Scapy heuristics)",
            font=_FONT_SMALL,
            text_color=("#8892a6", "#8892a6"),
        ).pack(anchor="w", padx=20, pady=(0, 8))

        ctk.CTkLabel(
            side_scroll,
            text=(
                "Live capture needs Npcap (Windows) or libpcap, and usually Administrator/root. "
                "Offline: Zeek conn.log (TSV), iptables-style SRC=/DST= logs, or generic two-IP lines; "
                "also .pcap / .pcapng."
            ),
            font=("Segoe UI", 10) if platform.system() == "Windows" else ("Ubuntu", 10),
            text_color=("#6b7280", "#6b7280"),
            wraplength=360,
            justify="left",
        ).pack(anchor="w", padx=16, pady=(0, 10))

        self._mode = ctk.StringVar(value="file")
        mf = ctk.CTkFrame(side_scroll, fg_color="transparent")
        mf.pack(fill="x", padx=16, pady=4)
        ctk.CTkRadioButton(mf, text="Offline file (log / pcap)", variable=self._mode, value="file").pack(anchor="w")
        ctk.CTkRadioButton(mf, text="Live capture (this machine)", variable=self._mode, value="live").pack(anchor="w")

        ff = ctk.CTkFrame(side_scroll, fg_color="transparent")
        ff.pack(fill="x", padx=16, pady=8)
        ctk.CTkLabel(ff, text="File path", font=_FONT_SMALL).pack(anchor="w")
        fr = ctk.CTkFrame(ff, fg_color="transparent")
        fr.pack(fill="x", pady=4)
        ctk.CTkEntry(fr, textvariable=self._file_path, width=250, placeholder_text=".pcap, .log, Zeek…").pack(
            side="left", padx=(0, 8)
        )
        ctk.CTkButton(fr, text="Browse…", width=90, command=self._browse_file).pack(side="left")

        lf = ctk.CTkFrame(side_scroll, fg_color="transparent")
        lf.pack(fill="x", padx=16, pady=4)
        ctk.CTkLabel(lf, text="Interface (live)", font=_FONT_SMALL).pack(anchor="w")
        ifaces = [""] + _list_scapy_interfaces()
        self._iface_combo = ctk.CTkComboBox(lf, values=ifaces, variable=self._iface, width=340)
        self._iface_combo.pack(fill="x", pady=4)
        ctk.CTkLabel(
            lf,
            text="Empty = default; refresh after installing Npcap",
            font=("Segoe UI", 9) if platform.system() == "Windows" else ("Ubuntu", 9),
            text_color=("#5c6578", "#5c6578"),
        ).pack(anchor="w")

        df = ctk.CTkFrame(side_scroll, fg_color="transparent")
        df.pack(fill="x", padx=16, pady=4)
        ctk.CTkLabel(df, text="Duration (seconds, live only)", font=_FONT_SMALL).pack(anchor="w")
        ctk.CTkEntry(df, textvariable=self._duration, width=120).pack(anchor="w", pady=4)

        bf = ctk.CTkFrame(side_scroll, fg_color="transparent")
        bf.pack(fill="x", padx=16, pady=4)
        ctk.CTkLabel(bf, text="BPF filter (optional, e.g. tcp port 80)", font=_FONT_SMALL).pack(anchor="w")
        ctk.CTkEntry(bf, textvariable=self._bpf, width=340, placeholder_text="libpcap filter syntax").pack(
            fill="x", pady=4
        )

        ctk.CTkLabel(
            side_scroll,
            text="Tools",
            font=("Segoe UI", 12, "bold") if platform.system() == "Windows" else ("Ubuntu", 12, "bold"),
        ).pack(anchor="w", padx=16, pady=(12, 4))
        self._tool_log = ctk.CTkTextbox(
            side_scroll,
            height=80,
            font=("Consolas", 9) if platform.system() == "Windows" else ("Ubuntu Mono", 9),
        )
        self._tool_log.pack(fill="x", padx=16, pady=4)
        self._tool_log.insert("0.0", "Click Check tools.\n")
        self._tool_log.configure(state="disabled")
        tbf = ctk.CTkFrame(side_scroll, fg_color="transparent")
        tbf.pack(fill="x", padx=16, pady=(0, 8))
        ctk.CTkButton(tbf, text="Check tools", width=120, command=self._check_tools).pack(side="left", padx=(0, 8))
        ctk.CTkButton(tbf, text="Refresh interfaces", width=140, command=self._refresh_ifaces).pack(side="left")

        btn_row = ctk.CTkFrame(side_scroll, fg_color="transparent")
        btn_row.pack(fill="x", padx=16, pady=12)
        ctk.CTkButton(
            btn_row,
            text="Run analysis",
            height=40,
            font=("Segoe UI", 13, "bold") if platform.system() == "Windows" else ("Ubuntu", 13, "bold"),
            command=self._run_clicked,
        ).pack(fill="x", pady=4)
        ctk.CTkButton(btn_row, text="Export JSON…", fg_color="#2d3748", command=self._export).pack(fill="x", pady=4)

        install_scrollable_wheel_fix(side_scroll)

        self._prog = ctk.CTkProgressBar(side, mode="indeterminate")
        self._prog.set(0)

        main = ctk.CTkFrame(self, fg_color=("#0f0f1a", "#0f0f1a"))
        main.grid(row=0, column=1, sticky="nsew", padx=0, pady=0)
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(0, weight=1)

        tabs = ctk.CTkTabview(main, anchor="w")
        tabs.grid(row=0, column=0, sticky="nsew", padx=16, pady=16)
        tabs.add("Findings")
        tabs.add("Stats & parse")
        tabs.add("Help")
        tabs.add("Full capabilities")

        fin = tabs.tab("Findings")
        fin.grid_columnconfigure(0, weight=1)
        fin.grid_rowconfigure(1, weight=1)

        self._summary_lbl = ctk.CTkLabel(
            fin,
            text="Records: —   Findings: —",
            font=("Segoe UI", 12, "bold") if platform.system() == "Windows" else ("Ubuntu", 12, "bold"),
            text_color=("#a5b4fc", "#a5b4fc"),
        )
        self._summary_lbl.grid(row=0, column=0, sticky="w", padx=4, pady=(0, 8))

        tree_frame = ctk.CTkFrame(fin, fg_color="transparent")
        tree_frame.grid(row=1, column=0, sticky="nsew")
        tree_frame.grid_columnconfigure(0, weight=1)
        tree_frame.grid_rowconfigure(0, weight=1)
        self._tree = ttk.Treeview(
            tree_frame,
            columns=("sev", "category", "code", "title"),
            show="headings",
            height=20,
        )
        _style = ttk.Style()
        if "clam" in _style.theme_names():
            _style.theme_use("clam")
        _style.configure("Treeview", background="#1e1e2e", foreground="#e4e4e7", fieldbackground="#1e1e2e", rowheight=24)
        _style.configure("Treeview.Heading", background="#27273a", foreground="#e4e4e7")
        self._tree.heading("sev", text="Severity")
        self._tree.heading("category", text="Category")
        self._tree.heading("code", text="Code")
        self._tree.heading("title", text="Finding")
        self._tree.column("sev", width=72)
        self._tree.column("category", width=130)
        self._tree.column("code", width=128)
        self._tree.column("title", width=400)
        ys = ttk.Scrollbar(tree_frame, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=ys.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")

        self._detail = ctk.CTkTextbox(fin, height=140, font=_FONT_SMALL)
        self._detail.grid(row=2, column=0, sticky="ew", pady=8)
        self._tree.bind("<<TreeviewSelect>>", self._on_select)

        self._stats_box = ctk.CTkTextbox(
            tabs.tab("Stats & parse"),
            font=("Consolas", 11) if platform.system() == "Windows" else ("Ubuntu Mono", 11),
        )
        self._stats_box.pack(fill="both", expand=True, padx=8, pady=8)
        self._stats_box.insert("0.0", "Run analysis to see record counts and parse metadata.\n")

        help_tab = tabs.tab("Help")
        ctk.CTkLabel(
            help_tab,
            text=(
                "Quick start: load a Zeek conn.log, firewall export, or .pcap, or run a short live capture as admin. "
                "See the Full capabilities tab for what each detector category means.\n\n"
                "This is triage assistance, not a replacement for IDS/SIEM tuning."
            ),
            font=("Segoe UI", 12) if platform.system() == "Windows" else ("Ubuntu", 12),
            wraplength=880,
            justify="left",
        ).pack(anchor="w", padx=12, pady=12)

        cap = tabs.tab("Full capabilities")
        cap_scroll = ctk.CTkScrollableFrame(cap, fg_color=("#0f0f1a", "#0f0f1a"))
        cap_scroll.pack(fill="both", expand=True, padx=8, pady=8)

        _cap_title = ("Segoe UI", 13, "bold") if platform.system() == "Windows" else ("Ubuntu", 13, "bold")
        _cap_body = ("Segoe UI", 12) if platform.system() == "Windows" else ("Ubuntu", 12)

        ctk.CTkLabel(
            cap_scroll,
            text="Full detection capabilities",
            font=_cap_title,
            text_color=("#e8e8f0", "#e8e8f0"),
        ).pack(anchor="w", padx=4, pady=(0, 12))

        ctk.CTkLabel(
            cap_scroll,
            text="1. Reconnaissance detection (early attacker behavior)",
            font=_cap_title,
            text_color=("#a5b4fc", "#a5b4fc"),
        ).pack(anchor="w", padx=4, pady=(8, 4))
        ctk.CTkLabel(
            cap_scroll,
            text=(
                "These are often the first signs of an attacker scanning or mapping your systems.\n\n"
                "Detect:\n"
                "  • Port scanning — many distinct destination ports from the same source toward a target; "
                "includes rapid TCP sweeps when packet timestamps show many ports opened within a short window.\n"
                "  • SYN scan patterns — a high ratio of SYN packets (half-open / probe-heavy TCP) from a source, "
                "consistent with SYN scans or incomplete handshakes.\n"
                "  • Ping sweeps — ICMP from one source toward many different hosts (host discovery). "
                "When ICMP type is known from capture, echo replies are excluded from this sweep signal.\n\n"
                "Logic: same IP → many ports or many targets in a short time → suspicious (heuristic threshold)."
            ),
            font=_cap_body,
            wraplength=900,
            justify="left",
        ).pack(anchor="w", padx=4, pady=(0, 16))

        ctk.CTkLabel(
            cap_scroll,
            text="2. Brute force attack detection",
            font=_cap_title,
            text_color=("#a5b4fc", "#a5b4fc"),
        ).pack(anchor="w", padx=4, pady=(8, 4))
        ctk.CTkLabel(
            cap_scroll,
            text=(
                "Network flows do not reveal password success/failure; we infer risk from repeated TCP activity "
                "to common login services (same idea as multiple failed login attempts in auth logs).\n\n"
                "Detect:\n"
                "  • Repeated connections to SSH (:22), FTP (:21), web login ports (80, 443, 8080, 8443), and RDP (:3389).\n"
                "  • High rate of events from the same source to the same destination:port within a 1-minute sliding window.\n\n"
                "Logic: same IP → repeated attempts → short time.\n\n"
                "Example output style:\n"
                "  [ALERT] SSH Brute Force suspected from 45.12.x.x\n"
                "  Attempts: 30 in 1 minute"
            ),
            font=_cap_body,
            wraplength=900,
            justify="left",
        ).pack(anchor="w", padx=4, pady=(0, 16))

        ctk.CTkLabel(
            cap_scroll,
            text="3. DDoS / traffic flood detection",
            font=_cap_title,
            text_color=("#a5b4fc", "#a5b4fc"),
        ).pack(anchor="w", padx=4, pady=(8, 4))
        ctk.CTkLabel(
            cap_scroll,
            text=(
                "Detect:\n"
                "  • Sudden spike in traffic (peak requests/sec in any one-second bucket).\n"
                "  • Too many requests from one IP (dominant share of the busiest second).\n"
                "  • Too many requests overall (sustained average rate across the capture when timestamps span several seconds).\n\n"
                "Logic: requests/sec compared to built-in thresholds (tunable in code).\n\n"
                "Example output style:\n"
                "  [ALERT] Possible DDoS detected\n"
                "  Traffic spike: 500 requests/sec"
            ),
            font=_cap_body,
            wraplength=900,
            justify="left",
        ).pack(anchor="w", padx=4, pady=(0, 16))

        ctk.CTkLabel(
            cap_scroll,
            text="4. Suspicious IP behavior",
            font=_cap_title,
            text_color=("#a5b4fc", "#a5b4fc"),
        ).pack(anchor="w", padx=4, pady=(8, 4))
        ctk.CTkLabel(
            cap_scroll,
            text=(
                "Detect:\n"
                "  • Unknown external (public) IPs accessing multiple services toward private (RFC1918) space — "
                "many distinct destination ports or many distinct internal hosts from one public source.\n"
                "  • Repeated access attempts to sensitive ports beyond the core login set (e.g. SMB 445, "
                "database, Redis, Elasticsearch — see engine constants).\n\n"
                "Bonus:\n"
                "  • Private → public unusual patterns — internal hosts contacting many distinct public destinations "
                "(possible scanning, C2, or exfil heuristics; IPv4 classification only).\n\n"
                "Logic uses RFC1918 / public IPv4 heuristics; unknown or non-IPv4 addresses are skipped."
            ),
            font=_cap_body,
            wraplength=900,
            justify="left",
        ).pack(anchor="w", padx=4, pady=(0, 16))

        ctk.CTkLabel(
            cap_scroll,
            text="5. Unauthorized access attempts",
            font=_cap_title,
            text_color=("#a5b4fc", "#a5b4fc"),
        ).pack(anchor="w", padx=4, pady=(8, 4))
        ctk.CTkLabel(
            cap_scroll,
            text=(
                "Detect:\n"
                "  • Access to restricted ports/services from the public Internet toward internal (RFC1918) hosts — "
                "admin-style ports (e.g. 8080, 8443, 9000) and other restricted management/database ports.\n"
                "  • Unexpected internal service exposure — the same internal address:port reached from several "
                "different public sources (possible unintended exposure).\n\n"
                "Logic: public IPv4 → private IPv4 on selected ports; connection event counts proxy for attempts "
                "(not application-level authentication).\n\n"
                "Example:\n"
                "  [ALERT] Unauthorized attempt to access admin panel"
            ),
            font=_cap_body,
            wraplength=900,
            justify="left",
        ).pack(anchor="w", padx=4, pady=(0, 16))

        ctk.CTkLabel(
            cap_scroll,
            text="6. DNS anomalies",
            font=_cap_title,
            text_color=("#a5b4fc", "#a5b4fc"),
        ).pack(anchor="w", padx=4, pady=(8, 4))
        ctk.CTkLabel(
            cap_scroll,
            text=(
                "Detect:\n"
                "  • Too many DNS requests from one host in a short window (possible tunneling or misconfiguration) — "
                "uses UDP/TCP :53 volume or Zeek dns.log with timestamps.\n"
                "  • Requests to suspicious / random-looking domains when the query name is visible (entropy, label "
                "length, hex-like labels — not a threat-intel feed).\n\n"
                "Logic: high frequency + unusual FQDN shapes (heuristic).\n\n"
                "Best results: live/pcap with DNS layers, or Zeek dns.log exports."
            ),
            font=_cap_body,
            wraplength=900,
            justify="left",
        ).pack(anchor="w", padx=4, pady=(0, 16))

        ctk.CTkLabel(
            cap_scroll,
            text="7. Data exfiltration detection (important)",
            font=_cap_title,
            text_color=("#fca5a5", "#fca5a5"),
        ).pack(anchor="w", padx=4, pady=(8, 4))
        ctk.CTkLabel(
            cap_scroll,
            text=(
                "Detect:\n"
                "  • Large outbound traffic — bytes from internal (RFC1918) hosts toward the public Internet summed in "
                "a 2-minute sliding window.\n"
                "  • Unusual upload behavior — one internal host sends far more bytes outbound than it receives inbound "
                "from the Internet in the same capture (ratio heuristic).\n\n"
                "Logic: normal baseline is often modest upload; suspicious is a sudden large transfer (packet sizes summed).\n\n"
                "Example:\n"
                "  [ALERT] Possible Data Exfiltration\n"
                "  Outbound traffic: 500MB in 2 minutes"
            ),
            font=_cap_body,
            wraplength=900,
            justify="left",
        ).pack(anchor="w", padx=4, pady=(0, 16))

        ctk.CTkLabel(
            cap_scroll,
            text="8. Protocol anomalies",
            font=_cap_title,
            text_color=("#a5b4fc", "#a5b4fc"),
        ).pack(anchor="w", padx=4, pady=(8, 4))
        ctk.CTkLabel(
            cap_scroll,
            text=(
                "Detect:\n"
                "  • Malformed / implausible packet sizes (impossible lengths, floods of tiny frames).\n"
                "  • Unexpected protocol usage — non-TCP/UDP/ICMP IPv4 next-header values when captured from pcap "
                "(e.g. GRE, ESP — best with full packet decode).\n"
                "  • Non-standard ports for common services — alternate SSH/RDP ports, symmetric client/server ports, "
                "oversized ICMP payloads.\n\n"
                "Logic: structure and metadata heuristics (not deep packet inspection)."
            ),
            font=_cap_body,
            wraplength=900,
            justify="left",
        ).pack(anchor="w", padx=4, pady=(0, 16))

        ctk.CTkLabel(
            cap_scroll,
            text="9. ARP spoofing detection (local network attack)",
            font=_cap_title,
            text_color=("#a5b4fc", "#a5b4fc"),
        ).pack(anchor="w", padx=4, pady=(8, 4))
        ctk.CTkLabel(
            cap_scroll,
            text=(
                "Detect:\n"
                "  • Same IPv4 address associated with multiple sender MAC addresses in ARP frames (possible "
                "spoofing or misconfiguration).\n\n"
                "Requires ARP-capable captures (Ethernet + ARP in .pcap / live sniff); plain firewall text logs "
                "usually do not include ARP.\n\n"
                "Example:\n"
                "  [ALERT] ARP Spoofing suspected\n"
                "  IP conflict detected"
            ),
            font=_cap_body,
            wraplength=900,
            justify="left",
        ).pack(anchor="w", padx=4, pady=(0, 16))

        ctk.CTkLabel(
            cap_scroll,
            text="10. Suspicious User-Agent / HTTP behavior",
            font=_cap_title,
            text_color=("#a5b4fc", "#a5b4fc"),
        ).pack(anchor="w", padx=4, pady=(8, 4))
        ctk.CTkLabel(
            cap_scroll,
            text=(
                "Applies to cleartext HTTP carried in TCP (typical ports like 80, 8080, 8000). "
                "HTTPS on 443 is encrypted here — User-Agent is not visible in the same way.\n\n"
                "Detect:\n"
                "  • Automated tools — User-Agent substrings typical of scripts and scanners (e.g. curl, wget, "
                "Python requests, Go/Java HTTP clients, Nikto, ffuf, nuclei, masscan-style strings, and similar).\n"
                "  • Missing User-Agent — multiple HTTP requests from the same source with no User-Agent header "
                "(often scripts, older tools, or misconfigured clients).\n"
                "  • Weird User-Agent — very short, placeholder, or mostly non-printable values.\n\n"
                "Logic: parse HTTP request lines and headers from TCP payloads on selected ports; threshold "
                "noise filters (e.g. repeated missing-UA or scanner-like strings)."
            ),
            font=_cap_body,
            wraplength=900,
            justify="left",
        ).pack(anchor="w", padx=4, pady=(0, 16))

        ctk.CTkLabel(
            cap_scroll,
            text="11. Malware / beaconing behavior",
            font=_cap_title,
            text_color=("#fca5a5", "#fca5a5"),
        ).pack(anchor="w", padx=4, pady=(8, 4))
        ctk.CTkLabel(
            cap_scroll,
            text=(
                "Detect:\n"
                "  • Repeated small requests to the same destination IP and port — many compact packets from one source "
                "toward a fixed peer (possible command-and-control check-ins).\n"
                "  • Regular timing — inter-arrival times between traffic pulses are similar (low variance vs mean), "
                "i.e. same interval → same destination.\n\n"
                "Logic: group TCP/UDP flows by (source, destination, port); merge bursts within ~2s; require several "
                "pulses with small packet sizes (≤512 B by default) and a stable mean interval between ~0.5s and 2 hours. "
                "Multicast/broadcast destinations are ignored.\n\n"
                "Example:\n"
                "  Possible beaconing / C2-style pattern: 10.0.0.5 → 203.0.113.10:443"
            ),
            font=_cap_body,
            wraplength=900,
            justify="left",
        ).pack(anchor="w", padx=4, pady=(0, 16))

        ctk.CTkLabel(
            cap_scroll,
            text="12. Traffic pattern anomalies (smart feature)",
            font=_cap_title,
            text_color=("#a5b4fc", "#a5b4fc"),
        ).pack(anchor="w", padx=4, pady=(8, 4))
        ctk.CTkLabel(
            cap_scroll,
            text=(
                "Detect:\n"
                "  • Behavior deviation from an estimated normal baseline — compares the busiest second to a "
                "“typical” rate derived from the rest of the capture (the single peak second is excluded when "
                "estimating normal traffic).\n\n"
                "Example:\n"
                "  • Normally: ~10 req/sec (baseline)\n"
                "  • Now: ~200 req/sec in the peak second → alert when the ratio exceeds built-in thresholds "
                "(e.g. roughly 10× baseline with enough history).\n\n"
                "Logic: per-second packet counts; normal baseline ≈ median rate after removing the busiest second; "
                "flag large peak-to-baseline ratios. Works best with timestamps spanning many seconds."
            ),
            font=_cap_body,
            wraplength=900,
            justify="left",
        ).pack(anchor="w", padx=4, pady=(0, 16))

        ctk.CTkLabel(
            cap_scroll,
            text="13. Port misuse detection",
            font=_cap_title,
            text_color=("#a5b4fc", "#a5b4fc"),
        ).pack(anchor="w", padx=4, pady=(8, 4))
        ctk.CTkLabel(
            cap_scroll,
            text=(
                "Detect:\n"
                "  • HTTP traffic on non-standard ports — cleartext HTTP request line (GET/POST/…) seen toward a "
                "destination port outside the engine’s usual web list (e.g. not 80/8080/8000-style defaults).\n"
                "  • Encrypted traffic where it may be unexpected — TLS ClientHello on ports not in the typical HTTPS/TLS "
                "set (possible tunneling or non-standard services), or TLS toward ports that often carry cleartext HTTP "
                "(e.g. 80, 8080) for policy review.\n\n"
                "Logic: TCP payload heuristics (HTTP text vs TLS record header 0x16/0x03) combined with destination port "
                "classification; best with full packet capture."
            ),
            font=_cap_body,
            wraplength=900,
            justify="left",
        ).pack(anchor="w", padx=4, pady=(0, 16))

        ctk.CTkLabel(
            cap_scroll,
            text="14. Lateral movement detection (advanced)",
            font=_cap_title,
            text_color=("#a5b4fc", "#a5b4fc"),
        ).pack(anchor="w", padx=4, pady=(8, 4))
        ctk.CTkLabel(
            cap_scroll,
            text=(
                "Detect:\n"
                "  • Internal machine scanning or contacting many other internal machines — one RFC1918 source "
                "reaching a large number of distinct private destination addresses (TCP/UDP/ICMP).\n\n"
                "Logic: internal IP → many internal IPs (not Internet-bound). Broadcast-style addresses are ignored. "
                "Severity scales with how many unique internal targets are observed. Complements horizontal-scan "
                "reconnaissance (same port, many hosts) by aggregating across ports and protocols for a host-centric view."
            ),
            font=_cap_body,
            wraplength=900,
            justify="left",
        ).pack(anchor="w", padx=4, pady=(0, 16))

        ctk.CTkLabel(
            cap_scroll,
            text="15. Traffic & volume anomalies",
            font=_cap_title,
            text_color=("#a5b4fc", "#a5b4fc"),
        ).pack(anchor="w", padx=4, pady=(8, 4))
        ctk.CTkLabel(
            cap_scroll,
            text=(
                "Additional heuristics: relative spikes vs median second (baseline), dominant talker (non-DDoS wording), "
                "single-source share of total packets, high ICMP volume, bursts of TCP RST.\n\n"
                "Horizontal scans (one port toward many hosts) and UDP port-scan-like patterns are surfaced "
                "under reconnaissance where they match probe heuristics."
            ),
            font=_cap_body,
            wraplength=900,
            justify="left",
        ).pack(anchor="w", padx=4, pady=(0, 8))

        self.after(400, self._check_tools)

    def _set_tool_log(self, text: str) -> None:
        self._tool_log.configure(state="normal")
        self._tool_log.delete("0.0", "end")
        self._tool_log.insert("0.0", text)
        self._tool_log.configure(state="disabled")

    def _check_tools(self) -> None:
        try:
            from network_traffic_analyzer import format_tool_status

            self._set_tool_log(format_tool_status())
        except Exception as e:
            self._set_tool_log(str(e))

    def _refresh_ifaces(self) -> None:
        ifaces = [""] + _list_scapy_interfaces()
        self._iface_combo.configure(values=ifaces)

    def _browse_file(self) -> None:
        p = filedialog.askopenfilename(
            filetypes=[
                ("Captures & logs", "*.pcap;*.pcapng;*.log;*.txt"),
                ("PCAP", "*.pcap;*.pcapng"),
                ("All", "*.*"),
            ]
        )
        if p:
            self._file_path.set(p)

    def _on_select(self, _e=None) -> None:
        sel = self._tree.selection()
        if not sel or not self._last_report:
            return
        iid = sel[0]
        try:
            idx = int(iid)
            f = self._last_report.findings[idx]
            self._detail.delete("0.0", "end")
            ev = json.dumps(f.evidence, indent=2) if f.evidence else "{}"
            cat = getattr(f, "category", "general")
            self._detail.insert(
                "0.0",
                f"Category: {cat}\n\n{f.title}\n\n{f.detail}\n\nEvidence:\n{ev}\n",
            )
        except (ValueError, IndexError):
            pass

    def _run_clicked(self) -> None:
        from network_traffic_analyzer import analyze_flow_records, load_records_from_path, sniff_flows

        mode = self._mode.get()
        if mode == "file":
            path = self._file_path.get().strip()
            if not path or not Path(path).is_file():
                messagebox.showinfo("File required", "Choose a log file or .pcap / .pcapng.")
                return

            def work_file() -> None:
                try:
                    records, meta, perr = load_records_from_path(path)
                    if perr:
                        self.after(0, lambda: self._err(f"Pcap read: {perr}"))
                        return
                    rep = analyze_flow_records(records)
                    self.after(0, lambda: self._apply(rep, meta))
                except Exception:
                    self.after(0, lambda: self._err(traceback.format_exc()))

            self._start_prog(work_file)
            return

        # live
        try:
            dur = float(self._duration.get().strip() or "15")
        except ValueError:
            messagebox.showerror("Invalid duration", "Enter a number of seconds.")
            return
        iface = self._iface.get().strip() or None
        bpf = self._bpf.get().strip() or None

        def work_live() -> None:
            try:
                records, err = sniff_flows(iface=iface, duration_sec=dur, bpf_filter=bpf)
                meta = {"kind": "live", "iface": iface or "(default)", "duration_sec": dur, "bpf": bpf}
                if err:
                    meta["capture_error"] = err
                rep = analyze_flow_records(records)
                self.after(0, lambda: self._apply(rep, meta))
            except Exception:
                self.after(0, lambda: self._err(traceback.format_exc()))

        self._start_prog(work_live)

    def _start_prog(self, target) -> None:
        self._prog.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 12))
        self._prog.start()
        threading.Thread(target=target, daemon=True).start()

    def _err(self, err: str) -> None:
        self._prog.stop()
        self._prog.grid_forget()
        messagebox.showerror("Analysis failed", err[-1600:])

    def _apply(self, rep, meta: dict | None) -> None:
        self._prog.stop()
        self._prog.grid_forget()
        self._last_report = rep
        self._last_meta = meta

        self._summary_lbl.configure(
            text=f"Records: {rep.records_used}   Findings: {len(rep.findings)}",
        )

        self._tree.delete(*self._tree.get_children())
        for i, f in enumerate(rep.findings):
            cat = getattr(f, "category", "general")
            self._tree.insert(
                "",
                "end",
                iid=str(i),
                values=(f.severity.upper(), cat.replace("_", " "), f.code, f.title),
            )

        self._stats_box.delete("0.0", "end")
        lines = [json.dumps(rep.stats, indent=2)]
        if meta:
            lines.append("\n--- source ---\n")
            lines.append(json.dumps(meta, indent=2))
        self._stats_box.insert("0.0", "".join(lines))

        self._detail.delete("0.0", "end")
        if rep.findings:
            f0 = rep.findings[0]
            ev = json.dumps(f0.evidence, indent=2) if f0.evidence else "{}"
            c0 = getattr(f0, "category", "general")
            self._detail.insert(
                "0.0",
                f"Category: {c0}\n\n{f0.title}\n\n{f0.detail}\n\nEvidence:\n{ev}\n",
            )

    def _export(self) -> None:
        if not self._last_report:
            messagebox.showinfo("Nothing to export", "Run analysis first.")
            return
        p = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if not p:
            return
        out = {
            "stats": self._last_report.stats,
            "meta": self._last_meta,
            "findings": [
                {
                    "code": f.code,
                    "category": getattr(f, "category", "general"),
                    "severity": f.severity,
                    "title": f.title,
                    "detail": f.detail,
                    "evidence": f.evidence,
                }
                for f in self._last_report.findings
            ],
        }
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=2)
        messagebox.showinfo("Saved", f"Wrote {p}")

"""
Cross-platform desktop UI (Windows / Linux) for ThreatLog Analyzer.
"""
from __future__ import annotations

import json
import platform
import threading
import traceback
from dataclasses import asdict
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk

from .engine import AnalysisConfig, run_analysis
from .models import EventKind, Finding, ParsedEvent
from .parser import parse_file
from .registry import DETECTOR_INFOS

# Professional dark theme defaults
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

_FONT_BODY = ("Segoe UI", 12) if platform.system() == "Windows" else ("Ubuntu", 12)
_FONT_SMALL = ("Segoe UI", 11) if platform.system() == "Windows" else ("Ubuntu", 11)


def install_scrollable_wheel_fix(scrollable: ctk.CTkScrollableFrame) -> None:
    """
    CustomTkinter scrolls on mouse wheel only when event.widget traces to the inner canvas.
    Some CTk widgets break that chain; treat any descendant of this scrollable as inside it.
    On Linux, also bind Button-4/5 (wheel) on the canvas and descendants.
    """
    def check(widget: object) -> bool:
        w = widget
        while w is not None:
            if w is scrollable:
                return True
            if w is scrollable._parent_canvas:
                return True
            w = getattr(w, "master", None)
        return False

    scrollable.check_if_master_is_canvas = check  # type: ignore[assignment]

    if platform.system() != "Linux":
        return

    canvas = scrollable._parent_canvas

    def _linux_btn(event) -> None:
        if scrollable._orientation != "vertical":
            return
        if event.num == 4:
            delta = -1
        elif event.num == 5:
            delta = 1
        else:
            return
        if canvas.yview() != (0.0, 1.0):
            canvas.yview("scroll", delta, "units")

    def _bind_linux(w) -> None:
        w.bind("<Button-4>", _linux_btn)
        w.bind("<Button-5>", _linux_btn)
        for ch in w.winfo_children():
            _bind_linux(ch)

    canvas.bind("<Button-4>", _linux_btn)
    canvas.bind("<Button-5>", _linux_btn)
    _bind_linux(scrollable)


class LogAnalysisFrame(ctk.CTkFrame):
    """Log threat analysis UI (embedded in the unified suite)."""

    def __init__(self, master: ctk.Misc, initial_log: str | None = None, **kwargs) -> None:
        super().__init__(master, fg_color=("#0a0a12", "#0a0a12"), **kwargs)
        self._log_path: Path | None = Path(initial_log) if initial_log else None
        self._events: list[ParsedEvent] = []
        self._findings: list[Finding] = []
        self._detector_vars: dict[str, ctk.BooleanVar] = {}

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self._build()
        if self._log_path and self._log_path.is_file():
            self._path_var.set(str(self._log_path))

    def _build(self) -> None:

        # ---- Sidebar: fixed top (path + run) + scroll (detectors + export) for short windows ----
        side = ctk.CTkFrame(self, width=340, corner_radius=0, fg_color=("#1a1a2e", "#1a1a2e"))
        side.grid(row=0, column=0, sticky="nsew")
        side.grid_propagate(False)
        side.grid_rowconfigure(1, weight=1)
        side.grid_columnconfigure(0, weight=1)

        top_bar = ctk.CTkFrame(side, fg_color=("#1a1a2e", "#1a1a2e"))
        top_bar.grid(row=0, column=0, sticky="ew")

        head = ctk.CTkLabel(
            top_bar,
            text="ThreatLog Analyzer",
            font=("Segoe UI", 20, "bold") if platform.system() == "Windows" else ("Ubuntu", 20, "bold"),
            text_color=("#e8e8f0", "#e8e8f0"),
        )
        head.pack(anchor="w", padx=20, pady=(24, 4))
        sub = ctk.CTkLabel(
            top_bar,
            text="Auth/syslog, .pcap/.pcapng, Wireshark CSV, or tshark",
            font=_FONT_SMALL,
            text_color=("#8892a6", "#8892a6"),
        )
        sub.pack(anchor="w", padx=20, pady=(0, 8))
        ctk.CTkLabel(
            top_bar,
            text=(
                "Supports SSH/PAM logs, binary .pcap/.pcapng (via scapy), and text exports "
                "(CSV from Wireshark, tshark summary, tab-separated). Enable “Packet capture "
                "heuristics” for capture-based findings."
            ),
            font=("Segoe UI", 10) if platform.system() == "Windows" else ("Ubuntu", 10),
            text_color=("#6b7280", "#6b7280"),
            wraplength=308,
            justify="left",
        ).pack(anchor="w", padx=20, pady=(0, 12))

        self._path_var = ctk.StringVar(value="")
        row = ctk.CTkFrame(top_bar, fg_color="transparent")
        row.pack(fill="x", padx=16, pady=4)
        ctk.CTkLabel(row, text="Log file", font=_FONT_BODY).pack(anchor="w")
        pe = ctk.CTkEntry(
            row,
            textvariable=self._path_var,
            width=300,
            placeholder_text="auth.log, .pcapng, .pcap, or Wireshark .csv / tshark .txt",
        )
        pe.pack(fill="x", pady=(4, 4))
        ctk.CTkButton(row, text="Browse…", width=120, command=self._browse).pack(anchor="w")

        yf = ctk.CTkFrame(top_bar, fg_color="transparent")
        yf.pack(fill="x", padx=16, pady=8)
        ctk.CTkLabel(yf, text="Syslog year (no year in stamp)", font=_FONT_SMALL).pack(anchor="w")
        self._year_var = ctk.StringVar(value="2026")
        ctk.CTkEntry(yf, textvariable=self._year_var, width=100).pack(anchor="w", pady=4)

        mpf = ctk.CTkFrame(top_bar, fg_color="transparent")
        mpf.pack(fill="x", padx=16, pady=4)
        ctk.CTkLabel(mpf, text="Max PCAP packets (0 = no limit; blank = default)", font=_FONT_SMALL).pack(anchor="w")
        self._max_pcap_var = ctk.StringVar(value="250000")
        ctk.CTkEntry(mpf, textvariable=self._max_pcap_var, width=120).pack(anchor="w", pady=2)

        # Parameters
        param = ctk.CTkFrame(top_bar, fg_color="transparent")
        param.pack(fill="x", padx=16, pady=8)
        ctk.CTkLabel(param, text="Brute-force threshold", font=_FONT_SMALL).pack(anchor="w")
        self._fail_th = ctk.StringVar(value="5")
        ctk.CTkEntry(param, textvariable=self._fail_th, width=80).pack(anchor="w", pady=2)
        ctk.CTkLabel(param, text="Window (minutes)", font=_FONT_SMALL).pack(anchor="w", pady=(8, 0))
        self._win_m = ctk.StringVar(value="5")
        ctk.CTkEntry(param, textvariable=self._win_m, width=80).pack(anchor="w", pady=2)
        ctk.CTkLabel(param, text="Business hours (start–end)", font=_FONT_SMALL).pack(anchor="w", pady=(8, 0))
        bh = ctk.CTkFrame(param, fg_color="transparent")
        bh.pack(anchor="w", pady=2)
        self._biz_s = ctk.StringVar(value="8")
        self._biz_e = ctk.StringVar(value="18")
        ctk.CTkEntry(bh, textvariable=self._biz_s, width=50).pack(side="left")
        ctk.CTkLabel(bh, text=" – ").pack(side="left")
        ctk.CTkEntry(bh, textvariable=self._biz_e, width=50).pack(side="left")

        self._ml_var = ctk.BooleanVar(value=True)
        ctk.CTkSwitch(top_bar, text="Enable ML (Isolation Forest)", variable=self._ml_var).pack(
            anchor="w", padx=16, pady=12
        )

        # Run stays in the fixed top strip; detectors + export scroll below.
        self._run_frame = ctk.CTkFrame(top_bar, fg_color="transparent")
        self._run_frame.pack(fill="x", padx=16, pady=(4, 12))
        ctk.CTkButton(
            self._run_frame,
            text="Run analysis",
            height=40,
            font=("Segoe UI", 13, "bold") if platform.system() == "Windows" else ("Ubuntu", 13, "bold"),
            command=self._run_clicked,
        ).pack(fill="x", pady=2)
        self._prog = ctk.CTkProgressBar(self._run_frame, mode="indeterminate")
        self._prog.set(0)

        side_scroll = ctk.CTkScrollableFrame(
            side,
            fg_color=("#1a1a2e", "#1a1a2e"),
            corner_radius=0,
        )
        side_scroll.grid(row=1, column=0, sticky="nsew")

        det_lab = ctk.CTkLabel(
            side_scroll,
            text="Detection modules",
            font=("Segoe UI", 13, "bold") if platform.system() == "Windows" else ("Ubuntu", 13, "bold"),
        )
        det_lab.pack(anchor="w", padx=16, pady=(4, 4))

        det_frame = ctk.CTkFrame(side_scroll, fg_color="transparent")
        det_frame.pack(fill="x", padx=12, pady=(0, 8))
        for info in DETECTOR_INFOS:
            v = ctk.BooleanVar(value=info.default_enabled)
            self._detector_vars[info.id] = v
            row_f = ctk.CTkFrame(det_frame, fg_color="transparent")
            row_f.pack(fill="x", pady=2)
            sw = ctk.CTkSwitch(row_f, text=info.name, variable=v, font=_FONT_SMALL)
            sw.pack(anchor="w")
            tip = ctk.CTkLabel(
                row_f,
                text=info.description[:92] + ("…" if len(info.description) > 92 else ""),
                font=("Segoe UI", 10) if platform.system() == "Windows" else ("Ubuntu", 10),
                text_color=("#6b7280", "#6b7280"),
                wraplength=300,
                justify="left",
            )
            tip.pack(anchor="w", padx=(28, 0))

        ext = ctk.CTkLabel(
            side_scroll,
            text="Extensions: use threat_analyzer.registry.register_extension()",
            font=("Consolas", 10) if platform.system() == "Windows" else ("Ubuntu Mono", 10),
            text_color=("#5c6370", "#5c6370"),
            wraplength=310,
        )
        ext.pack(anchor="w", padx=16, pady=(4, 8))

        btn_row = ctk.CTkFrame(side_scroll, fg_color="transparent")
        btn_row.pack(fill="x", padx=16, pady=(4, 20))
        ctk.CTkButton(btn_row, text="Export JSON…", fg_color="#2d3748", command=self._export).pack(
            fill="x", pady=4
        )
        ctk.CTkButton(btn_row, text="Export HTML report…", fg_color="#1e3a5f", command=self._export_html).pack(
            fill="x", pady=4
        )

        install_scrollable_wheel_fix(side_scroll)

        # ---- Main content ----
        main = ctk.CTkFrame(self, fg_color=("#0f0f1a", "#0f0f1a"))
        main.grid(row=0, column=1, sticky="nsew", padx=0, pady=0)
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(0, weight=1)

        tabs = ctk.CTkTabview(main, anchor="w")
        tabs.grid(row=0, column=0, sticky="nsew", padx=16, pady=16)
        tabs.add("Overview")
        tabs.add("Log file info")
        tabs.add("Findings")
        tabs.add("Event mix")
        tabs.add("Category AI")

        ov = tabs.tab("Overview")
        self._overview = ctk.CTkTextbox(ov, font=("Consolas", 12) if platform.system() == "Windows" else ("Ubuntu Mono", 12))
        self._overview.pack(fill="both", expand=True, padx=8, pady=8)

        lfi = tabs.tab("Log file info")
        ctk.CTkLabel(
            lfi,
            text=(
                "File metadata, parse coverage, time span, auth and packet summaries for the loaded file. "
                "This is informational triage, not a list of security alerts (see Findings)."
            ),
            font=_FONT_SMALL,
            text_color=("#8892a6", "#8892a6"),
            wraplength=920,
            justify="left",
        ).pack(anchor="w", padx=8, pady=(8, 4))
        self._log_file_info = ctk.CTkTextbox(
            lfi,
            font=("Consolas", 11) if platform.system() == "Windows" else ("Ubuntu Mono", 11),
        )
        self._log_file_info.pack(fill="both", expand=True, padx=8, pady=8)
        self._log_file_info.insert("0.0", "Run analysis to populate this section.\n")
        self._log_file_info.configure(state="disabled")

        fin = tabs.tab("Findings")
        fin.grid_columnconfigure(0, weight=1)
        fin.grid_rowconfigure(0, weight=1)
        tree_frame = ctk.CTkFrame(fin, fg_color="transparent")
        tree_frame.grid(row=0, column=0, sticky="nsew")
        tree_frame.grid_columnconfigure(0, weight=1)
        tree_frame.grid_rowconfigure(0, weight=1)
        self._tree = ttk.Treeview(
            tree_frame,
            columns=("sev", "cat", "title", "detail"),
            show="headings",
            height=18,
        )
        _style = ttk.Style()
        if "clam" in _style.theme_names():
            _style.theme_use("clam")
        _style.configure("Treeview", background="#1e1e2e", foreground="#e4e4e7", fieldbackground="#1e1e2e", rowheight=26)
        _style.configure("Treeview.Heading", background="#27273a", foreground="#e4e4e7")
        _style.map("Treeview", background=[("selected", "#3b3b5c")])
        self._tree.heading("sev", text="Severity")
        self._tree.heading("cat", text="Category")
        self._tree.heading("title", text="Title")
        self._tree.heading("detail", text="Detail")
        self._tree.column("sev", width=72)
        self._tree.column("cat", width=120)
        self._tree.column("title", width=260)
        self._tree.column("detail", width=420)
        ys = ttk.Scrollbar(tree_frame, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=ys.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")

        self._detail = ctk.CTkTextbox(fin, height=220, font=_FONT_SMALL)
        self._detail.grid(row=1, column=0, sticky="ew", padx=0, pady=8)
        self._tree.bind("<<TreeviewSelect>>", self._on_tree_select)

        mix = tabs.tab("Event mix")
        ctk.CTkLabel(
            mix,
            text=(
                "What this shows: counts of parsed event kinds (login_success, login_failure, packet_record, etc.). "
                "It is not the same as “Category AI” (which explains security finding categories). "
                "Use it to see whether the file is mostly auth lines vs packet rows."
            ),
            font=_FONT_SMALL,
            text_color=("#8892a6", "#8892a6"),
            wraplength=920,
            justify="left",
        ).pack(anchor="w", padx=8, pady=(8, 4))
        self._mix = ctk.CTkTextbox(mix, font=("Consolas", 12) if platform.system() == "Windows" else ("Ubuntu Mono", 12))
        self._mix.pack(fill="both", expand=True, padx=8, pady=8)

        cai = tabs.tab("Category AI")
        ctk.CTkLabel(
            cai,
            text=(
                "Rule-based intelligence per security finding category (e.g. brute_force, unusual_time). "
                "This is not the Event mix tab: Event mix counts raw parsed line types; Category AI explains "
                "what each alert category means for triage."
            ),
            font=_FONT_SMALL,
            text_color=("#8892a6", "#8892a6"),
            wraplength=920,
            justify="left",
        ).pack(anchor="w", padx=8, pady=(8, 4))
        self._cat_ai = ctk.CTkTextbox(
            cai,
            font=("Segoe UI", 12) if platform.system() == "Windows" else ("Ubuntu", 12),
        )
        self._cat_ai.pack(fill="both", expand=True, padx=8, pady=8)
        self._cat_ai.insert("0.0", "Run analysis to see category intelligence narratives.\n")
        self._cat_ai.configure(state="disabled")

        self._overview.insert(
            "0.0",
            "Load a log file and click Run analysis.\n\n"
            "Supported inputs:\n"
            "  • Linux/SSH auth logs (e.g. auth.log)\n"
            "  • Binary captures: .pcapng / .pcap (requires scapy — pip install -r requirements.txt)\n"
            "  • Wireshark: Export Packet Dissections → As CSV\n"
            "  • tshark: one-line frame summary (src → dst, protocol, info)\n\n"
            "Samples: sample_logs/wireshark_export_sample.csv, sample_logs/minimal_capture.pcapng, "
            "sample_logs/detector_triggers_sample.log (auth detectors)\n\n"
            "After Run analysis: use Log file info for a detailed summary of this file; Findings for alerts.\n\n",
        )
        self._overview.configure(state="disabled")

    def _browse(self) -> None:
        p = filedialog.askopenfilename(
            title="Select log or capture",
            filetypes=[
                ("Captures and logs", "*.pcapng *.pcap *.log *.txt *.csv"),
                ("Packet capture", "*.pcapng *.pcap"),
                ("Log / export", "*.log *.txt *.csv"),
                ("All files", "*.*"),
            ],
        )
        if p:
            self._path_var.set(p)
            self._log_path = Path(p)

    def _enabled_ids(self) -> set[str] | None:
        all_on = all(v.get() for v in self._detector_vars.values())
        if all_on:
            return None
        return {k for k, v in self._detector_vars.items() if v.get()}

    def _parse_int(self, var: ctk.StringVar, default: int) -> int:
        try:
            return int(var.get().strip())
        except ValueError:
            return default

    def _parse_max_pcap(self) -> int | None:
        s = self._max_pcap_var.get().strip()
        if not s:
            return None
        try:
            return int(s)
        except ValueError:
            return None

    def _run_clicked(self) -> None:
        path = Path(self._path_var.get().strip())
        if not path.is_file():
            messagebox.showerror("Invalid file", "Choose a valid log file.")
            return

        def work() -> None:
            try:
                from .pcap_io import DEFAULT_MAX_PCAP_PACKETS

                year = self._parse_int(self._year_var, 2026)
                max_pcap = self._parse_max_pcap()
                events = parse_file(str(path), default_year=year, max_pcap_packets=max_pcap)
                n = len(events)
                ml_requested = self._ml_var.get()
                ml_ok = ml_requested and n <= 100_000
                notes: list[str] = []
                suf = path.suffix.lower()
                if suf in (".pcap", ".pcapng") and max_pcap != 0:
                    if max_pcap is not None:
                        if max_pcap > 0 and len(events) >= max_pcap:
                            notes.append(
                                f"PCAP: loaded at most {max_pcap:,} packets (your limit). "
                                "Increase or enter 0 for no limit (may be slow)."
                            )
                    elif len(events) >= DEFAULT_MAX_PCAP_PACKETS:
                        notes.append(
                            f"PCAP: loaded the first {DEFAULT_MAX_PCAP_PACKETS:,} packets (default cap). "
                            "Raise Max PCAP packets or use 0 for no limit (may be slow)."
                        )
                if ml_requested and not ml_ok:
                    notes.append(
                        "ML (Isolation Forest): skipped — more than 100,000 parsed rows (prevents long freezes)."
                    )
                cfg = AnalysisConfig(
                    year=year,
                    fail_threshold=self._parse_int(self._fail_th, 5),
                    window_minutes=self._parse_int(self._win_m, 5),
                    business_start=self._parse_int(self._biz_s, 8),
                    business_end=self._parse_int(self._biz_e, 18),
                    ml_enabled=ml_ok,
                    enabled_detector_ids=self._enabled_ids(),
                )
                findings, _ = run_analysis(events, cfg)
                note_txt = "\n".join(notes)
                self.after(0, lambda: self._apply_results(events, findings, path, note_txt))
            except Exception:
                err = traceback.format_exc()
                self.after(0, lambda: self._on_error(err))

        self._prog.pack(fill="x", pady=(8, 0))
        self._prog.start()
        threading.Thread(target=work, daemon=True).start()

    def _on_error(self, err: str) -> None:
        self._prog.stop()
        self._prog.pack_forget()
        messagebox.showerror("Analysis failed", err[-800:])

    def _apply_results(
        self,
        events: list[ParsedEvent],
        findings: list[Finding],
        path: Path,
        performance_notes: str = "",
    ) -> None:
        self._prog.stop()
        self._prog.pack_forget()
        self._events = events
        self._findings = findings
        self._log_path = path

        parsed = [e for e in events if e.kind != EventKind.UNKNOWN]
        fails = sum(1 for e in parsed if e.kind == EventKind.LOGIN_FAILURE)
        oks = sum(1 for e in parsed if e.kind == EventKind.LOGIN_SUCCESS)
        packets = sum(1 for e in parsed if e.kind == EventKind.PACKET_RECORD)
        other = len(parsed) - fails - oks - packets

        overview = (
            f"File: {path}\n"
            f"Parsed lines (non-unknown): {len(parsed)}\n"
            f"  Auth failures: {fails}\n"
            f"  Auth success: {oks}\n"
            f"  Packet rows (Wireshark/tshark/pcap): {packets}\n"
            f"  Other (password changes, lockouts, probes, etc.): {other}\n\n"
            f"Findings (detectors): {len(findings)}\n"
        )
        if performance_notes.strip():
            overview += f"\nPerformance / limits:\n{performance_notes}\n"
        self._overview.configure(state="normal")
        self._overview.delete("0.0", "end")
        self._overview.insert("0.0", overview)
        self._overview.configure(state="disabled")

        for item in self._tree.get_children():
            self._tree.delete(item)
        sorted_f = sorted(
            findings,
            key=lambda x: ({"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(x.severity, 5), x.category),
        )
        for i, f in enumerate(sorted_f):
            self._tree.insert(
                "",
                "end",
                iid=str(i),
                values=(f.severity.upper(), f.category, f.title, f.detail[:200]),
            )
        self._finding_by_row = {str(i): f for i, f in enumerate(sorted_f)}

        kinds: dict[str, int] = {}
        for e in events:
            if e.kind != EventKind.UNKNOWN:
                kinds[e.kind.value] = kinds.get(e.kind.value, 0) + 1
        mix_txt = "Event kinds (parsed):\n\n"
        for k, v in sorted(kinds.items(), key=lambda x: -x[1]):
            mix_txt += f"  {k}: {v}\n"
        self._mix.delete("0.0", "end")
        self._mix.insert("0.0", mix_txt)

        from .log_category_ai import build_category_insights_text

        self._cat_ai.configure(state="normal")
        self._cat_ai.delete("0.0", "end")
        self._cat_ai.insert("0.0", build_category_insights_text(findings))
        self._cat_ai.configure(state="disabled")

        from .log_file_info import build_log_file_info_text

        self._log_file_info.configure(state="normal")
        self._log_file_info.delete("0.0", "end")
        self._log_file_info.insert("0.0", build_log_file_info_text(events, path, performance_notes))
        self._log_file_info.configure(state="disabled")

    def _on_tree_select(self, _evt=None) -> None:
        sel = self._tree.selection()
        if not sel:
            return
        f = getattr(self, "_finding_by_row", {}).get(sel[0])
        if not f:
            return
        self._detail.delete("0.0", "end")
        self._detail.insert("0.0", f"{f.title}\n\n{f.detail}\n\nEvidence:\n")
        for line in f.evidence:
            self._detail.insert("end", f"  {line}\n")

    def _export(self) -> None:
        if not self._findings:
            messagebox.showinfo("Nothing to export", "Run analysis first.")
            return
        p = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
        )
        if not p:
            return
        payload = {
            "source_log": str(self._log_path) if self._log_path else None,
            "findings": [asdict(f) for f in self._findings],
        }
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        messagebox.showinfo("Exported", f"Saved to {p}")

    def _export_html(self) -> None:
        if not self._events:
            messagebox.showinfo("Nothing to export", "Run analysis first.")
            return
        p = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML report", "*.html"), ("All files", "*.*")],
        )
        if not p:
            return
        from .log_category_ai import build_html_log_report

        html = build_html_log_report(
            str(self._log_path) if self._log_path else None,
            self._events,
            self._findings,
        )
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(html)
        messagebox.showinfo("Report saved", f"HTML report written to {p}")


def launch(initial_log: str | None = None) -> None:
    """Open the unified Security Operations Suite (log + cloud)."""
    from .suite_app import SecuritySuiteApp

    app = SecuritySuiteApp(initial_log=initial_log)
    app.mainloop()

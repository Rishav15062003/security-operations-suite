"""
Mini ARES — attack surface tab (recon + rule-based “why risky” text).
"""
from __future__ import annotations

import json
import platform
import threading
import traceback
from dataclasses import asdict
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk

from .app_ui import _FONT_BODY, _FONT_SMALL, install_scrollable_wheel_fix

_FONT_TAB = ("Segoe UI", 14, "bold") if platform.system() == "Windows" else ("Ubuntu", 14, "bold")


class AttackSurfaceFrame(ctk.CTkFrame):
    def __init__(self, master: ctk.Misc, **kwargs) -> None:
        super().__init__(master, fg_color=("#0a0a12", "#0a0a12"), **kwargs)
        self._rows: list = []
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self._build()

    def _build(self) -> None:
        side = ctk.CTkFrame(self, width=360, corner_radius=0, fg_color=("#1a1a2e", "#1a1a2e"))
        side.grid(row=0, column=0, sticky="nsew")
        side.grid_propagate(False)
        side.grid_rowconfigure(0, weight=1)
        side.grid_columnconfigure(0, weight=1)

        side_scroll = ctk.CTkScrollableFrame(
            side,
            fg_color=("#1a1a2e", "#1a1a2e"),
            corner_radius=0,
        )
        side_scroll.grid(row=0, column=0, sticky="nsew")

        ctk.CTkLabel(
            side_scroll,
            text="Mini ARES",
            font=_FONT_TAB,
            text_color=("#e8e8f0", "#e8e8f0"),
        ).pack(anchor="w", padx=20, pady=(20, 4))
        ctk.CTkLabel(
            side_scroll,
            text="Passive subdomains · port scan · tech fingerprint",
            font=_FONT_SMALL,
            text_color=("#8892a6", "#8892a6"),
        ).pack(anchor="w", padx=20, pady=(0, 8))

        ctk.CTkLabel(
            side_scroll,
            text="Only scan systems you own or have written permission to test.",
            font=("Segoe UI", 10) if platform.system() == "Windows" else ("Ubuntu", 10),
            text_color=("#c45c5c", "#c45c5c"),
            wraplength=320,
            justify="left",
        ).pack(anchor="w", padx=16, pady=(0, 12))

        self._domain = ctk.StringVar(value="")
        df = ctk.CTkFrame(side_scroll, fg_color="transparent")
        df.pack(fill="x", padx=16, pady=4)
        ctk.CTkLabel(df, text="Target domain (apex)", font=_FONT_BODY).pack(anchor="w")
        ctk.CTkEntry(df, textvariable=self._domain, width=300, placeholder_text="example.com").pack(fill="x", pady=4)

        self._max_hosts = ctk.StringVar(value="15")
        mf = ctk.CTkFrame(side_scroll, fg_color="transparent")
        mf.pack(fill="x", padx=16, pady=6)
        ctk.CTkLabel(mf, text="Max hosts to port-scan", font=_FONT_SMALL).pack(anchor="w")
        ctk.CTkEntry(mf, textvariable=self._max_hosts, width=80).pack(anchor="w", pady=4)

        self._subfinder = ctk.BooleanVar(value=True)
        self._nmap = ctk.BooleanVar(value=True)
        self._deep = ctk.BooleanVar(value=False)
        self._os_detect = ctk.BooleanVar(value=False)
        ctk.CTkSwitch(side_scroll, text="Use subfinder (if installed)", variable=self._subfinder).pack(
            anchor="w", padx=16, pady=4
        )
        ctk.CTkSwitch(side_scroll, text="Prefer nmap (else TCP connect)", variable=self._nmap).pack(
            anchor="w", padx=16, pady=4
        )
        ctk.CTkSwitch(
            side_scroll,
            text="In-depth scan (nmap -sV, service versions, NSE scripts)",
            variable=self._deep,
        ).pack(anchor="w", padx=16, pady=4)
        ctk.CTkSwitch(
            side_scroll,
            text="OS detection (nmap -O; may need admin / slower)",
            variable=self._os_detect,
        ).pack(anchor="w", padx=16, pady=4)

        ctk.CTkLabel(
            side_scroll,
            text="External tools (nmap, subfinder)",
            font=("Segoe UI", 12, "bold") if platform.system() == "Windows" else ("Ubuntu", 12, "bold"),
        ).pack(anchor="w", padx=16, pady=(12, 4))
        ctk.CTkLabel(
            side_scroll,
            text="Scans work without these (crt.sh + TCP connect). Install for faster/better results.",
            font=("Segoe UI", 10) if platform.system() == "Windows" else ("Ubuntu", 10),
            text_color=("#6b7280", "#6b7280"),
            wraplength=320,
            justify="left",
        ).pack(anchor="w", padx=16, pady=(0, 4))
        self._tool_log = ctk.CTkTextbox(
            side_scroll,
            height=110,
            font=("Consolas", 10) if platform.system() == "Windows" else ("Ubuntu Mono", 10),
        )
        self._tool_log.pack(fill="x", padx=16, pady=4)
        self._tool_log.insert("0.0", "Click Check tools.\n")
        self._tool_log.configure(state="disabled")
        tbf = ctk.CTkFrame(side_scroll, fg_color="transparent")
        tbf.pack(fill="x", padx=16, pady=(0, 8))
        ctk.CTkButton(tbf, text="Check tools", width=130, command=self._check_tools).pack(side="left", padx=(0, 8))
        ctk.CTkButton(tbf, text="Install missing (auto)", width=180, command=self._install_tools_clicked).pack(
            side="left", padx=(0, 8)
        )
        ctk.CTkButton(
            tbf,
            text="Help",
            width=70,
            fg_color="#2d3748",
            command=self._tools_help,
        ).pack(side="left")

        ctk.CTkLabel(
            side_scroll,
            text="FastAPI: python -m mini_ares -> http://127.0.0.1:8765/docs",
            font=("Consolas", 10) if platform.system() == "Windows" else ("Ubuntu Mono", 10),
            text_color=("#5c6370", "#5c6370"),
            wraplength=320,
        ).pack(anchor="w", padx=16, pady=(8, 4))

        btn_row = ctk.CTkFrame(side_scroll, fg_color="transparent")
        btn_row.pack(fill="x", padx=16, pady=12)
        ctk.CTkButton(
            btn_row,
            text="Run surface scan",
            height=40,
            font=("Segoe UI", 13, "bold") if platform.system() == "Windows" else ("Ubuntu", 13, "bold"),
            command=self._run_clicked,
        ).pack(fill="x", pady=4)
        ctk.CTkButton(btn_row, text="Export JSON…", fg_color="#2d3748", command=self._export).pack(fill="x", pady=4)
        ctk.CTkButton(btn_row, text="Export HTML report…", fg_color="#1e3a5f", command=self._export_html).pack(
            fill="x", pady=4
        )

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
        tabs.add("Category AI")
        tabs.add("Why this is risky")

        fin = tabs.tab("Findings")
        fin.grid_columnconfigure(0, weight=1)
        fin.grid_rowconfigure(0, weight=1)
        tree_frame = ctk.CTkFrame(fin, fg_color="transparent")
        tree_frame.grid(row=0, column=0, sticky="nsew")
        tree_frame.grid_columnconfigure(0, weight=1)
        tree_frame.grid_rowconfigure(0, weight=1)
        self._tree = ttk.Treeview(
            tree_frame,
            columns=("sev", "cat", "title", "target"),
            show="headings",
            height=22,
        )
        _style = ttk.Style()
        if "clam" in _style.theme_names():
            _style.theme_use("clam")
        _style.configure("Treeview", background="#1e1e2e", foreground="#e4e4e7", fieldbackground="#1e1e2e", rowheight=24)
        self._tree.heading("sev", text="Severity")
        self._tree.heading("cat", text="Category")
        self._tree.heading("title", text="Title")
        self._tree.heading("target", text="Target")
        self._tree.column("sev", width=72)
        self._tree.column("cat", width=90)
        self._tree.column("title", width=420)
        self._tree.column("target", width=280)
        ys = ttk.Scrollbar(tree_frame, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=ys.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")

        self._detail = ctk.CTkTextbox(fin, height=140, font=_FONT_SMALL)
        self._detail.grid(row=1, column=0, sticky="ew", pady=8)
        self._tree.bind("<<TreeviewSelect>>", self._on_select)

        cai = tabs.tab("Category AI")
        ctk.CTkLabel(
            cai,
            text="Per-category intelligence (subdomain, port, technology, risk) for awareness and reporting.",
            font=_FONT_SMALL,
            text_color=("#8892a6", "#8892a6"),
        ).pack(anchor="w", padx=8, pady=(8, 4))
        self._surf_cat_ai = ctk.CTkTextbox(
            cai,
            font=("Segoe UI", 12) if platform.system() == "Windows" else ("Ubuntu", 12),
        )
        self._surf_cat_ai.pack(fill="both", expand=True, padx=8, pady=8)
        self._surf_cat_ai.insert("0.0", "Run a surface scan to populate category intelligence.\n")
        self._surf_cat_ai.configure(state="disabled")

        self._why = ctk.CTkTextbox(tabs.tab("Why this is risky"), font=_FONT_SMALL)
        self._why.pack(fill="both", expand=True, padx=8, pady=8)
        self._why.insert("0.0", "Select a row to see the rule-based risk explanation.\n")
        self._why.configure(state="disabled")

        self.after(400, self._check_tools)

    def _set_tool_log(self, text: str) -> None:
        self._tool_log.configure(state="normal")
        self._tool_log.delete("0.0", "end")
        self._tool_log.insert("0.0", text)
        self._tool_log.configure(state="disabled")

    def _check_tools(self) -> None:
        try:
            from mini_ares.toolchain import format_tool_status

            self._set_tool_log(format_tool_status())
        except Exception as e:
            self._set_tool_log(f"Could not check tools: {e}")

    def _install_tools_clicked(self) -> None:
        self._set_tool_log("Running installer (this can take several minutes)...\nDo not close the app.\n")

        def work() -> None:
            try:
                from mini_ares.toolchain import run_auto_install

                log = run_auto_install()
                self.after(0, lambda: self._set_tool_log(log))
            except Exception:
                self.after(0, lambda: self._set_tool_log(traceback.format_exc()[-4000:]))

        threading.Thread(target=work, daemon=True).start()

    def _tools_help(self) -> None:
        messagebox.showinfo(
            "Mini ARES tools",
            "Auto-install tries:\n"
            "  Windows: winget install Nmap; Go install subfinder (if Go is installed).\n"
            "  Linux: pkexec apt-get/dnf install nmap; Go install subfinder.\n\n"
            "Manual scripts (run in a terminal):\n"
            "  Windows PowerShell: .\\scripts\\install_mini_ares_tools.ps1\n"
            "  Linux: bash scripts/install_mini_ares_tools.sh\n\n"
            "Without nmap, port checks use Python TCP connect.\n"
            "Without subfinder, subdomain discovery uses crt.sh only.\n\n"
            "In-depth scan: nmap -sV plus safe NSE scripts (http-title, ssl-cert, ssh-hostkey, …).\n"
            "OS detection: nmap -O --osscan-guess (may require elevation on some systems).",
        )

    def _parse_int(self, v: str, default: int) -> int:
        try:
            return max(1, min(80, int(v.strip())))
        except ValueError:
            return default

    def _run_clicked(self) -> None:
        d = self._domain.get().strip()
        if not d or "." not in d:
            messagebox.showerror("Invalid domain", "Enter an apex domain like example.com")
            return

        def work() -> None:
            try:
                from mini_ares.recon import run_attack_surface_scan

                findings = run_attack_surface_scan(
                    d,
                    max_hosts=self._parse_int(self._max_hosts.get(), 15),
                    use_subfinder=self._subfinder.get(),
                    prefer_nmap=self._nmap.get(),
                    deep_scan=self._deep.get(),
                    os_detection=self._os_detect.get(),
                )
                self.after(0, lambda: self._apply(findings))
            except Exception:
                err = traceback.format_exc()
                self.after(0, lambda: self._err(err))

        self._prog.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 12))
        self._prog.start()
        threading.Thread(target=work, daemon=True).start()

    def _err(self, err: str) -> None:
        self._prog.stop()
        self._prog.grid_forget()
        messagebox.showerror("Scan failed", err[-1200:])

    def _apply(self, findings: list) -> None:
        self._prog.stop()
        self._prog.grid_forget()
        self._rows = findings
        for item in self._tree.get_children():
            self._tree.delete(item)
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_f = sorted(findings, key=lambda f: (order.get(f.severity, 5), f.category, f.title))
        for i, f in enumerate(sorted_f):
            self._tree.insert(
                "",
                "end",
                iid=str(i),
                values=(f.severity.upper(), f.category, f.title[:100], f.target[:80]),
            )
        self._map = {str(i): f for i, f in enumerate(sorted_f)}

        from mini_ares.category_insights import build_category_insights_text

        self._surf_cat_ai.configure(state="normal")
        self._surf_cat_ai.delete("0.0", "end")
        self._surf_cat_ai.insert("0.0", build_category_insights_text(findings))
        self._surf_cat_ai.configure(state="disabled")

    def _on_select(self, _e=None) -> None:
        sel = self._tree.selection()
        if not sel:
            return
        f = getattr(self, "_map", {}).get(sel[0])
        if not f:
            return
        self._detail.delete("0.0", "end")
        extra_txt = ""
        if getattr(f, "extra", None):
            try:
                extra_txt = "\n\n--- structured extra ---\n" + json.dumps(f.extra, indent=2, default=str)[:12000]
            except Exception:
                extra_txt = ""
        self._detail.insert(
            "0.0",
            f"{f.title}\n\n{f.detail}\n\n---\nWhy this is risky:\n{f.why_risky}\n{extra_txt}",
        )
        self._why.configure(state="normal")
        self._why.delete("0.0", "end")
        self._why.insert("0.0", f"Why this is risky\n\n{f.why_risky}\n")
        self._why.configure(state="disabled")

    def _export(self) -> None:
        if not self._rows:
            messagebox.showinfo("Nothing to export", "Run a scan first.")
            return
        p = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if not p:
            return
        payload = {"findings": [asdict(f) for f in self._rows]}
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, default=str)
        messagebox.showinfo("Exported", f"Saved to {p}")

    def _export_html(self) -> None:
        if not self._rows:
            messagebox.showinfo("Nothing to export", "Run a scan first.")
            return
        p = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML report", "*.html"), ("All files", "*.*")],
        )
        if not p:
            return
        from mini_ares.category_insights import build_html_surface_report

        html = build_html_surface_report(self._rows)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(html)
        messagebox.showinfo("Report saved", f"HTML report written to {p}")

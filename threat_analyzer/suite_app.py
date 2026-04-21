"""
Unified desktop app: log threat analysis + cloud misconfiguration scanning.
"""
from __future__ import annotations

import json
import platform
import threading
import traceback
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk

from .app_ui import LogAnalysisFrame, _FONT_BODY, _FONT_SMALL, install_scrollable_wheel_fix
from .attack_surface_ui import AttackSurfaceFrame
from .network_traffic_ui import NetworkTrafficFrame
from .phishing_ui import PhishingFrame

_FONT_TAB = ("Segoe UI", 14, "bold") if platform.system() == "Windows" else ("Ubuntu", 14, "bold")


def _cloud_finding_to_dict(f) -> dict:
    return {
        "code": f.code,
        "title": f.title,
        "detail": f.detail,
        "severity": f.severity.value,
        "provider": f.provider.value,
        "resource_id": f.resource_id,
        "resource_type": f.resource_type,
        "region": f.region,
    }


class CloudScanFrame(ctk.CTkFrame):
    """Cloud misconfiguration scanner UI."""

    def __init__(self, master: ctk.Misc, **kwargs) -> None:
        super().__init__(master, fg_color=("#0a0a12", "#0a0a12"), **kwargs)
        self._findings: list = []
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self._build()

    def _build(self) -> None:
        side = ctk.CTkFrame(self, width=340, corner_radius=0, fg_color=("#1a1a2e", "#1a1a2e"))
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
            text="Cloud misconfiguration",
            font=_FONT_TAB,
            text_color=("#e8e8f0", "#e8e8f0"),
        ).pack(anchor="w", padx=20, pady=(20, 4))
        ctk.CTkLabel(
            side_scroll,
            text="AWS / Azure live API + offline JSON",
            font=_FONT_SMALL,
            text_color=("#8892a6", "#8892a6"),
        ).pack(anchor="w", padx=20, pady=(0, 12))

        self._config_path = ctk.StringVar(value="")
        row = ctk.CTkFrame(side_scroll, fg_color="transparent")
        row.pack(fill="x", padx=16, pady=4)
        ctk.CTkLabel(row, text="Config JSON (optional)", font=_FONT_BODY).pack(anchor="w")
        ctk.CTkEntry(row, textvariable=self._config_path, width=300, placeholder_text="config.example.json").pack(
            fill="x", pady=4
        )
        ctk.CTkButton(row, text="Browse…", width=120, command=self._browse_config).pack(anchor="w")

        self._regions_var = ctk.StringVar(value="us-east-1")
        rf = ctk.CTkFrame(side_scroll, fg_color="transparent")
        rf.pack(fill="x", padx=16, pady=6)
        ctk.CTkLabel(rf, text="AWS regions (comma-separated)", font=_FONT_SMALL).pack(anchor="w")
        ctk.CTkEntry(rf, textvariable=self._regions_var, width=300).pack(fill="x", pady=4)

        self._azure_sub = ctk.StringVar(value="")
        af = ctk.CTkFrame(side_scroll, fg_color="transparent")
        af.pack(fill="x", padx=16, pady=6)
        ctk.CTkLabel(af, text="Azure subscription ID (or env AZURE_SUBSCRIPTION_ID)", font=_FONT_SMALL).pack(anchor="w")
        ctk.CTkEntry(af, textvariable=self._azure_sub, width=300).pack(fill="x", pady=4)

        self._aws_var = ctk.BooleanVar(value=True)
        self._azure_var = ctk.BooleanVar(value=False)
        ctk.CTkSwitch(side_scroll, text="Scan AWS (S3, SG, API GW v2, Lambda URLs)", variable=self._aws_var).pack(
            anchor="w", padx=16, pady=4
        )
        ctk.CTkSwitch(side_scroll, text="Scan Azure (storage, NSG, optional APIM)", variable=self._azure_var).pack(
            anchor="w", padx=16, pady=4
        )
        ctk.CTkLabel(
            side_scroll,
            text="For offline JSON only, turn off AWS and Azure.",
            font=("Segoe UI", 10) if platform.system() == "Windows" else ("Ubuntu", 10),
            text_color=("#6b7280", "#6b7280"),
            wraplength=300,
            justify="left",
        ).pack(anchor="w", padx=20, pady=(0, 6))

        self._json_path = ctk.StringVar(value="")
        jf = ctk.CTkFrame(side_scroll, fg_color="transparent")
        jf.pack(fill="x", padx=16, pady=8)
        ctk.CTkLabel(jf, text="Offline JSON (SG / bucket policy / NSG)", font=_FONT_SMALL).pack(anchor="w")
        ctk.CTkEntry(jf, textvariable=self._json_path, width=300).pack(fill="x", pady=4)
        ctk.CTkButton(jf, text="Browse JSON…", width=120, command=self._browse_json).pack(anchor="w")

        btn_row = ctk.CTkFrame(side_scroll, fg_color="transparent")
        btn_row.pack(fill="x", padx=16, pady=12)
        ctk.CTkButton(
            btn_row,
            text="Run cloud scan",
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
        tabs.add("Remediation")

        fin = tabs.tab("Findings")
        fin.grid_columnconfigure(0, weight=1)
        fin.grid_rowconfigure(0, weight=1)
        tree_frame = ctk.CTkFrame(fin, fg_color="transparent")
        tree_frame.grid(row=0, column=0, sticky="nsew")
        tree_frame.grid_columnconfigure(0, weight=1)
        tree_frame.grid_rowconfigure(0, weight=1)
        self._tree = ttk.Treeview(
            tree_frame,
            columns=("sev", "prov", "code", "title", "resource"),
            show="headings",
            height=20,
        )
        _style = ttk.Style()
        if "clam" in _style.theme_names():
            _style.theme_use("clam")
        _style.configure("Treeview", background="#1e1e2e", foreground="#e4e4e7", fieldbackground="#1e1e2e", rowheight=24)
        _style.configure("Treeview.Heading", background="#27273a", foreground="#e4e4e7")
        self._tree.heading("sev", text="Severity")
        self._tree.heading("prov", text="Cloud")
        self._tree.heading("code", text="Code")
        self._tree.heading("title", text="Title")
        self._tree.heading("resource", text="Resource")
        self._tree.column("sev", width=72)
        self._tree.column("prov", width=56)
        self._tree.column("code", width=160)
        self._tree.column("title", width=280)
        self._tree.column("resource", width=360)
        ys = ttk.Scrollbar(tree_frame, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=ys.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")

        self._detail = ctk.CTkTextbox(fin, height=120, font=_FONT_SMALL)
        self._detail.grid(row=1, column=0, sticky="ew", pady=8)
        self._tree.bind("<<TreeviewSelect>>", self._on_tree_select)

        cai = tabs.tab("Category AI")
        ctk.CTkLabel(
            cai,
            text="Intelligence by cloud area (AWS / Azure / offline) for awareness and reporting.",
            font=_FONT_SMALL,
            text_color=("#8892a6", "#8892a6"),
        ).pack(anchor="w", padx=8, pady=(8, 4))
        self._cloud_cat_ai = ctk.CTkTextbox(
            cai,
            font=("Segoe UI", 12) if platform.system() == "Windows" else ("Ubuntu", 12),
        )
        self._cloud_cat_ai.pack(fill="both", expand=True, padx=8, pady=8)
        self._cloud_cat_ai.insert("0.0", "Run a cloud scan to populate category intelligence.\n")
        self._cloud_cat_ai.configure(state="disabled")

        self._remediation = ctk.CTkTextbox(tabs.tab("Remediation"), font=("Consolas", 11) if platform.system() == "Windows" else ("Ubuntu Mono", 11))
        self._remediation.pack(fill="both", expand=True, padx=8, pady=8)

        self._remediation.insert("0.0", "Run a scan to see suggested fixes (AWS CLI / Azure CLI / console).\n")
        self._remediation.configure(state="disabled")

    def _browse_config(self) -> None:
        p = filedialog.askopenfilename(filetypes=[("JSON", "*.json"), ("All", "*.*")])
        if p:
            self._config_path.set(p)

    def _browse_json(self) -> None:
        p = filedialog.askopenfilename(filetypes=[("JSON", "*.json"), ("All", "*.*")])
        if p:
            self._json_path.set(p)

    def _run_clicked(self) -> None:
        cfg_path = self._config_path.get().strip()
        json_path = self._json_path.get().strip()
        run_aws = self._aws_var.get()
        run_azure = self._azure_var.get()

        if not run_aws and not run_azure and not json_path:
            messagebox.showinfo(
                "Nothing to scan",
                "Enable AWS and/or Azure, or choose an offline JSON file (exported SG, bucket policy, or NSG).",
            )
            return

        def work() -> None:
            try:
                from cloud_scanner.config_loader import ScanConfig, apply_env_defaults, load_config

                if cfg_path and Path(cfg_path).is_file():
                    cfg = load_config(cfg_path)
                else:
                    cfg = ScanConfig()
                apply_env_defaults(cfg)
                sub = self._azure_sub.get().strip()
                if sub:
                    cfg.azure_subscription_id = sub
                regions = [r.strip() for r in self._regions_var.get().split(",") if r.strip()]
                if regions:
                    cfg.aws_regions = regions

                findings: list = []
                if json_path and Path(json_path).is_file():
                    from cloud_scanner.json_analyzer import analyze_json_file

                    findings.extend(analyze_json_file(json_path))
                if run_aws:
                    from cloud_scanner.aws_scanner import scan_aws

                    findings.extend(scan_aws(cfg))
                if run_azure:
                    from cloud_scanner.azure_scanner import scan_azure

                    findings.extend(scan_azure(cfg))

                self.after(0, lambda: self._apply_results(findings))
            except Exception:
                err = traceback.format_exc()
                self.after(0, lambda: self._on_error(err))

        self._prog.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 12))
        self._prog.start()
        threading.Thread(target=work, daemon=True).start()

    def _on_error(self, err: str) -> None:
        self._prog.stop()
        self._prog.grid_forget()
        messagebox.showerror("Cloud scan failed", err[-1200:])

    def _apply_results(self, findings: list) -> None:
        self._prog.stop()
        self._prog.grid_forget()
        self._findings = findings

        for item in self._tree.get_children():
            self._tree.delete(item)

        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_f = sorted(
            findings,
            key=lambda f: (order.get(f.severity.value, 5), f.provider.value, f.title),
        )
        for i, f in enumerate(sorted_f):
            self._tree.insert(
                "",
                "end",
                iid=str(i),
                values=(
                    f.severity.value.upper(),
                    f.provider.value,
                    f.code,
                    f.title[:120],
                    f"{f.resource_type}: {f.resource_id}" + (f" ({f.region})" if f.region else ""),
                ),
            )
        self._row_map = {str(i): f for i, f in enumerate(sorted_f)}

        from cloud_scanner.remediation import format_remediation_block

        self._remediation.configure(state="normal")
        self._remediation.delete("0.0", "end")
        seen: set[str] = set()
        for f in sorted_f:
            if f.code in seen:
                continue
            seen.add(f.code)
            self._remediation.insert("end", f"[{f.code}]\n{format_remediation_block(f.code)}\n\n")
        self._remediation.configure(state="disabled")

        from cloud_scanner.reporting import build_category_insights_text

        self._cloud_cat_ai.configure(state="normal")
        self._cloud_cat_ai.delete("0.0", "end")
        self._cloud_cat_ai.insert("0.0", build_category_insights_text(findings))
        self._cloud_cat_ai.configure(state="disabled")

    def _on_tree_select(self, _evt=None) -> None:
        sel = self._tree.selection()
        if not sel:
            return
        f = getattr(self, "_row_map", {}).get(sel[0])
        if not f:
            return
        self._detail.delete("0.0", "end")
        self._detail.insert("0.0", f"{f.title}\n\n{f.detail}\n")

    def _export(self) -> None:
        if not self._findings:
            messagebox.showinfo("Nothing to export", "Run a cloud scan first.")
            return
        p = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if not p:
            return
        payload = {"findings": [_cloud_finding_to_dict(f) for f in self._findings]}
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        messagebox.showinfo("Exported", f"Saved to {p}")

    def _export_html(self) -> None:
        if not self._findings:
            messagebox.showinfo("Nothing to export", "Run a cloud scan first.")
            return
        p = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML report", "*.html"), ("All files", "*.*")],
        )
        if not p:
            return
        from cloud_scanner.reporting import build_html_cloud_report

        html = build_html_cloud_report(self._findings)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(html)
        messagebox.showinfo("Report saved", f"HTML report written to {p}")


class SecuritySuiteApp(ctk.CTk):
    """Single window: Log analysis, cloud, attack surface, phishing, network traffic."""

    def __init__(self, initial_log: str | None = None) -> None:
        super().__init__()
        self.title("Security Operations Suite")
        self.geometry("1320x820")
        self.minsize(1100, 720)

        tv = ctk.CTkTabview(self, anchor="w")
        tv.pack(fill="both", expand=True, padx=10, pady=10)

        tv.add("Log analysis")
        tv.add("Cloud security")
        tv.add("Attack surface")
        tv.add("Phishing detector")
        tv.add("Network traffic")

        LogAnalysisFrame(tv.tab("Log analysis"), initial_log=initial_log).pack(fill="both", expand=True)
        CloudScanFrame(tv.tab("Cloud security")).pack(fill="both", expand=True)
        AttackSurfaceFrame(tv.tab("Attack surface")).pack(fill="both", expand=True)
        PhishingFrame(tv.tab("Phishing detector")).pack(fill="both", expand=True)
        NetworkTrafficFrame(tv.tab("Network traffic")).pack(fill="both", expand=True)


def launch_suite(initial_log: str | None = None) -> None:
    app = SecuritySuiteApp(initial_log=initial_log)
    app.mainloop()

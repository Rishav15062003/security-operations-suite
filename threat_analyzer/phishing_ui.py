"""
Phishing detection: URL / text / .eml + heuristics + optional VirusTotal.
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


class PhishingFrame(ctk.CTkFrame):
    def __init__(self, master: ctk.Misc, **kwargs) -> None:
        super().__init__(master, fg_color=("#0a0a12", "#0a0a12"), **kwargs)
        self._last_report = None
        self._eml_path = ctk.StringVar(value="")
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self._build()

    def _build(self) -> None:
        side = ctk.CTkFrame(self, width=380, corner_radius=0, fg_color=("#1a1a2e", "#1a1a2e"))
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
            text="Phishing detection",
            font=_FONT_TAB,
            text_color=("#e8e8f0", "#e8e8f0"),
        ).pack(anchor="w", padx=20, pady=(20, 4))
        ctk.CTkLabel(
            side_scroll,
            text="EML + URL heuristics + TLS/DNS + VirusTotal (optional)",
            font=_FONT_SMALL,
            text_color=("#8892a6", "#8892a6"),
        ).pack(anchor="w", padx=20, pady=(0, 8))

        ctk.CTkLabel(
            side_scroll,
            text="Paste a URL or email body, or load a .eml file. "
            "VirusTotal needs a free API key (VT_API_KEY). Rate limits apply.",
            font=("Segoe UI", 10) if platform.system() == "Windows" else ("Ubuntu", 10),
            text_color=("#6b7280", "#6b7280"),
            wraplength=340,
            justify="left",
        ).pack(anchor="w", padx=16, pady=(0, 10))

        emf = ctk.CTkFrame(side_scroll, fg_color="transparent")
        emf.pack(fill="x", padx=16, pady=4)
        ctk.CTkLabel(emf, text="Optional .eml file", font=_FONT_SMALL).pack(anchor="w")
        er = ctk.CTkFrame(emf, fg_color="transparent")
        er.pack(fill="x", pady=4)
        ctk.CTkEntry(er, textvariable=self._eml_path, width=240, placeholder_text="path to message.eml").pack(
            side="left", padx=(0, 8)
        )
        ctk.CTkButton(er, text="Browse…", width=90, command=self._browse_eml).pack(side="left")

        self._input = ctk.CTkTextbox(
            side_scroll,
            height=120,
            font=("Consolas", 11) if platform.system() == "Windows" else ("Ubuntu Mono", 11),
        )
        self._input.pack(fill="x", padx=16, pady=4)
        self._input.insert("0.0", "https://\n")

        self._vt_key = ctk.StringVar(value="")
        vtf = ctk.CTkFrame(side_scroll, fg_color="transparent")
        vtf.pack(fill="x", padx=16, pady=4)
        ctk.CTkLabel(vtf, text="VirusTotal API key (optional)", font=_FONT_SMALL).pack(anchor="w")
        ctk.CTkEntry(
            vtf,
            textvariable=self._vt_key,
            width=320,
            placeholder_text="paste key or set VT_API_KEY in environment",
            show="*",
        ).pack(fill="x", pady=4)

        self._use_vt = ctk.BooleanVar(value=True)
        ctk.CTkSwitch(
            side_scroll,
            text="Query VirusTotal (URLs + attachment SHA256)",
            variable=self._use_vt,
        ).pack(anchor="w", padx=16, pady=4)

        self._follow = ctk.BooleanVar(value=True)
        ctk.CTkSwitch(
            side_scroll,
            text="Follow redirects for URL analysis",
            variable=self._follow,
        ).pack(anchor="w", padx=16, pady=4)

        ctk.CTkLabel(
            side_scroll,
            text="Tools",
            font=("Segoe UI", 12, "bold") if platform.system() == "Windows" else ("Ubuntu", 12, "bold"),
        ).pack(anchor="w", padx=16, pady=(12, 4))
        self._tool_log = ctk.CTkTextbox(
            side_scroll,
            height=90,
            font=("Consolas", 9) if platform.system() == "Windows" else ("Ubuntu Mono", 9),
        )
        self._tool_log.pack(fill="x", padx=16, pady=4)
        self._tool_log.insert("0.0", "Click Check tools.\n")
        self._tool_log.configure(state="disabled")
        tbf = ctk.CTkFrame(side_scroll, fg_color="transparent")
        tbf.pack(fill="x", padx=16, pady=(0, 8))
        ctk.CTkButton(tbf, text="Check tools", width=130, command=self._check_tools).pack(side="left", padx=(0, 8))
        ctk.CTkButton(tbf, text="Install missing (auto)", width=180, command=self._install_tools).pack(side="left")

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
        tabs.add("Signals")
        tabs.add("AI summary")
        tabs.add("Extracted URLs")
        tabs.add("VirusTotal")
        tabs.add("EML & attachments")

        sig = tabs.tab("Signals")
        sig.grid_columnconfigure(0, weight=1)
        sig.grid_rowconfigure(1, weight=1)

        self._verdict_lbl = ctk.CTkLabel(
            sig,
            text="Verdict: —   Score: —   Host: —",
            font=("Segoe UI", 12, "bold") if platform.system() == "Windows" else ("Ubuntu", 12, "bold"),
            text_color=("#a5b4fc", "#a5b4fc"),
        )
        self._verdict_lbl.grid(row=0, column=0, sticky="w", padx=4, pady=(0, 8))

        tree_frame = ctk.CTkFrame(sig, fg_color="transparent")
        tree_frame.grid(row=1, column=0, sticky="nsew")
        tree_frame.grid_columnconfigure(0, weight=1)
        tree_frame.grid_rowconfigure(0, weight=1)
        self._tree = ttk.Treeview(
            tree_frame,
            columns=("sev", "code", "title"),
            show="headings",
            height=20,
        )
        _style = ttk.Style()
        if "clam" in _style.theme_names():
            _style.theme_use("clam")
        _style.configure("Treeview", background="#1e1e2e", foreground="#e4e4e7", fieldbackground="#1e1e2e", rowheight=24)
        _style.configure("Treeview.Heading", background="#27273a", foreground="#e4e4e7")
        self._tree.heading("sev", text="Severity")
        self._tree.heading("code", text="Code")
        self._tree.heading("title", text="Finding")
        self._tree.column("sev", width=80)
        self._tree.column("code", width=140)
        self._tree.column("title", width=480)
        ys = ttk.Scrollbar(tree_frame, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=ys.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")

        self._detail = ctk.CTkTextbox(sig, height=120, font=_FONT_SMALL)
        self._detail.grid(row=2, column=0, sticky="ew", pady=8)
        self._tree.bind("<<TreeviewSelect>>", self._on_select)

        self._ai = ctk.CTkTextbox(
            tabs.tab("AI summary"),
            font=("Segoe UI", 12) if platform.system() == "Windows" else ("Ubuntu", 12),
        )
        self._ai.pack(fill="both", expand=True, padx=8, pady=8)
        self._ai.insert("0.0", "Run analysis to see the narrative summary.\n")

        self._urls_box = ctk.CTkTextbox(
            tabs.tab("Extracted URLs"),
            font=("Consolas", 11) if platform.system() == "Windows" else ("Ubuntu Mono", 11),
        )
        self._urls_box.pack(fill="both", expand=True, padx=8, pady=8)
        self._urls_box.insert("0.0", "Extracted links appear here.\n")

        self._vt_box = ctk.CTkTextbox(
            tabs.tab("VirusTotal"),
            font=("Consolas", 10) if platform.system() == "Windows" else ("Ubuntu Mono", 10),
        )
        self._vt_box.pack(fill="both", expand=True, padx=8, pady=8)
        self._vt_box.insert("0.0", "VirusTotal raw lines appear here when a key is set.\n")

        self._eml_box = ctk.CTkTextbox(
            tabs.tab("EML & attachments"),
            font=("Consolas", 10) if platform.system() == "Windows" else ("Ubuntu Mono", 10),
        )
        self._eml_box.pack(fill="both", expand=True, padx=8, pady=8)
        self._eml_box.insert("0.0", "Load a .eml file to see subject, recipients, and attachment hashes.\n")

        self.after(400, self._check_tools)

    def _set_tool_log(self, text: str) -> None:
        self._tool_log.configure(state="normal")
        self._tool_log.delete("0.0", "end")
        self._tool_log.insert("0.0", text)
        self._tool_log.configure(state="disabled")

    def _check_tools(self) -> None:
        try:
            from phishing_detector import format_phishing_tool_status

            self._set_tool_log(format_phishing_tool_status())
        except Exception as e:
            self._set_tool_log(str(e))

    def _install_tools(self) -> None:
        self._set_tool_log("Running pip install (httpx, certifi)…\n")

        def work() -> None:
            try:
                from phishing_detector import run_phishing_auto_install

                log = run_phishing_auto_install()
                self.after(0, lambda: self._set_tool_log(log))
            except Exception:
                self.after(0, lambda: self._set_tool_log(traceback.format_exc()[-4000:]))

        threading.Thread(target=work, daemon=True).start()

    def _browse_eml(self) -> None:
        p = filedialog.askopenfilename(filetypes=[("Email", "*.eml"), ("All", "*.*")])
        if p:
            self._eml_path.set(p)

    def _on_select(self, _e=None) -> None:
        sel = self._tree.selection()
        if not sel or not self._last_report:
            return
        iid = sel[0]
        try:
            idx = int(iid)
            s = self._last_report.signals[idx]
            self._detail.delete("0.0", "end")
            self._detail.insert("0.0", f"{s.title}\n\n{s.detail}\n")
        except (ValueError, IndexError):
            pass

    def _run_clicked(self) -> None:
        text = self._input.get("0.0", "end").strip()
        eml = self._eml_path.get().strip()
        if not text and not eml:
            messagebox.showinfo("Empty", "Paste text / URL or choose a .eml file.")
            return
        if eml and not Path(eml).is_file():
            messagebox.showerror("Invalid file", f"EML not found: {eml}")
            return

        vt_key = self._vt_key.get().strip()
        use_vt = self._use_vt.get()

        def work() -> None:
            try:
                from phishing_detector import analyze_phishing

                rep = analyze_phishing(
                    text,
                    eml_path=eml if eml else None,
                    vt_api_key=vt_key or None,
                    use_virustotal=use_vt,
                    follow_redirects=self._follow.get(),
                )
                self.after(0, lambda: self._apply(rep))
            except Exception:
                err = traceback.format_exc()
                self.after(0, lambda: self._err(err))

        self._prog.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 12))
        self._prog.start()
        threading.Thread(target=work, daemon=True).start()

    def _err(self, err: str) -> None:
        self._prog.stop()
        self._prog.grid_forget()
        messagebox.showerror("Analysis failed", err[-1400:])

    def _apply(self, rep) -> None:
        self._prog.stop()
        self._prog.grid_forget()
        self._last_report = rep

        self._verdict_lbl.configure(
            text=f"Verdict: {rep.verdict.value.replace('_', ' ')}   Score: {rep.risk_score}/100   Host: {rep.host or '—'}"
        )

        for item in self._tree.get_children():
            self._tree.delete(item)
        for i, s in enumerate(rep.signals):
            self._tree.insert(
                "",
                "end",
                iid=str(i),
                values=(s.severity.upper(), s.code, s.title[:200]),
            )

        self._ai.delete("0.0", "end")
        self._ai.insert("0.0", rep.ai_summary or "(no summary)")

        self._urls_box.delete("0.0", "end")
        if rep.extracted_urls:
            self._urls_box.insert("0.0", "\n".join(rep.extracted_urls))
        else:
            self._urls_box.insert("0.0", rep.primary_url or "(none)")

        self._vt_box.delete("0.0", "end")
        self._vt_box.insert("0.0", rep.virustotal_text or "(VirusTotal not queried — add key or enable switch.)")

        self._eml_box.delete("0.0", "end")
        if rep.eml_path:
            lines = [
                f"File: {rep.eml_path}",
                f"Subject: {rep.eml_subject or ''}",
                f"From: {rep.eml_from or ''}",
                f"To: {rep.eml_to or ''}",
                f"Reply-To: {rep.eml_reply_to or ''}",
                f"Return-Path: {rep.eml_return_path or ''}",
                "",
                "Attachments:",
            ]
            for a in rep.eml_attachments:
                lines.append(f"  • {a.filename} ({a.size_bytes} bytes, {a.content_type})")
                lines.append(f"    SHA256: {a.sha256}")
            self._eml_box.insert("0.0", "\n".join(lines))
        else:
            self._eml_box.insert("0.0", "No .eml file loaded for this run.")

        self._detail.delete("0.0", "end")
        self._detail.insert("0.0", "Select a row above for detail.\n")

    def _export(self) -> None:
        if not self._last_report:
            messagebox.showinfo("Nothing to export", "Run analysis first.")
            return
        p = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if not p:
            return
        r = self._last_report
        payload = {
            "primary_url": r.primary_url,
            "normalized_url": r.normalized_url,
            "host": r.host,
            "risk_score": r.risk_score,
            "verdict": r.verdict.value,
            "extracted_urls": r.extracted_urls,
            "signals": [
                {"code": s.code, "severity": s.severity, "title": s.title, "detail": s.detail, "weight": s.weight}
                for s in r.signals
            ],
            "ai_summary": r.ai_summary,
            "virustotal_text": r.virustotal_text,
            "eml_path": r.eml_path,
            "eml_subject": r.eml_subject,
            "eml_from": r.eml_from,
            "eml_to": r.eml_to,
            "eml_reply_to": r.eml_reply_to,
            "eml_return_path": r.eml_return_path,
            "eml_attachments": [
                {
                    "filename": a.filename,
                    "content_type": a.content_type,
                    "size_bytes": a.size_bytes,
                    "sha256": a.sha256,
                }
                for a in r.eml_attachments
            ],
        }
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        messagebox.showinfo("Exported", f"Saved to {p}")

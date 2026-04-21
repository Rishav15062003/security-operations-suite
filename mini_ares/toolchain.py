"""
Optional external tools for Mini ARES: nmap (port scan), subfinder (subdomains), Go (to build subfinder).

Provides status checks and best-effort auto-install (Windows: winget; Linux: apt/dnf + go install).
"""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
from pathlib import Path

from .tool_paths import resolve_go_executable, resolve_nmap_executable, resolve_subfinder_executable


def has_nmap() -> bool:
    return resolve_nmap_executable() is not None


def has_subfinder() -> bool:
    return resolve_subfinder_executable() is not None


def has_go() -> bool:
    return resolve_go_executable() is not None


def _winget_exe() -> str | None:
    """Resolve winget.exe (PATH alias or LocalAppData WindowsApps)."""
    w = shutil.which("winget")
    if w:
        return w
    lad = os.environ.get("LOCALAPPDATA", "")
    if lad:
        cand = Path(lad) / "Microsoft" / "WindowsApps" / "winget.exe"
        if cand.is_file():
            return str(cand)
    return None


def has_winget() -> bool:
    return platform.system() == "Windows" and _winget_exe() is not None


def _nmap_status_text() -> str:
    exe = resolve_nmap_executable()
    if not exe:
        return "NOT FOUND (port scans use slower TCP connect fallback)"
    on_path = shutil.which("nmap") or (os.name == "nt" and shutil.which("nmap.exe"))
    if on_path:
        return "found"
    return f"found ({exe})"


def _subfinder_status_text() -> str:
    exe = resolve_subfinder_executable()
    if not exe:
        return "NOT FOUND (passive crt.sh still works)"
    if shutil.which("subfinder"):
        return "found"
    return f"found ({exe})"


def _go_status_text() -> str:
    exe = resolve_go_executable()
    if not exe:
        return "NOT FOUND (optional — for go install subfinder)"
    if shutil.which("go"):
        return "found"
    return f"found ({exe})"


def tool_status_lines() -> list[str]:
    """Human-readable lines for the UI."""
    sys = platform.system()
    lines = [
        f"Platform: {sys} ({platform.machine()})",
        f"  nmap:        {_nmap_status_text()}",
        f"  subfinder:   {_subfinder_status_text()}",
        f"  go:          {_go_status_text()}",
    ]
    if sys == "Windows":
        lines.append(f"  winget:      {'found' if has_winget() else 'not found (install Nmap manually or install App Installer)'}")
    return lines


def format_tool_status() -> str:
    return "\n".join(tool_status_lines())


def _run_logged(cmd: list[str], log: list[str], timeout: int = 600) -> int:
    log.append(f"$ {' '.join(cmd)}")
    try:
        # Do not use CREATE_NO_WINDOW on Windows: winget/go often need a real console
        # or they exit with misleading errors when spawned from a GUI.
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        log.append("  (command not found)")
        return 127
    except subprocess.TimeoutExpired:
        log.append("  (timeout)")
        return 124
    out = (p.stdout or "").strip()
    err = (p.stderr or "").strip()
    if out:
        log.append(out[-4000:])
    if err:
        log.append("stderr: " + err[-4000:])
    log.append(f"  exit code: {p.returncode}")
    return p.returncode


def install_tools_windows(log: list[str]) -> None:
    """Try winget for Nmap; try go install for subfinder. Requires user context that can run winget."""
    winget = _winget_exe()
    if not winget:
        log.append("winget not found on PATH. Install Nmap from https://nmap.org/download.html")
        log.append("Or install “App Installer” from the Microsoft Store, then re-open this app.")
    else:
        # Official winget id (see: winget search nmap) — was incorrectly Nmap.Nmap
        nmap_ids = ("Insecure.Nmap", "Nmap.Nmap")
        last_rc = 1
        for pkg_id in nmap_ids:
            log.append(f"Trying winget package id: {pkg_id}")
            last_rc = _run_logged(
                [
                    winget,
                    "install",
                    "-e",
                    "--id",
                    pkg_id,
                    "--accept-package-agreements",
                    "--accept-source-agreements",
                ],
                log,
                timeout=900,
            )
            blob = "\n".join(log).lower()
            if last_rc == 0:
                break
            if any(
                s in blob
                for s in (
                    "already installed",
                    "no newer package",
                    "no applicable upgrade",
                    "a newer version was not found",
                )
            ):
                break
        if last_rc != 0 and not has_nmap():
            log.append(
                "If winget failed, run in an elevated PowerShell:\n"
                f'  "{winget}" install -e --id Insecure.Nmap --accept-package-agreements --accept-source-agreements'
            )

        if not has_go():
            log.append("Installing Go via winget (GoLang.Go) for subfinder…")
            go_rc = _run_logged(
                [
                    winget,
                    "install",
                    "-e",
                    "--id",
                    "GoLang.Go",
                    "--accept-package-agreements",
                    "--accept-source-agreements",
                ],
                log,
                timeout=900,
            )
            blob = "\n".join(log).lower()
            if go_rc != 0 and not any(
                s in blob
                for s in (
                    "already installed",
                    "no newer package",
                    "no applicable upgrade",
                    "a newer version was not found",
                )
            ):
                log.append(
                    "If Go install failed, try: https://go.dev/dl/ or\n"
                    f'  "{winget}" install -e --id GoLang.Go --accept-package-agreements --accept-source-agreements'
                )

    go_exe = resolve_go_executable()
    if go_exe and not has_subfinder():
        gopath = os.environ.get("GOPATH") or str(Path.home() / "go")
        bindir = Path(gopath) / "bin"
        _run_logged(
            [go_exe, "install", "-v", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"],
            log,
            timeout=600,
        )
        log.append(f"Expect subfinder under: {bindir} (detected without PATH refresh)")
    elif not has_subfinder() and not resolve_go_executable():
        log.append(
            "Go not found — install with: winget install -e --id GoLang.Go  OR  https://go.dev/dl/  then re-run Install missing."
        )


def _which_pkg_mgr() -> str | None:
    if shutil.which("apt-get"):
        return "apt"
    if shutil.which("dnf"):
        return "dnf"
    if shutil.which("yum"):
        return "yum"
    return None


def install_tools_linux(log: list[str]) -> None:
    """Try apt/dnf without sudo first; then suggest sudo command. Optionally use pkexec."""
    mgr = _which_pkg_mgr()
    if mgr == "apt":
        # Non-interactive sudo often fails from GUI; try pkexec (graphical sudo on many desktops)
        if shutil.which("pkexec"):
            rc = _run_logged(
                ["pkexec", "apt-get", "install", "-y", "nmap"],
                log,
                timeout=900,
            )
            if rc != 0:
                log.append("If pkexec failed, run in a terminal: sudo apt-get update && sudo apt-get install -y nmap")
        else:
            log.append("Run in a terminal: sudo apt-get update && sudo apt-get install -y nmap")
    elif mgr in ("dnf", "yum"):
        exe = "dnf" if mgr == "dnf" else "yum"
        if shutil.which("pkexec"):
            _run_logged(["pkexec", exe, "install", "-y", "nmap"], log, timeout=900)
        else:
            log.append(f"Run in a terminal: sudo {exe} install -y nmap")
    else:
        log.append("Could not detect apt/dnf/yum. Install nmap using your distribution's package manager.")

    go_exe = resolve_go_executable()
    if go_exe and not has_subfinder():
        _run_logged(
            [go_exe, "install", "-v", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"],
            log,
            timeout=600,
        )
        gopath = os.environ.get("GOPATH") or str(Path.home() / "go")
        log.append(f"Ensure this is on your PATH: {Path(gopath) / 'bin'}")


def run_auto_install() -> str:
    """
    Best-effort install. Returns full log text. Safe to call from a background thread.
    """
    log: list[str] = ["=== Mini ARES tool install ===\n"]
    try:
        sys = platform.system()
        if sys == "Windows":
            install_tools_windows(log)
        elif sys == "Linux":
            install_tools_linux(log)
        else:
            log.append(f"Auto-install not implemented for {sys}. Install nmap and optional subfinder manually.")
        log.append(
            "\n=== After install: restart the app if status still looks wrong (PATH may be stale). "
            "Nmap, Go under Program Files, and subfinder under %USERPROFILE%\\go\\bin are detected without restart. ===\n"
        )
        log.append("\n".join(tool_status_lines()))
        return "\n".join(log)
    except Exception as e:
        log.append(f"{type(e).__name__}: {e}")
        return "\n".join(log)

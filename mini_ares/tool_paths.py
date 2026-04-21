"""Resolve optional CLI tools even when PATH is stale (e.g. after winget from a GUI)."""
from __future__ import annotations

import os
import platform
import shutil
from pathlib import Path


def resolve_nmap_executable() -> str | None:
    """PATH first, then common Windows install dirs."""
    if platform.system() == "Windows":
        for name in ("nmap.exe", "nmap"):
            w = shutil.which(name)
            if w:
                return w
        pf = os.environ.get("ProgramFiles", r"C:\Program Files")
        pfx86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
        for base in (Path(pf), Path(pfx86)):
            cand = base / "Nmap" / "nmap.exe"
            if cand.is_file():
                return str(cand)
    else:
        w = shutil.which("nmap")
        if w:
            return w
    return None


def resolve_go_executable() -> str | None:
    w = shutil.which("go")
    if w:
        return w
    if platform.system() == "Windows":
        pf = os.environ.get("ProgramFiles", r"C:\Program Files")
        cand = Path(pf) / "Go" / "bin" / "go.exe"
        if cand.is_file():
            return str(cand)
        lad = os.environ.get("LOCALAPPDATA", "")
        if lad:
            cand2 = Path(lad) / "Programs" / "Go" / "bin" / "go.exe"
            if cand2.is_file():
                return str(cand2)
    return None


def resolve_subfinder_executable() -> str | None:
    w = shutil.which("subfinder")
    if w:
        return w
    gopath = os.environ.get("GOPATH") or str(Path.home() / "go")
    for name in ("subfinder.exe", "subfinder"):
        cand = Path(gopath) / "bin" / name
        if cand.is_file():
            return str(cand)
    return None

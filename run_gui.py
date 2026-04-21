"""
Desktop entry point for the Security Operations Suite (Log + Cloud + Attack surface).

- Development: python run_gui.py
- Frozen EXE: double-click SecuritySuite.exe (see SecuritySuite.spec / build_windows.ps1)
"""
from __future__ import annotations

import multiprocessing
import sys
from pathlib import Path

# Dev mode: add repo root so `threat_analyzer` imports resolve. Frozen EXE bundles deps — no path hack.
if not getattr(sys, "frozen", False):
    _root = Path(__file__).resolve().parent
    if str(_root) not in sys.path:
        sys.path.insert(0, str(_root))


def main() -> None:
    from threat_analyzer.app_ui import launch

    launch()


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()

#!/usr/bin/env bash
# Build Security Operations Suite for Linux (ELF binary, no terminal window)
set -euo pipefail
cd "$(dirname "$0")"
python3 -m pip install -r requirements.txt -q
python3 -m pip install pyinstaller -q
python3 -m PyInstaller --noconfirm SecuritySuite.spec
echo "Done. Run: ./dist/SecuritySuite"

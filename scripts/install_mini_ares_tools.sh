#!/usr/bin/env bash
# Mini ARES optional tools — Linux (run with: bash scripts/install_mini_ares_tools.sh)
set -euo pipefail

echo "=== Mini ARES: installing optional tools ==="

if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update
  sudo apt-get install -y nmap
elif command -v dnf >/dev/null 2>&1; then
  sudo dnf install -y nmap
elif command -v yum >/dev/null 2>&1; then
  sudo yum install -y nmap
else
  echo "Install nmap using your distribution package manager." >&2
  exit 1
fi

if command -v go >/dev/null 2>&1; then
  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  echo "Ensure GOPATH/bin is on PATH (often ~/go/bin)"
else
  echo "Optional: install Go from https://go.dev/dl/ then: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
fi

echo "Done. Try: nmap --version && command -v subfinder"

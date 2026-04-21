# Mini ARES optional tools — Windows (run PowerShell as Administrator if winget fails)
# Usage: .\scripts\install_mini_ares_tools.ps1

$ErrorActionPreference = "Stop"

Write-Host "=== Mini ARES: installing optional tools ===" -ForegroundColor Cyan

if (Get-Command winget -ErrorAction SilentlyContinue) {
    Write-Host "Installing Nmap via winget..."
    winget install -e --id Insecure.Nmap --accept-package-agreements --accept-source-agreements
} else {
    Write-Warning "winget not found. Install Nmap from https://nmap.org/download.html"
}

if (Get-Command go -ErrorAction SilentlyContinue) {
    Write-Host "Installing subfinder via Go..."
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    $goBin = Join-Path $env:USERPROFILE "go\bin"
    Write-Host "Add to PATH if needed: $goBin" -ForegroundColor Yellow
} else {
    Write-Warning "Go not found. Install from https://go.dev/dl/ or download subfinder from https://github.com/projectdiscovery/subfinder/releases"
}

Write-Host "Done. Open a new terminal and run: nmap --version" -ForegroundColor Green

# Build Security Operations Suite as a Windows GUI application (single .exe)
# Requires: Python 3.10+, pip install -r requirements.txt pyinstaller

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "Installing dependencies..." -ForegroundColor Cyan
python -m pip install -r requirements.txt -q
python -m pip install pyinstaller -q

Write-Host "Building SecuritySuite.exe (this may take several minutes)..." -ForegroundColor Cyan
python -m PyInstaller --noconfirm SecuritySuite.spec

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "Done. Run: .\dist\SecuritySuite.exe" -ForegroundColor Green
} else {
    Write-Host "Build failed." -ForegroundColor Red
    exit $LASTEXITCODE
}

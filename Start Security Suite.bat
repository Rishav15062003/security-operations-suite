@echo off
title Security Operations Suite
cd /d "%~dp0"
where python >nul 2>&1
if %ERRORLEVEL% neq 0 (
  echo Python is not in PATH. Install Python 3.10+ from https://www.python.org/
  pause
  exit /b 1
)
python run_gui.py
if %ERRORLEVEL% neq 0 pause

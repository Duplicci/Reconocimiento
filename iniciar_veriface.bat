@echo off
cd /d "%~dp0"
where py >nul 2>&1
if not errorlevel 1 (
  py -3 scanner_server.py
) else (
  python scanner_server.py
)
if errorlevel 1 pause

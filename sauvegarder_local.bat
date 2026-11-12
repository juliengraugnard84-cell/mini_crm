@echo off
setlocal
cd /d "%~dp0"
"venv\Scripts\python.exe" local_crm.py --backup
pause
endlocal

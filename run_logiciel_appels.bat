@echo off
setlocal

set "APP_DIR=%~dp0logiciel_appels"
set "PYTHON_EXE=%~dp0venv\Scripts\python.exe"

if exist "%PYTHON_EXE%" (
    "%PYTHON_EXE%" "%APP_DIR%\app.py"
) else (
    python "%APP_DIR%\app.py"
)

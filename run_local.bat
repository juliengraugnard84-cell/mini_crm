@echo off
setlocal

cd /d "%~dp0"

set "LOCAL_MODE=1"
set "PORT=5055"

if not exist "venv\Scripts\python.exe" (
    echo [ERREUR] Environnement Python introuvable dans venv\Scripts\python.exe
    echo.
    echo Verifie que le dossier venv existe bien dans C:\mini_crm.
    pause
    exit /b 1
)

echo ===============================================
echo   Mini CRM - demarrage local
echo ===============================================
echo.
echo Mode local : LOCAL_MODE=1
echo URL        : http://127.0.0.1:5055
echo Identifiants : instance\local_crm\ACCES_LOCAL.txt
echo.
echo Garde cette fenetre ouverte pendant l'aperçu.
echo Ensuite, actualise simplement l'onglet du navigateur integre.
echo Pour arreter le serveur : Ctrl + C
echo.

"venv\Scripts\python.exe" local_crm.py
pause

endlocal

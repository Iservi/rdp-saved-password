@echo off
REM Launcher for Find-RdpSavedPassword.ps1
REM Place this .bat in the SAME folder as the .ps1 file, then double-click it.
REM Run it on the OLD computer, logged in as the Windows user that used mstsc.

setlocal
set "PS1=%~dp0Find-RdpSavedPassword.ps1"

if not exist "%PS1%" (
    echo [!] Find-RdpSavedPassword.ps1 was not found next to this launcher.
    echo     Keep both files in the same folder.
    echo.
    pause
    exit /b 1
)

echo Running "%PS1%" ...
echo.

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %*

echo.
echo Done. Copy the result before closing this window.
pause

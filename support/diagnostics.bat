@echo off
title Cheat.Guard - Diagnostics
echo ============================================================
echo  Cheat.Guard - Collect Diagnostics
echo ============================================================
echo.
echo  Collects network/DNS state and recent app logs into one
echo  text file on the Desktop. Read-only; changes nothing.
echo.
rem This .bat ships at the app root, but also works from the repository's
rem support\ folder: resolve the .ps1 from both possible layouts.
set "PS1=%~dp0support\diagnostics.ps1"
if not exist "%PS1%" set "PS1=%~dp0diagnostics.ps1"
powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%"
echo.
pause

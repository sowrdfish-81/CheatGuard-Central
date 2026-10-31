@echo off
title Cheat.Guard - Emergency Network Restore
echo ============================================================
echo  Cheat.Guard - Emergency Network Restore
echo ============================================================
echo.
echo  Use this ONLY if a Cheat.Guard session ended abnormally
echo  (power loss, forced reboot, crash) and the Internet stayed
echo  blocked. If Cheat.Guard is running right now, end the
echo  session from the app instead.
echo.
rem This .bat ships at the app root, but also works from the repository's
rem support\ folder: resolve the .ps1 from both possible layouts.
set "PS1=%~dp0support\emergency-restore.ps1"
if not exist "%PS1%" set "PS1=%~dp0emergency-restore.ps1"
powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%"
echo.
pause

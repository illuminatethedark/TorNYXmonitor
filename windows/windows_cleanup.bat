@echo off
title Tor NYX Monitor — Cleanup
setlocal enabledelayedexpansion

echo ================================================
echo  Tor NYX Monitor — Remove App Data
echo ================================================
echo.
echo  This will delete:
echo    - Config and profile files from your user folder
echo    - Desktop shortcut (if present)
echo    - Saved passwords from Windows Credential Manager
echo.
echo  Your Tor NYX Monitor exe is NOT deleted.
echo  Remove it manually once cleanup is complete.
echo.
set /p "_CONFIRM=  Continue? [Y/N]: "
if /i not "!_CONFIRM!"=="Y" (
    echo  Cancelled.
    pause & exit /b 0
)

echo.

:: ── Data files ────────────────────────────────────────────────────────
set "_REMOVED=0"
for %%f in (
    "%USERPROFILE%\.tor_bridge_monitor.json"
    "%USERPROFILE%\.tor_bridge_monitor_profiles.json"
    "%USERPROFILE%\.tor_bridge_monitor_known_hosts"
    "%USERPROFILE%\.tor_bridge_monitor.log"
    "%USERPROFILE%\.tor_bridge_monitor.log.1"
    "%USERPROFILE%\.tor_bridge_monitor.log.2"
) do (
    if exist %%f (
        del /q %%f 2>nul
        echo  [OK] Deleted %%f
        set "_REMOVED=1"
    )
)
if "!_REMOVED!"=="0" echo  [--] No data files found.

:: ── Desktop shortcut ──────────────────────────────────────────────────
if exist "%USERPROFILE%\Desktop\Tor NYX Monitor.lnk" (
    del /q "%USERPROFILE%\Desktop\Tor NYX Monitor.lnk" 2>nul
    echo  [OK] Deleted Desktop shortcut.
) else (
    echo  [--] No Desktop shortcut found.
)

:: ── Windows Credential Manager (keyring entries) ──────────────────────
echo.
echo  Removing Windows Credential Manager entries...
powershell -NoProfile -Command ^
    "cmdkey /list | Select-String 'TorNYXMonitor' | ForEach-Object { $t = ($_ -replace '^\s*Target:\s*(LegacyGeneric:target=)?','').Trim(); if ($t -ne '') { cmdkey /delete:$t | Out-Null; Write-Host ('  [OK] Removed credential: ' + $t) } }"
echo  [OK] Credential Manager check complete.

echo.
echo ================================================
echo  Cleanup complete.
echo  Delete the Tor NYX Monitor exe manually to
echo  finish removing the application.
echo ================================================
echo.
pause
endlocal

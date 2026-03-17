@echo off
title Tor NYX Monitor - Build EXE
setlocal enabledelayedexpansion

echo ================================================
echo  Tor NYX Monitor - EXE Builder
echo ================================================
echo.

:: ── Resolve root project directory (one level up from windows\) ───────
set "ROOT_DIR=%~dp0.."

:: ── Verify source file exists ────────────────────────────────────────
if not exist "%ROOT_DIR%\tor_bridge_monitor.py" (
    echo  ERROR: tor_bridge_monitor.py not found at %ROOT_DIR%
    echo  Place windows_build.bat inside a 'windows' subfolder of the project.
    pause & exit /b 1
)

:: ── Locate Python (bootstrap if not found) ───────────────────────────
set "BOOTSTRAP_PYTHON_DIR=%~dp0_python_build"
set "BOOTSTRAP_PYTHON_EXE=%BOOTSTRAP_PYTHON_DIR%\python.exe"
set "_PYTHON_BOOTSTRAPPED=0"

where python >nul 2>&1
if errorlevel 1 (
    echo  Python not found in PATH — downloading Python 3.12 installer for build...
    echo  ^(This will not affect your system installation.^)
    echo.

    set "PYVER=3.12.10"
    set "PYINST=%TEMP%\python312_setup.exe"
    set "PYURL=https://www.python.org/ftp/python/!PYVER!/python-!PYVER!-amd64.exe"
    powershell -NoProfile -Command "Invoke-WebRequest -Uri '!PYURL!' -OutFile '!PYINST!' -UseBasicParsing"
    if errorlevel 1 (
        echo  ERROR: Failed to download Python installer. Check your internet connection.
        echo  Alternatively install Python manually from https://python.org
        pause & exit /b 1
    )

    rem Install to a local folder — no system PATH changes
    rem /passive shows a progress bar (no clicks needed) and returns a non-zero
    rem exit code on failure, unlike /quiet which can fail silently.
    if exist "!BOOTSTRAP_PYTHON_DIR!" rmdir /s /q "!BOOTSTRAP_PYTHON_DIR!"
    "!PYINST!" /passive InstallAllUsers=0 PrependPath=0 Include_test=0 ^
        Include_launcher=0 TargetDir="!BOOTSTRAP_PYTHON_DIR!"
    if errorlevel 1 (
        echo  ERROR: Python installer exited with an error.
        echo  This can happen if Windows policy blocks the install, or if UAC
        echo  was declined. Try running this script as Administrator, or install
        echo  Python 3.12 manually from https://python.org then re-run the build.
        del /q "!PYINST!" 2>nul
        pause & exit /b 1
    )
    del /q "!PYINST!" 2>nul
    if not exist "!BOOTSTRAP_PYTHON_EXE!" (
        echo  ERROR: Python installer completed but python.exe was not found at:
        echo    !BOOTSTRAP_PYTHON_DIR!
        echo  The installer may have chosen a different target directory.
        echo  Install Python 3.12 manually from https://python.org then re-run.
        pause & exit /b 1
    )

    set "PATH=!BOOTSTRAP_PYTHON_DIR!;!BOOTSTRAP_PYTHON_DIR!\Scripts;!PATH!"
    set "_PYTHON_BOOTSTRAPPED=1"
    echo  Bootstrap complete.
    echo.
)

for /f "tokens=*" %%i in ('where python') do (
    set PYTHON_EXE=%%i
    goto :found_python
)
:found_python
for /f "tokens=*" %%v in ('"!PYTHON_EXE!" --version 2^>^&1') do echo  Python: %%v
echo  Path:   !PYTHON_EXE!

:: Derive install prefix via temp file (avoids cmd.exe quote-stripping)
"!PYTHON_EXE!" -c "import sys; open('__prefix__.tmp','w').write(sys.prefix)"
set /p PYTHON_PREFIX=<__prefix__.tmp
del /q __prefix__.tmp 2>nul

:: ── Clean corrupted pip leftovers (tilde-prefixed entries) ────────────
echo.
echo [1/4] Cleaning corrupted pip entries...
for /d %%d in ("!PYTHON_PREFIX!\Lib\site-packages\~*") do (
    echo        Removing: %%d
    rmdir /s /q "%%d" 2>nul
)
for %%f in ("!PYTHON_PREFIX!\Lib\site-packages\~*") do (
    echo        Removing: %%f
    del /q "%%f" 2>nul
)

:: ── Install dependencies ──────────────────────────────────────────────
echo.
echo [2/4] Installing dependencies...
"!PYTHON_EXE!" -m pip install paramiko pyte pyinstaller PyNaCl cryptography --quiet
if errorlevel 1 (
    echo  ERROR: pip install failed.
    echo  Try running as Administrator, or run manually:
    echo    pip install paramiko pyte pyinstaller PyNaCl cryptography
    pause & exit /b 1
)
echo        OK.

:: ── Resolve icon ──────────────────────────────────────────────────────
set "ICON_ARG="
if exist "%ROOT_DIR%\icon.ico" (
    set "ICON_ARG=--icon="%ROOT_DIR%\icon.ico""
    echo  Using icon: %ROOT_DIR%\icon.ico
)

:: ── Build the exe (output goes directly to Desktop) ──────────────────
echo.
echo [3/4] Building executable...
echo        This may take a minute...
echo.
"!PYTHON_EXE!" -m PyInstaller ^
    --onefile ^
    --windowed ^
    --name "Tor NYX Monitor" ^
    --distpath "%USERPROFILE%\Desktop" ^
    --workpath "%ROOT_DIR%\build" ^
    --specpath "%ROOT_DIR%" ^
    !ICON_ARG! ^
    --add-data "%ROOT_DIR%\icon.ico;." ^
    --hidden-import paramiko ^
    --hidden-import paramiko.transport ^
    --hidden-import paramiko.auth_handler ^
    --hidden-import paramiko.channel ^
    --hidden-import paramiko.client ^
    --hidden-import paramiko.config ^
    --hidden-import paramiko.pkey ^
    --hidden-import paramiko.rsakey ^
    --hidden-import paramiko.ecdsakey ^
    --hidden-import paramiko.ed25519key ^
    --hidden-import paramiko.sftp ^
    --hidden-import paramiko.sftp_client ^
    --hidden-import paramiko.sftp_attr ^
    --hidden-import paramiko.sftp_handle ^
    --hidden-import paramiko.packet ^
    --hidden-import paramiko.compress ^
    --hidden-import paramiko.kex_ecdh_nist ^
    --hidden-import paramiko.kex_curve25519 ^
    --hidden-import paramiko.kex_group14 ^
    --hidden-import paramiko.kex_gex ^
    --hidden-import pyte ^
    --hidden-import pyte.modes ^
    --hidden-import pyte.screens ^
    --hidden-import pyte.streams ^
    --hidden-import pyte.graphics ^
    --hidden-import pyte.control ^
    --hidden-import pyte.escape ^
    --hidden-import cryptography ^
    --hidden-import cryptography.hazmat.primitives ^
    --hidden-import cryptography.hazmat.backends ^
    --hidden-import bcrypt ^
    --hidden-import nacl ^
    --hidden-import nacl.signing ^
    --clean ^
    --noconfirm ^
    "%ROOT_DIR%\tor_bridge_monitor.py"

if errorlevel 1 (
    echo.
    echo  ERROR: PyInstaller build failed.
    echo  Check the output above for details.
    pause & exit /b 1
)

:: ── Verify output ─────────────────────────────────────────────────────
echo.
echo [4/4] Verifying output...
if exist "%USERPROFILE%\Desktop\Tor NYX Monitor.exe" (
    echo        SUCCESS: Tor NYX Monitor.exe placed on Desktop.
    for %%i in ("%USERPROFILE%\Desktop\Tor NYX Monitor.exe") do echo        Size: %%~zi bytes
) else (
    echo  ERROR: exe not found on Desktop.
    pause & exit /b 1
)

:: ── Clean up build artefacts ──────────────────────────────────────────
echo.
echo        Cleaning up build files...
if exist "%ROOT_DIR%\build"                         rmdir /s /q "%ROOT_DIR%\build"
if exist "%ROOT_DIR%\Tor NYX Monitor.spec"  del /q "%ROOT_DIR%\Tor NYX Monitor.spec"
if "!_PYTHON_BOOTSTRAPPED!"=="1" (
    echo        Removing bootstrapped Python...
    rmdir /s /q "!BOOTSTRAP_PYTHON_DIR!" 2>nul
)
echo        Done.

echo.
echo ================================================
echo  Build complete!
echo  Your exe is on the Desktop:
echo    Tor NYX Monitor.exe
echo.
echo  NOTE: Windows SmartScreen may warn on first run
echo  because the exe is unsigned. Click "More info"
echo  then "Run anyway" to launch it.
echo.
echo  To suppress the warning permanently, sign the
echo  exe with a code signing certificate from
echo  DigiCert, Sectigo, or similar (~$200-500/yr).
echo ================================================
echo.
pause
endlocal

@echo off
title Tor NYX Monitor v0.2.1 - Build EXE
setlocal enabledelayedexpansion

echo ================================================
echo  Tor NYX Monitor v0.2.1 - EXE Builder
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

:: ── Locate Python ─────────────────────────────────────────────────────
where python >nul 2>&1
if errorlevel 1 (
    echo  ERROR: Python not found. Install from https://python.org
    echo  Tick "Add Python to PATH" during install.
    pause & exit /b 1
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
    set "ICON_ARG=--icon=%ROOT_DIR%\icon.ico"
    echo  Using icon: %ROOT_DIR%\icon.ico
)

:: ── Build the exe (output goes to root dist\ and build\) ──────────────
echo.
echo [3/4] Building executable...
echo        This may take a minute...
echo.
"!PYTHON_EXE!" -m PyInstaller ^
    --onefile ^
    --windowed ^
    --name "Tor NYX Monitor v0.2.1" ^
    --distpath "%ROOT_DIR%\dist" ^
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
if exist "%ROOT_DIR%\dist\Tor NYX Monitor v0.2.1.exe" (
    echo        SUCCESS: dist\Tor NYX Monitor v0.2.1.exe created.
    for %%i in ("%ROOT_DIR%\dist\Tor NYX Monitor v0.2.1.exe") do echo        Size: %%~zi bytes
) else (
    echo  ERROR: exe not found in dist\ folder.
    pause & exit /b 1
)

:: ── Clean up build artefacts ──────────────────────────────────────────
echo.
echo        Cleaning up build files...
if exist "%ROOT_DIR%\build"                         rmdir /s /q "%ROOT_DIR%\build"
if exist "%ROOT_DIR%\Tor NYX Monitor v0.2.1.spec"  del /q "%ROOT_DIR%\Tor NYX Monitor v0.2.1.spec"
echo        Done.

echo.
echo ================================================
echo  Build complete!
echo  Your exe is at:  dist\Tor NYX Monitor v0.2.1.exe
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

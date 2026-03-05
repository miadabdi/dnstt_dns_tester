@echo off
REM Install Python dependencies.
REM Tries online install first; falls back to bundled wheels in vendor\
REM Usage: install_deps.bat

setlocal enabledelayedexpansion
set SCRIPT_DIR=%~dp0
set VENDOR_DIR=%SCRIPT_DIR%vendor
set REQ_FILE=%SCRIPT_DIR%requirements.txt

if not exist "%REQ_FILE%" (
    echo Error: requirements.txt not found in %SCRIPT_DIR%
    exit /b 1
)

echo Attempting online install from PyPI...
pip install -r "%REQ_FILE%"
if %ERRORLEVEL% EQU 0 (
    echo Installed dependencies from PyPI.
    exit /b 0
)

echo Online install failed or offline. Falling back to vendor\
if not exist "%VENDOR_DIR%" (
    echo Error: vendor\ directory not found. Cannot install dependencies.
    exit /b 1
)

echo Installing dependencies from vendor\ ...
pip install --no-index --find-links "%VENDOR_DIR%" -r "%REQ_FILE%"
if %ERRORLEVEL% NEQ 0 (
    echo Failed to install dependencies from vendor\. >&2
    exit /b %ERRORLEVEL%
)
echo Done.

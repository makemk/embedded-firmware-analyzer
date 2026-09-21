@echo off
setlocal enabledelayedexpansion

echo ======================================================================
echo  Embedded Firmware Analyzer - Isolated Environment Setup
echo ======================================================================

set "SKILL_ROOT=%~dp0"
cd /d "%SKILL_ROOT%"

:: 1. Check Python
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python 3 was not found in system PATH.
    echo Please install Python 3.9+ and try again.
    pause
    exit /b 1
)

:: 2. Create isolated .venv
echo [1/3] Creating isolated Python virtual environment (.venv)...
if not exist ".venv\Scripts\python.exe" (
    python -m venv .venv
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to create virtual environment.
        exit /b 1
    )
)
echo      Virtual environment ready.

:: 3. Install requirements
echo [2/3] Installing isolated dependencies into .venv...
.venv\Scripts\python.exe -m pip install --upgrade pip --quiet
.venv\Scripts\python.exe -m pip install -r requirements.txt --quiet
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install dependencies.
    exit /b 1
)
echo      Dependencies successfully installed: pyelftools, mapfile-parser, lizard.

:: 4. Verify Bundled Cppcheck
echo [3/3] Verifying isolated bundled tools...
if exist "tools\cppcheck\cppcheck.exe" (
    echo      Isolated Cppcheck is bundled: tools\cppcheck\cppcheck.exe
) else (
    echo [WARN] tools\cppcheck\cppcheck.exe not found.
    echo        Will attempt to fallback to system Cppcheck or EIDE.
)

echo.
echo ======================================================================
echo  Setup Complete! The skill is fully isolated and self-contained.
echo  You can now run:
echo    run_gate.bat --workspace "<path_to_firmware>"
echo ======================================================================
echo.


@echo off
setlocal

set "SKILL_ROOT=%~dp0"
set "PYTHON_EXE=%SKILL_ROOT%.venv\Scripts\python.exe"

if not exist "%PYTHON_EXE%" (
    where python >nul 2>nul
    if %errorlevel% equ 0 (
        set "PYTHON_EXE=python"
        echo [INFO] Using host system Python.
    ) else (
        echo [ERROR] Python environment not found. Please run setup_env.bat first!
        exit /b 1
    )
) else (
    echo [Isolated Environment Active]
    echo   Python Runtime : %PYTHON_EXE%
    if exist "%SKILL_ROOT%tools\cppcheck\cppcheck.exe" (
        echo   Bundled Tool   : %SKILL_ROOT%tools\cppcheck\cppcheck.exe
    )
    echo.
)

"%PYTHON_EXE%" "%SKILL_ROOT%scripts\embedded_ocr_gate.py" %*
exit /b %ERRORLEVEL%


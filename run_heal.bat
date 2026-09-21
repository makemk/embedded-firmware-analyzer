@echo off
setlocal

set "SKILL_ROOT=%~dp0"
set "PYTHON_EXE=%SKILL_ROOT%.venv\Scripts\python.exe"

if not exist "%PYTHON_EXE%" (
    where python >nul 2>nul
    if %errorlevel% equ 0 (
        set "PYTHON_EXE=python"
    ) else (
        echo [ERROR] Python environment not found. Please run setup_env.bat first!
        exit /b 1
    )
)

"%PYTHON_EXE%" "%SKILL_ROOT%scripts\embedded_ocr_heal.py" %*
exit /b %ERRORLEVEL%


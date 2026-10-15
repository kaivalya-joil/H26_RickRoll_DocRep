@echo off
title DocRep - Repository Resilience Workbench
echo ========================================================
echo   DocRep: Repository Resilience Workbench
echo   Starting local GUI server on 127.0.0.1...
echo ========================================================
echo.

if exist "%~dp0.venv\Scripts\python.exe" (
    "%~dp0.venv\Scripts\python.exe" -m repomedic.cli gui
) else (
    python -m repomedic.cli gui
)

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Failed to start DocRep.
    pause
)

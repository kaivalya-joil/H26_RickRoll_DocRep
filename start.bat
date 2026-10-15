@echo off
title DocRep - Dependency Resilience Workbench
echo =======================================================
echo   DocRep (RepoMedic) - Dependency Resilience Workbench
echo   Starting local GUI server on 127.0.0.1...
echo =======================================================
python -m repomedic.cli gui
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Failed to start DocRep.
    echo Please verify Python 3.10+ is installed and available in your PATH.
    pause
)

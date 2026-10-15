#!/usr/bin/env bash
echo "======================================================="
echo "  DocRep (RepoMedic) - Dependency Resilience Workbench"
echo "  Starting local GUI server on 127.0.0.1..."
echo "======================================================="
if command -v python3 &>/dev/null; then
    python3 -m repomedic.cli gui
elif command -v python &>/dev/null; then
    python -m repomedic.cli gui
else
    echo "[ERROR] Python not found on PATH. Please install Python 3.10+."
    exit 1
fi

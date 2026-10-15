"""Verification runner: executes checks in isolated sandboxes and captures evidence."""

import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from .models import FindingStatus, VerificationResult
from .safety import IsolatedSandbox


class SafeVerificationRunner:
    """Executes safe commands in an isolated sandbox, preserving the original repository."""

    def __init__(self, repo_dir: Path | str, timeout_seconds: int = 30):
        self.repo_dir = Path(repo_dir).resolve()
        self.timeout_seconds = timeout_seconds

    def run_check(
        self,
        check_id: str,
        target_description: str,
        command: List[str],
        cwd_override: Optional[Path] = None,
        use_sandbox: bool = True,
        extra_env: Optional[dict] = None,
    ) -> VerificationResult:
        """Run a command safely with exact timing, exit code, and stdout/stderr capture."""
        start_time = time.monotonic()
        timestamp = datetime.now(timezone.utc).isoformat()

        # Check if the executable is available
        executable = command[0]
        if executable != sys.executable and not shutil.which(executable):
            return VerificationResult(
                id=check_id,
                target=target_description,
                command=command,
                exit_code=None,
                stdout="",
                stderr=f"Executable '{executable}' not found in PATH.",
                duration_ms=0,
                status=FindingStatus.BLOCKED,
                timestamp=timestamp,
                sandbox_used=False,
                notes=f"Prerequisite command '{executable}' is not installed in the current environment.",
            )

        env = os.environ.copy()
        if extra_env:
            env.update(extra_env)

        if use_sandbox:
            with IsolatedSandbox(self.repo_dir) as sandbox_path:
                work_dir = cwd_override if cwd_override else sandbox_path
                env["PYTHONPATH"] = str(sandbox_path)
                return self._execute_process(
                    check_id, target_description, command, work_dir, env, start_time, timestamp, sandbox_used=True
                )
        else:
            work_dir = cwd_override if cwd_override else self.repo_dir
            env["PYTHONPATH"] = str(self.repo_dir)
            return self._execute_process(
                check_id, target_description, command, work_dir, env, start_time, timestamp, sandbox_used=False
            )

    def _execute_process(
        self,
        check_id: str,
        target: str,
        command: List[str],
        work_dir: Path,
        env: dict,
        start_time: float,
        timestamp: str,
        sandbox_used: bool,
    ) -> VerificationResult:
        try:
            proc = subprocess.run(
                command,
                cwd=str(work_dir),
                env=env,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
            elapsed_ms = int((time.monotonic() - start_time) * 1000)
            status = FindingStatus.VERIFIED if proc.returncode == 0 else FindingStatus.FAILED
            return VerificationResult(
                id=check_id,
                target=target,
                command=command,
                exit_code=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                duration_ms=elapsed_ms,
                status=status,
                timestamp=timestamp,
                sandbox_used=sandbox_used,
                notes=f"Process exited with code {proc.returncode}",
            )
        except subprocess.TimeoutExpired as te:
            elapsed_ms = int((time.monotonic() - start_time) * 1000)
            return VerificationResult(
                id=check_id,
                target=target,
                command=command,
                exit_code=-1,
                stdout=te.stdout or "",
                stderr=f"Command timed out after {self.timeout_seconds} seconds.",
                duration_ms=elapsed_ms,
                status=FindingStatus.FAILED,
                timestamp=timestamp,
                sandbox_used=sandbox_used,
                notes="Execution timed out.",
            )
        except Exception as e:
            elapsed_ms = int((time.monotonic() - start_time) * 1000)
            return VerificationResult(
                id=check_id,
                target=target,
                command=command,
                exit_code=-1,
                stdout="",
                stderr=str(e),
                duration_ms=elapsed_ms,
                status=FindingStatus.FAILED,
                timestamp=timestamp,
                sandbox_used=sandbox_used,
                notes=f"Execution error: {e}",
            )

    def run_baseline_tests(self) -> VerificationResult:
        """Attempt to run test suite in sandbox with pytest or python -m unittest."""
        # Check if pytest is available
        has_pytest = shutil.which("pytest") is not None
        if not has_pytest:
            # Check via python -m pytest
            res = subprocess.run(
                [sys.executable, "-m", "pytest", "--version"],
                capture_output=True,
            )
            has_pytest = res.returncode == 0

        if has_pytest:
            cmd = [sys.executable, "-m", "pytest", "tests"]
            desc = "LinkWatch pytest test suite execution"
        else:
            # Pytest not installed in system interpreter
            cmd = [sys.executable, "-m", "pytest", "tests"]
            return VerificationResult(
                id="VERIFY-TEST-001",
                target="LinkWatch pytest test suite execution",
                command=cmd,
                exit_code=None,
                stdout="",
                stderr="pytest is not installed in the active Python environment.",
                duration_ms=0,
                status=FindingStatus.BLOCKED,
                timestamp=datetime.now(timezone.utc).isoformat(),
                sandbox_used=False,
                notes="pytest is listed in requirements-dev.txt but not installed in the active environment.",
            )

        return self.run_check(
            check_id="VERIFY-TEST-001",
            target_description=desc,
            command=cmd,
            use_sandbox=True,
        )

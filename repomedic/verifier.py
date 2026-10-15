"""Allow-list based safe verifier. No shell strings, no arbitrary commands."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional
from pydantic import BaseModel, Field

from .models import FindingStatus, VerificationResult
from .safety import IsolatedSandbox


class SafeCheckDefinition(BaseModel):
    name: str
    purpose: str
    command_builder: str  # identifier of internal method


ALLOWED_SAFE_CHECKS = {
    "manifest_consistency": "Check version consistency across all discovered dependency manifests.",
    "version_constraint_compatibility": "Verify installed package metadata against declared manifest constraints.",
    "import_checks": "Attempt deterministic Python compilation/syntax check on source modules.",
    "config_validation": "Check validity of pyproject.toml and configuration files.",
    "test_suite_run": "Run test suite safely using pytest -q in isolated sandbox.",
}


class SafeVerificationRunner:
    """Executes only pre-approved, allow-listed verification checks."""

    def __init__(self, repo_dir: Path | str, timeout_seconds: int = 30):
        self.repo_dir = Path(repo_dir).resolve()
        self.timeout_seconds = timeout_seconds

    def execute_check(self, check_name: str, check_id: Optional[str] = None) -> VerificationResult:
        """Run an allow-listed check by name. Rejects unknown checks."""
        cid = check_id or f"VERIFY-{check_name}"
        if check_name not in ALLOWED_SAFE_CHECKS:
            return VerificationResult(
                id=cid,
                target=f"Rejected check: {check_name}",
                command=[],
                exit_code=-1,
                stdout="",
                stderr=f"Check '{check_name}' is not in the allowed verification allow-list: {list(ALLOWED_SAFE_CHECKS.keys())}.",
                duration_ms=0,
                status=FindingStatus.BLOCKED,
                timestamp=datetime.now(timezone.utc).isoformat(),
                sandbox_used=False,
                notes="Security policy rejection: arbitrary or unapproved check name.",
            )

        start = time.monotonic()
        ts = datetime.now(timezone.utc).isoformat()

        if check_name == "manifest_consistency":
            return self._verify_manifest_consistency(cid, ts, start)
        elif check_name == "version_constraint_compatibility":
            return self._verify_version_constraints(cid, ts, start)
        elif check_name == "import_checks":
            return self._verify_import_syntax(cid, ts, start)
        elif check_name == "config_validation":
            return self._verify_config_validation(cid, ts, start)
        elif check_name == "test_suite_run":
            return self._verify_test_suite(cid, ts, start)

        return VerificationResult(
            id=cid,
            target=check_name,
            command=[],
            exit_code=-1,
            stdout="",
            stderr="Check not implemented",
            duration_ms=0,
            status=FindingStatus.NOT_RUN,
            timestamp=ts,
            sandbox_used=False,
            notes="Check implementation missing.",
        )

    def _verify_manifest_consistency(self, cid: str, ts: str, start: float) -> VerificationResult:
        # Check requirements.txt vs pyproject.toml
        from .scanner import RepositoryScanner
        scanner = RepositoryScanner(self.repo_dir)
        _, decls, _, _, _ = scanner.scan()
        by_name: Dict[str, set] = {}
        for d in decls:
            if d.specifier:
                by_name.setdefault(d.name, set()).add(d.specifier)
        conflicts = {pkg: specs for pkg, specs in by_name.items() if len(specs) > 1}
        elapsed = int((time.monotonic() - start) * 1000)
        status = FindingStatus.FAILED if conflicts else FindingStatus.VERIFIED
        out = "All manifests consistent." if not conflicts else f"Inconsistencies detected: {conflicts}"
        return VerificationResult(
            id=cid,
            target="manifest_consistency",
            command=["internal_manifest_check"],
            exit_code=1 if conflicts else 0,
            stdout=out,
            stderr="",
            duration_ms=elapsed,
            status=status,
            timestamp=ts,
            sandbox_used=False,
            notes="Deterministic manifest specifier comparison.",
        )

    def _verify_version_constraints(self, cid: str, ts: str, start: float) -> VerificationResult:
        from .scanner import RepositoryScanner
        from .compat import CompatibilityAnalyzer, CompatibilityStatus
        scanner = RepositoryScanner(self.repo_dir)
        meta, decls, _, _, _ = scanner.scan()
        analyzer = CompatibilityAnalyzer(meta, decls)
        results = analyzer.analyze()
        violations = [r for r in results if r.status == CompatibilityStatus.CONSTRAINT_VIOLATION]
        elapsed = int((time.monotonic() - start) * 1000)
        status = FindingStatus.FAILED if violations else FindingStatus.VERIFIED
        return VerificationResult(
            id=cid,
            target="version_constraint_compatibility",
            command=["internal_metadata_check"],
            exit_code=1 if violations else 0,
            stdout=f"Checked {len(results)} version facts. Violations: {len(violations)}",
            stderr="",
            duration_ms=elapsed,
            status=status,
            timestamp=ts,
            sandbox_used=False,
            notes="Local importlib.metadata constraint evaluation.",
        )

    def _verify_import_syntax(self, cid: str, ts: str, start: float) -> VerificationResult:
        errors = []
        py_files = list(self.repo_dir.rglob("*.py"))
        for p in py_files:
            try:
                compile(p.read_text(encoding="utf-8", errors="replace"), str(p), "exec")
            except Exception as e:
                errors.append(f"{p.name}: {e}")
        elapsed = int((time.monotonic() - start) * 1000)
        status = FindingStatus.FAILED if errors else FindingStatus.VERIFIED
        return VerificationResult(
            id=cid,
            target="import_checks",
            command=["python_compile_check"],
            exit_code=1 if errors else 0,
            stdout=f"Compiled {len(py_files)} Python files.",
            stderr="\n".join(errors),
            duration_ms=elapsed,
            status=status,
            timestamp=ts,
            sandbox_used=False,
            notes="AST compilation check across source files.",
        )

    def _verify_config_validation(self, cid: str, ts: str, start: float) -> VerificationResult:
        errors = []
        pyproj = self.repo_dir / "pyproject.toml"
        if pyproj.exists():
            try:
                import tomllib
                tomllib.loads(pyproj.read_text(encoding="utf-8", errors="replace"))
            except Exception as e:
                errors.append(f"pyproject.toml: {e}")
        elapsed = int((time.monotonic() - start) * 1000)
        status = FindingStatus.FAILED if errors else FindingStatus.VERIFIED
        return VerificationResult(
            id=cid,
            target="config_validation",
            command=["toml_parser_check"],
            exit_code=1 if errors else 0,
            stdout="Configuration files validated.",
            stderr="\n".join(errors),
            duration_ms=elapsed,
            status=status,
            timestamp=ts,
            sandbox_used=False,
            notes="TOML configuration validation.",
        )

    def _verify_test_suite(self, cid: str, ts: str, start: float) -> VerificationResult:
        cmd = [sys.executable, "-m", "pytest", "-q", "tests"]
        with IsolatedSandbox(self.repo_dir) as sandbox:
            env = os.environ.copy()
            env["PYTHONPATH"] = str(sandbox)
            try:
                proc = subprocess.run(
                    cmd,
                    cwd=str(sandbox),
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                )
                elapsed = int((time.monotonic() - start) * 1000)
                status = FindingStatus.VERIFIED if proc.returncode == 0 else FindingStatus.FAILED
                return VerificationResult(
                    id=cid,
                    target="test_suite_run",
                    command=cmd,
                    exit_code=proc.returncode,
                    stdout=proc.stdout[:500],
                    stderr=proc.stderr[:500],
                    duration_ms=elapsed,
                    status=status,
                    timestamp=ts,
                    sandbox_used=True,
                    notes=f"Pytest exited with {proc.returncode}.",
                )
            except subprocess.TimeoutExpired:
                elapsed = int((time.monotonic() - start) * 1000)
                return VerificationResult(
                    id=cid,
                    target="test_suite_run",
                    command=cmd,
                    exit_code=-1,
                    stdout="",
                    stderr=f"Timed out after {self.timeout_seconds}s",
                    duration_ms=elapsed,
                    status=FindingStatus.FAILED,
                    timestamp=ts,
                    sandbox_used=True,
                    notes="Sandbox test execution timed out.",
                )

    def run_baseline_tests(self) -> VerificationResult:
        return self.execute_check("test_suite_run", "VERIFY-BASELINE")

    def run_all_checks(self) -> List[VerificationResult]:
        """Execute all allow-listed safe verification checks."""
        results: List[VerificationResult] = []
        for name in ALLOWED_SAFE_CHECKS:
            results.append(self.execute_check(name))
        return results

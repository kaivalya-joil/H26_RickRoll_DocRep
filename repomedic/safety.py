"""Safety utilities: repository path boundary enforcement and sandbox isolation."""

import os
import shutil
import tempfile
from pathlib import Path
from typing import Optional


class PathTraversalError(ValueError):
    """Raised when a path escapes the repository root."""
    pass


def validate_safe_path(base_dir: Path | str, target_path: Path | str) -> Path:
    """Validate that target_path resolves strictly within base_dir.
    
    Prevents directory traversal attacks ('..'), symlink escapes, and absolute
    path injections.
    
    Returns the resolved Path inside base_dir.
    Raises PathTraversalError if outside.
    """
    base_resolved = Path(base_dir).resolve()
    
    # If target_path is relative, join it with base_resolved
    candidate = Path(target_path)
    if not candidate.is_absolute():
        candidate = base_resolved / candidate
    candidate_resolved = candidate.resolve()

    try:
        candidate_resolved.relative_to(base_resolved)
    except ValueError:
        raise PathTraversalError(
            f"Path '{target_path}' resolves to '{candidate_resolved}', "
            f"which is outside repository boundary '{base_resolved}'"
        )
    return candidate_resolved


def to_relative_posix(base_dir: Path | str, target_path: Path | str) -> str:
    """Convert an in-boundary path to a clean relative POSIX path."""
    safe_path = validate_safe_path(base_dir, target_path)
    base_resolved = Path(base_dir).resolve()
    rel = safe_path.relative_to(base_resolved)
    return rel.as_posix()


class IsolatedSandbox:
    """Context manager creating a safe copy of a repository for destructive/verification experiments.
    
    Guarantees the original repository remains pristine and unmodified.
    """

    def __init__(self, src_repo_dir: Path | str, prefix: str = "repomedic_sandbox_"):
        self.src_repo_dir = Path(src_repo_dir).resolve()
        self.prefix = prefix
        self.sandbox_dir: Optional[Path] = None

    def __enter__(self) -> Path:
        temp_dir = tempfile.mkdtemp(prefix=self.prefix)
        self.sandbox_dir = Path(temp_dir).resolve()
        
        # Copy directory tree while ignoring .git or cache if needed
        def _ignore(dir_path: str, names: list[str]) -> set[str]:
            return {".git", "__pycache__", ".venv", "venv", ".pytest_cache"}.intersection(names)

        shutil.copytree(self.src_repo_dir, self.sandbox_dir, dirs_exist_ok=True, ignore=_ignore)
        return self.sandbox_dir

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.sandbox_dir and self.sandbox_dir.exists():
            shutil.rmtree(self.sandbox_dir, ignore_errors=True)

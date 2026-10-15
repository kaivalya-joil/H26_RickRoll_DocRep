"""Repository Inventory Scanner — deterministic, boundary-safe repository analysis.

Accepts an explicit repository path, validates it, classifies its structure,
discovers manifests, and records every skipped file with a reason.
Never follows symlinks outside the repository boundary.
"""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .safety import PathTraversalError, validate_safe_path, to_relative_posix

# ── limits ──────────────────────────────────────────────────────────────────
MAX_FILE_SIZE_BYTES = 1 * 1024 * 1024   # 1 MiB — skip larger files
MAX_FILE_COUNT = 5_000                  # hard cap on total files walked

# ── known manifest formats ───────────────────────────────────────────────────
SUPPORTED_MANIFESTS: Dict[str, str] = {
    "pyproject.toml":        "pep517_pyproject",
    "requirements.txt":      "pip_requirements",
    "requirements-dev.txt":  "pip_requirements_dev",
    "requirements-test.txt": "pip_requirements_dev",
    "setup.py":              "setuptools_setup_py",
    "setup.cfg":             "setuptools_setup_cfg",
    "Pipfile":               "pipenv",
    "Pipfile.lock":          "pipenv_lock",
}

# Manifest patterns to report as unsupported rather than silently ignore
UNSUPPORTED_MANIFEST_PATTERNS: List[str] = [
    "poetry.lock",
    "conda.yml",
    "conda.yaml",
    "environment.yml",
    "environment.yaml",
    "tox.ini",
]

# ── directories to always prune ──────────────────────────────────────────────
PRUNE_DIRS: Set[str] = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    "node_modules",
    ".venv",
    "venv",
    "env",
    ".env",
    "build",
    "dist",
    "*.egg-info",       # matched by suffix below
    ".eggs",
    "htmlcov",
    ".coverage",
    "site-packages",
}

PRUNE_DIR_SUFFIXES: Tuple[str, ...] = (".egg-info",)


# ── data classes ─────────────────────────────────────────────────────────────

@dataclass
class SkippedEntry:
    """Record of a file that was excluded from analysis, with reason."""
    relative_path: str
    reason: str          # e.g. "oversized", "symlink_escape", "prune_dir", "unsupported_format"
    size_bytes: Optional[int] = None


@dataclass
class ManifestEntry:
    """A discovered dependency manifest file."""
    relative_path: str
    format_id: str               # e.g. "pep517_pyproject"
    supported: bool
    sha256: str
    size_bytes: int


@dataclass
class SourceEntry:
    """A Python source or test file discovered in the repository."""
    relative_path: str
    is_test: bool
    sha256: str
    size_bytes: int


@dataclass
class ConfigEntry:
    """A configuration file relevant to dependency analysis (tox, Makefile, CI, etc.)."""
    relative_path: str
    config_type: str     # "tox", "makefile", "ci_github", "ci_gitlab", etc.
    sha256: str
    size_bytes: int


@dataclass
class RepositoryInventory:
    """Complete inventory of a scanned repository."""
    repo_root: str                   # Absolute resolved path
    repo_name: str
    manifests: List[ManifestEntry] = field(default_factory=list)
    source_files: List[SourceEntry] = field(default_factory=list)
    config_files: List[ConfigEntry] = field(default_factory=list)
    skipped: List[SkippedEntry] = field(default_factory=list)
    unsupported_manifests: List[str] = field(default_factory=list)
    file_count_capped: bool = False  # True if MAX_FILE_COUNT was reached

    @property
    def test_files(self) -> List[SourceEntry]:
        return [f for f in self.source_files if f.is_test]

    @property
    def non_test_files(self) -> List[SourceEntry]:
        return [f for f in self.source_files if not f.is_test]

    @property
    def supported_manifest_paths(self) -> List[str]:
        return [m.relative_path for m in self.manifests if m.supported]

    @property
    def manifest_sha256_map(self) -> Dict[str, str]:
        return {m.relative_path: m.sha256 for m in self.manifests if m.supported}

    @property
    def source_sha256_map(self) -> Dict[str, str]:
        return {s.relative_path: s.sha256 for s in self.source_files}


# ── config-file recognition ──────────────────────────────────────────────────

_CONFIG_PATTERNS: Dict[str, str] = {
    "tox.ini":          "tox",
    ".github":          "ci_github",       # directory — handled specially
    ".gitlab-ci.yml":   "ci_gitlab",
    "Makefile":         "makefile",
    "makefile":         "makefile",
    ".travis.yml":      "ci_travis",
    "appveyor.yml":     "ci_appveyor",
    "circle.yml":       "ci_circle",
    ".pre-commit-config.yaml": "pre_commit",
    "mypy.ini":         "mypy",
    ".mypy.ini":        "mypy",
    ".flake8":          "flake8",
    "pytest.ini":       "pytest",
    "conftest.py":      "pytest_conftest",
}


def _is_test_path(rel_path: str) -> bool:
    """Heuristic: classify a path as test code."""
    parts = rel_path.replace("\\", "/").split("/")
    name = parts[-1]
    return (
        "tests" in parts
        or "test" in parts
        or name.startswith("test_")
        or name.endswith("_test.py")
        or name == "conftest.py"
    )


def _sha256_of_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_symlink_escape(base: Path, link: Path) -> bool:
    """Return True if resolving *link* leaves *base*."""
    try:
        resolved = link.resolve()
        resolved.relative_to(base)
        return False
    except (ValueError, OSError):
        return True


class RepositoryInventoryScanner:
    """Walk a repository and collect all evidence-bearing artefacts.

    Parameters
    ----------
    repo_path:
        Explicit path to the repository root.  Must exist and be a directory.
    """

    def __init__(self, repo_path: str | Path) -> None:
        candidate = Path(repo_path).resolve()
        if not candidate.exists():
            raise FileNotFoundError(f"Repository path does not exist: {candidate}")
        if not candidate.is_dir():
            raise NotADirectoryError(f"Repository path is not a directory: {candidate}")
        # Validate the root itself (no traversal relative to itself — trivially safe)
        self._root = candidate

    @property
    def root(self) -> Path:
        return self._root

    def scan(self) -> RepositoryInventory:
        """Execute the full inventory scan and return the result."""
        inv = RepositoryInventory(
            repo_root=str(self._root),
            repo_name=self._root.name,
        )
        self._discover_top_level(inv)
        self._walk_tree(inv)
        return inv

    # ── top-level manifest discovery ─────────────────────────────────────────

    def _discover_top_level(self, inv: RepositoryInventory) -> None:
        """Check root directory for known manifests and config files."""
        for entry in self._root.iterdir():
            if not entry.is_file():
                continue
            name = entry.name
            rel = to_relative_posix(self._root, entry)

            # Unsupported manifest patterns
            if name in UNSUPPORTED_MANIFEST_PATTERNS:
                inv.unsupported_manifests.append(rel)
                inv.skipped.append(SkippedEntry(
                    relative_path=rel,
                    reason=f"unsupported_format:{name}",
                    size_bytes=self._safe_size(entry),
                ))
                continue

            if name in SUPPORTED_MANIFESTS:
                data = self._read_bounded(entry, inv, rel)
                if data is None:
                    continue
                inv.manifests.append(ManifestEntry(
                    relative_path=rel,
                    format_id=SUPPORTED_MANIFESTS[name],
                    supported=True,
                    sha256=_sha256_of_bytes(data),
                    size_bytes=len(data),
                ))
                continue

            # Config files at root
            if name in _CONFIG_PATTERNS:
                data = self._read_bounded(entry, inv, rel)
                if data is None:
                    continue
                inv.config_files.append(ConfigEntry(
                    relative_path=rel,
                    config_type=_CONFIG_PATTERNS[name],
                    sha256=_sha256_of_bytes(data),
                    size_bytes=len(data),
                ))

    # ── recursive tree walk ──────────────────────────────────────────────────

    def _walk_tree(self, inv: RepositoryInventory) -> None:
        """Walk the full tree, respecting prune rules and symlink boundaries."""
        file_count = 0
        for root_str, dirs, files in os.walk(str(self._root), followlinks=False):
            root_path = Path(root_str)

            # Prune dirs in-place
            dirs[:] = [
                d for d in dirs
                if not self._should_prune_dir(root_path / d, inv)
            ]

            for fname in files:
                if file_count >= MAX_FILE_COUNT:
                    inv.file_count_capped = True
                    return

                fpath = root_path / fname
                try:
                    rel = to_relative_posix(self._root, fpath)
                except PathTraversalError:
                    inv.skipped.append(SkippedEntry(
                        relative_path=str(fpath),
                        reason="path_traversal",
                    ))
                    continue

                # Symlink escape check
                if fpath.is_symlink() and _is_symlink_escape(self._root, fpath):
                    inv.skipped.append(SkippedEntry(
                        relative_path=rel,
                        reason="symlink_escape",
                        size_bytes=None,
                    ))
                    continue

                # Only process Python source files in tree walk
                if not fname.endswith(".py"):
                    continue

                data = self._read_bounded(fpath, inv, rel)
                if data is None:
                    continue

                file_count += 1
                inv.source_files.append(SourceEntry(
                    relative_path=rel,
                    is_test=_is_test_path(rel),
                    sha256=_sha256_of_bytes(data),
                    size_bytes=len(data),
                ))

    # ── helpers ──────────────────────────────────────────────────────────────

    def _should_prune_dir(self, dir_path: Path, inv: RepositoryInventory) -> bool:
        name = dir_path.name
        if name in PRUNE_DIRS:
            return True
        if name.endswith(PRUNE_DIR_SUFFIXES):
            return True
        # Prune symlink dirs that escape
        if dir_path.is_symlink() and _is_symlink_escape(self._root, dir_path):
            try:
                rel = to_relative_posix(self._root, dir_path)
            except PathTraversalError:
                rel = str(dir_path)
            inv.skipped.append(SkippedEntry(
                relative_path=rel,
                reason="symlink_escape_dir",
            ))
            return True
        return False

    def _read_bounded(
        self, path: Path, inv: RepositoryInventory, rel: str
    ) -> Optional[bytes]:
        """Read file bytes if within size limit; record skip otherwise."""
        try:
            size = path.stat().st_size
        except OSError as exc:
            inv.skipped.append(SkippedEntry(relative_path=rel, reason=f"stat_error:{exc}"))
            return None

        if size > MAX_FILE_SIZE_BYTES:
            inv.skipped.append(SkippedEntry(
                relative_path=rel,
                reason=f"oversized:{size}",
                size_bytes=size,
            ))
            return None

        try:
            return path.read_bytes()
        except OSError as exc:
            inv.skipped.append(SkippedEntry(
                relative_path=rel,
                reason=f"read_error:{exc}",
                size_bytes=size,
            ))
            return None

    @staticmethod
    def _safe_size(path: Path) -> Optional[int]:
        try:
            return path.stat().st_size
        except OSError:
            return None

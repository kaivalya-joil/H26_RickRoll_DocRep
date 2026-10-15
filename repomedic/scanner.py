"""Repository inventory scanner: manifests, dependency declarations, and AST imports."""

import ast
import hashlib
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

try:
    import tomllib
except ImportError:
    import toml as tomllib  # type: ignore

from .models import (
    DependencyDeclaration,
    EvidenceReference,
    FindingStatus,
    RepositoryMetadata,
    SourceImport,
)
from .safety import to_relative_posix, validate_safe_path

# Canonical mapping for common package names to imported module names
PACKAGE_TO_MODULE_MAP = {
    "jinja2": "jinja2",
    "python-dateutil": "dateutil",
    "pyyaml": "yaml",
    "pydantic": "pydantic",
    "setuptools": "setuptools",
    "requests": "requests",
    "click": "click",
    "rich": "rich",
    "toml": "toml",
    "appdirs": "appdirs",
    "six": "six",
    "chardet": "chardet",
    "idna": "idna",
    "certifi": "certifi",
    "nose": "nose",
    "pytest": "pytest",
}

MODULE_TO_PACKAGE_MAP = {v: k for k, v in PACKAGE_TO_MODULE_MAP.items()}
MODULE_TO_PACKAGE_MAP["pkg_resources"] = "setuptools"


class RepositoryScanner:
    """Scans repository structure, manifests, and source code imports."""

    def __init__(self, repo_dir: Path | str):
        self.repo_dir = Path(repo_dir).resolve()
        validate_safe_path(self.repo_dir, self.repo_dir)

    def scan(self) -> Tuple[RepositoryMetadata, List[DependencyDeclaration], List[SourceImport], Dict[str, str], Dict[str, str]]:
        """Run full repository scan.
        
        Returns:
            (metadata, declarations, imports, manifest_hashes, source_hashes)
        """
        manifest_files = self._locate_manifests()
        source_files, test_files = self._locate_python_files()

        declarations: List[DependencyDeclaration] = []
        manifest_hashes: Dict[str, str] = {}
        for m_path in manifest_files:
            rel_path = to_relative_posix(self.repo_dir, m_path)
            content = m_path.read_text(encoding="utf-8", errors="replace")
            manifest_hashes[rel_path] = hashlib.sha256(content.encode("utf-8")).hexdigest()
            declarations.extend(self._parse_manifest(m_path, rel_path, content))

        imports: List[SourceImport] = []
        source_hashes: Dict[str, str] = {}
        all_py_files = source_files + test_files
        for py_path in all_py_files:
            rel_path = to_relative_posix(self.repo_dir, py_path)
            content = py_path.read_text(encoding="utf-8", errors="replace")
            source_hashes[rel_path] = hashlib.sha256(content.encode("utf-8")).hexdigest()
            is_test = py_path in test_files
            imports.extend(self._extract_ast_imports(py_path, rel_path, content, is_test))

        metadata = self._build_metadata(manifest_files, source_files, test_files)
        return metadata, declarations, imports, manifest_hashes, source_hashes

    def _locate_manifests(self) -> List[Path]:
        """Find standard Python dependency manifests in repository."""
        manifest_names = {
            "pyproject.toml",
            "requirements.txt",
            "requirements-dev.txt",
            "setup.py",
            "setup.cfg",
            "Pipfile",
        }
        manifests = []
        for path in self.repo_dir.iterdir():
            if path.is_file() and path.name in manifest_names:
                manifests.append(path)
        return manifests

    def _locate_python_files(self) -> Tuple[List[Path], List[Path]]:
        """Identify source files and test files."""
        sources: List[Path] = []
        tests: List[Path] = []

        ignore_dirs = {".git", ".venv", "venv", "__pycache__", "build", "dist", ".pytest_cache"}

        for root, dirs, files in os.walk(self.repo_dir):
            dirs[:] = [d for d in dirs if d not in ignore_dirs]
            rel_root = Path(root).relative_to(self.repo_dir).as_posix()
            is_in_tests = rel_root.startswith("tests") or "test" in rel_root.split("/")

            for f in files:
                if f.endswith(".py"):
                    full_p = Path(root) / f
                    if is_in_tests or f.startswith("test_") or f.endswith("_test.py"):
                        tests.append(full_p)
                    else:
                        sources.append(full_p)
        return sources, tests

    def _parse_manifest(self, full_path: Path, rel_path: str, content: str) -> List[DependencyDeclaration]:
        """Extract dependency declarations with exact line-number evidence."""
        declarations: List[DependencyDeclaration] = []
        lines = content.splitlines()

        if full_path.name == "pyproject.toml":
            declarations.extend(self._parse_pyproject_toml(rel_path, lines, content))
        elif full_path.name.startswith("requirements"):
            is_dev = "dev" in full_path.name.lower() or "test" in full_path.name.lower()
            declarations.extend(self._parse_requirements_file(rel_path, lines, is_dev))
        return declarations

    def _parse_pyproject_toml(self, rel_path: str, lines: List[str], raw_text: str) -> List[DependencyDeclaration]:
        declarations: List[DependencyDeclaration] = []
        try:
            data = tomllib.loads(raw_text)
        except Exception:
            return declarations

        project_deps = data.get("project", {}).get("dependencies", [])
        for dep_str in project_deps:
            canonical, spec = self._split_name_and_spec(dep_str)
            line_no = self._find_line_in_text(lines, dep_str)
            declarations.append(
                DependencyDeclaration(
                    name=canonical,
                    raw_declaration=dep_str,
                    specifier=spec,
                    manifest_path=rel_path,
                    is_dev=False,
                    line_number=line_no,
                    status=FindingStatus.OBSERVED,
                )
            )

        optional_deps = data.get("project", {}).get("optional-dependencies", {})
        for group, group_deps in optional_deps.items():
            is_dev = "dev" in group.lower() or "test" in group.lower()
            for dep_str in group_deps:
                canonical, spec = self._split_name_and_spec(dep_str)
                line_no = self._find_line_in_text(lines, dep_str)
                declarations.append(
                    DependencyDeclaration(
                        name=canonical,
                        raw_declaration=dep_str,
                        specifier=spec,
                        manifest_path=rel_path,
                        is_dev=is_dev,
                        line_number=line_no,
                        status=FindingStatus.OBSERVED,
                    )
                )
        return declarations

    def _parse_requirements_file(self, rel_path: str, lines: List[str], is_dev: bool) -> List[DependencyDeclaration]:
        declarations: List[DependencyDeclaration] = []
        for idx, line in enumerate(lines, start=1):
            clean = line.strip()
            if not clean or clean.startswith("#") or clean.startswith("-"):
                continue
            canonical, spec = self._split_name_and_spec(clean)
            declarations.append(
                DependencyDeclaration(
                    name=canonical,
                    raw_declaration=clean,
                    specifier=spec,
                    manifest_path=rel_path,
                    is_dev=is_dev,
                    line_number=idx,
                    status=FindingStatus.OBSERVED,
                )
            )
        return declarations

    def _split_name_and_spec(self, declaration: str) -> Tuple[str, Optional[str]]:
        """Split a package requirement string like 'pydantic>=2.0' into ('pydantic', '>=2.0')."""
        match = re.split(r"([=<>!~;].*)", declaration.strip(), maxsplit=1)
        name = match[0].strip().lower()
        spec = match[1].strip() if len(match) > 1 else None
        return name, spec

    def _find_line_in_text(self, lines: List[str], needle: str) -> Optional[int]:
        for idx, line in enumerate(lines, start=1):
            if needle in line:
                return idx
        return None

    def _extract_ast_imports(self, full_path: Path, rel_path: str, content: str, is_test: bool) -> List[SourceImport]:
        """Extract imports using Python AST with line numbers and try/except contexts."""
        imports: List[SourceImport] = []
        try:
            tree = ast.parse(content, filename=str(full_path))
        except SyntaxError:
            # File has syntax error - return empty or handle gracefully
            return imports

        class ImportVisitor(ast.NodeVisitor):
            def __init__(self):
                self.in_try = False

            def visit_Try(self, node: ast.Try):
                prev = self.in_try
                self.in_try = True
                self.generic_visit(node)
                self.in_try = prev

            def visit_Import(self, node: ast.Import):
                for alias in node.names:
                    top_module = alias.name.split(".")[0]
                    imports.append(
                        SourceImport(
                            module=top_module,
                            imported_names=[alias.name],
                            file_path=rel_path,
                            line_number=node.lineno,
                            is_test_file=is_test,
                            is_try_except=self.in_try,
                            status=FindingStatus.OBSERVED,
                        )
                    )
                self.generic_visit(node)

            def visit_ImportFrom(self, node: ast.ImportFrom):
                if node.module:
                    top_module = node.module.split(".")[0]
                    imported_names = [alias.name for alias in node.names]
                    imports.append(
                        SourceImport(
                            module=top_module,
                            imported_names=imported_names,
                            file_path=rel_path,
                            line_number=node.lineno,
                            is_test_file=is_test,
                            is_try_except=self.in_try,
                            status=FindingStatus.OBSERVED,
                        )
                    )
                self.generic_visit(node)

        visitor = ImportVisitor()
        visitor.visit(tree)
        return imports

    def _build_metadata(self, manifests: List[Path], sources: List[Path], tests: List[Path]) -> RepositoryMetadata:
        repo_name = self.repo_dir.name
        git_branch = None
        git_commit = None
        try:
            git_branch = subprocess.check_output(
                ["git", "-C", str(self.repo_dir), "rev-parse", "--abbrev-ref", "HEAD"],
                text=True, stderr=subprocess.DEVNULL
            ).strip()
            git_commit = subprocess.check_output(
                ["git", "-C", str(self.repo_dir), "rev-parse", "HEAD"],
                text=True, stderr=subprocess.DEVNULL
            ).strip()
        except Exception:
            pass

        py_version_detected = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        py_requires = None
        for m in manifests:
            if m.name == "pyproject.toml":
                try:
                    data = tomllib.loads(m.read_text(encoding="utf-8", errors="replace"))
                    py_requires = data.get("project", {}).get("requires-python")
                except Exception:
                    pass

        return RepositoryMetadata(
            repo_name=repo_name,
            repo_path=str(self.repo_dir),
            git_branch=git_branch,
            git_commit=git_commit,
            python_version_detected=py_version_detected,
            python_requires_declared=py_requires,
            manifests_found=[to_relative_posix(self.repo_dir, m) for m in manifests],
            source_files_count=len(sources),
            test_files_count=len(tests),
        )

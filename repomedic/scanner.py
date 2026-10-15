"""Repository inventory scanner: manifests, dependency declarations, and AST imports."""

from __future__ import annotations

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
    Finding,
    FindingSeverity,
    FindingStatus,
    RepositoryMetadata,
    SourceImport,
)
from .safety import to_relative_posix, validate_safe_path

# Standard library modules set for separation
STDLIB_MODULES = sys.stdlib_module_names if hasattr(sys, "stdlib_module_names") else {
    "abc", "argparse", "ast", "asyncio", "base64", "collections", "contextlib",
    "copy", "csv", "datetime", "decimal", "difflib", "dis", "email", "enum",
    "errno", "functools", "glob", "hashlib", "http", "importlib", "inspect",
    "io", "itertools", "json", "logging", "math", "multiprocessing", "os",
    "pathlib", "pickle", "platform", "queue", "random", "re", "shutil",
    "signal", "socket", "sqlite3", "ssl", "stat", "string", "subprocess",
    "sys", "tempfile", "threading", "time", "traceback", "types", "typing",
    "unittest", "urllib", "uuid", "warnings", "weakref", "zipfile", "tomllib",
}

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
        candidate = Path(repo_dir)
        if not candidate.exists():
            raise FileNotFoundError(f"Repository path does not exist: {candidate}")
        if not candidate.is_dir():
            raise NotADirectoryError(f"Repository path is not a directory: {candidate}")
        self.repo_dir = candidate.resolve()
        validate_safe_path(self.repo_dir, self.repo_dir)

    def scan(self) -> Tuple[RepositoryMetadata, List[DependencyDeclaration], List[SourceImport], Dict[str, str], Dict[str, str]]:
        """Run full repository scan."""
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

    def run_deterministic_rules(
        self,
        declarations: List[DependencyDeclaration],
        imports: List[SourceImport],
    ) -> List[Finding]:
        """Produce evidence-grounded findings with confidence and explicit limitations."""
        findings: List[Finding] = []

        # 1. Manifest Conflicts (e.g. pydantic>=2 vs pydantic==1.10.13)
        by_pkg: Dict[str, List[DependencyDeclaration]] = {}
        for d in declarations:
            by_pkg.setdefault(d.name, []).append(d)

        conflict_idx = 1
        for pkg, decls in sorted(by_pkg.items()):
            specs = {d.specifier for d in decls if d.specifier}
            if len(specs) > 1:
                findings.append(Finding(
                    id=f"MANIFEST-DIV-{conflict_idx:03d}",
                    category="manifest_conflict",
                    title=f"Conflicting version constraints for '{pkg}'",
                    explanation=f"Package '{pkg}' declared with contradictory specifiers: {' vs '.join(repr(s) for s in sorted(specs))}.",
                    severity=FindingSeverity.HIGH,
                    status=FindingStatus.OBSERVED,
                    package_name=pkg,
                    confidence=1.0,
                    limitations=["Only checks declared manifests; resolver behavior depends on pip/uv resolution flags."],
                    evidence=[
                        EvidenceReference(
                            file_path=d.manifest_path,
                            line_start=d.line_number,
                            line_end=d.line_number,
                            content_snippet=d.raw_declaration,
                            source_type="manifest",
                        ) for d in decls
                    ],
                    remediation_hint=f"Align '{pkg}' specification across manifests.",
                ))
                conflict_idx += 1

        # 2. Undeclared Third-Party Imports (e.g. certifi imported without manifest entry)
        declared_pkgs = {d.name.lower() for d in declarations}
        declared_modules = {PACKAGE_TO_MODULE_MAP.get(p, p).lower() for p in declared_pkgs}

        # Identify local module names in repository
        local_modules = {p.stem.lower() for p in self.repo_dir.rglob("*.py")}
        local_modules.update({p.name.lower() for p in self.repo_dir.iterdir() if p.is_dir()})

        undeclared_idx = 1
        seen_undeclared = set()
        for imp in imports:
            mod = imp.module.lower()
            if mod in STDLIB_MODULES or mod in local_modules or mod.startswith("."):
                continue
            if mod not in declared_modules and mod not in declared_pkgs and mod not in seen_undeclared:
                seen_undeclared.add(mod)
                findings.append(Finding(
                    id=f"UNDECLARED-{undeclared_idx:03d}",
                    category="undeclared_dependency",
                    title=f"Undeclared third-party import: '{mod}'",
                    explanation=(
                        f"Module '{mod}' is directly imported in source code ({imp.file_path}:{imp.line_number}), "
                        f"but has no corresponding declaration in requirements.txt or pyproject.toml."
                    ),
                    severity=FindingSeverity.HIGH,
                    status=FindingStatus.OBSERVED,
                    package_name=mod,
                    confidence=0.95,
                    limitations=["Transitive dependencies installed by other packages may satisfy this at runtime."],
                    evidence=[EvidenceReference(
                        file_path=imp.file_path,
                        line_start=imp.line_number,
                        line_end=imp.line_number,
                        content_snippet=f"import {mod}",
                        source_type="source_ast",
                    )],
                    remediation_hint=f"Add '{mod}' explicitly to dependency manifests.",
                ))
                undeclared_idx += 1

        # 3. Possibly Unused Dependencies
        cli_or_build = {"pytest", "coverage", "flake8", "mypy", "black", "ruff", "setuptools"}
        imported_modules = {imp.module.lower() for imp in imports}
        
        ghost_idx = 1
        for pkg, decls in sorted(by_pkg.items()):
            canonical = PACKAGE_TO_MODULE_MAP.get(pkg, pkg).lower()
            if pkg in cli_or_build or canonical in cli_or_build:
                continue
            if canonical not in imported_modules and pkg not in imported_modules:
                findings.append(Finding(
                    id=f"GHOST-{ghost_idx:03d}",
                    category="ghost_dependency",
                    title=f"POSSIBLY unused dependency: '{pkg}'",
                    explanation=(
                        f"No static AST import statement observed for '{pkg}' (or module '{canonical}') "
                        f"across repository files. Never assume definitely unused without runtime verification."
                    ),
                    severity=FindingSeverity.MEDIUM if pkg != "six" else FindingSeverity.HIGH,
                    status=FindingStatus.INFERRED,
                    package_name=pkg,
                    confidence=0.75,
                    limitations=[
                        "Static AST cannot detect dynamic imports (importlib.import_module, __import__).",
                        "Entry points, CLI tools, and plugins are often not imported directly.",
                    ],
                    evidence=[
                        EvidenceReference(
                            file_path=d.manifest_path,
                            line_start=d.line_number,
                            line_end=d.line_number,
                            content_snippet=d.raw_declaration,
                            source_type="manifest",
                        ) for d in decls
                    ],
                    remediation_hint=f"Verify runtime usage of '{pkg}' before removing.",
                ))
                ghost_idx += 1

        # 4. Inconclusive / Candidate checks
        # HTTP calls with missing timeout parameter
        timeout_idx = 1
        for py_file in self.repo_dir.rglob("*.py"):
            try:
                text = py_file.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(text, filename=str(py_file))
                rel = to_relative_posix(self.repo_dir, py_file)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Call):
                        # check session.get / requests.get without timeout=
                        func_name = ""
                        if isinstance(node.func, ast.Attribute):
                            func_name = node.func.attr
                        if func_name in ("get", "post", "put", "delete"):
                            has_timeout = any(kw.arg == "timeout" for kw in node.keywords)
                            if not has_timeout:
                                findings.append(Finding(
                                    id=f"HTTP-TIMEOUT-{timeout_idx:03d}",
                                    category="network_resilience",
                                    title="HTTP request with no explicit timeout parameter",
                                    explanation=f"Call to '{func_name}()' in {rel} (line {node.lineno}) has no explicit timeout.",
                                    severity=FindingSeverity.MEDIUM,
                                    status=FindingStatus.OBSERVED,
                                    confidence=0.90,
                                    limitations=["Default timeouts may be configured at the custom adapter level."],
                                    evidence=[EvidenceReference(
                                        file_path=rel,
                                        line_start=node.lineno,
                                        line_end=node.lineno,
                                        content_snippet=f"{func_name}(...) without timeout",
                                        source_type="source_ast",
                                    )],
                                    remediation_hint=f"Specify explicit timeout (e.g. timeout=10) on {func_name}() call.",
                                ))
                                timeout_idx += 1
            except Exception:
                pass

        return findings

    def _locate_manifests(self) -> List[Path]:
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
            declarations.append(DependencyDeclaration(
                name=canonical,
                raw_declaration=dep_str,
                specifier=spec,
                manifest_path=rel_path,
                is_dev=False,
                line_number=line_no,
                status=FindingStatus.OBSERVED,
            ))

        optional_deps = data.get("project", {}).get("optional-dependencies", {})
        for group, group_deps in optional_deps.items():
            is_dev = "dev" in group.lower() or "test" in group.lower()
            for dep_str in group_deps:
                canonical, spec = self._split_name_and_spec(dep_str)
                line_no = self._find_line_in_text(lines, dep_str)
                declarations.append(DependencyDeclaration(
                    name=canonical,
                    raw_declaration=dep_str,
                    specifier=spec,
                    manifest_path=rel_path,
                    is_dev=is_dev,
                    line_number=line_no,
                    status=FindingStatus.OBSERVED,
                ))
        return declarations

    def _parse_requirements_file(self, rel_path: str, lines: List[str], is_dev: bool) -> List[DependencyDeclaration]:
        declarations: List[DependencyDeclaration] = []
        for idx, line in enumerate(lines, start=1):
            clean = line.strip()
            if not clean or clean.startswith("#") or clean.startswith("-"):
                continue
            canonical, spec = self._split_name_and_spec(clean)
            declarations.append(DependencyDeclaration(
                name=canonical,
                raw_declaration=clean,
                specifier=spec,
                manifest_path=rel_path,
                is_dev=is_dev,
                line_number=idx,
                status=FindingStatus.OBSERVED,
            ))
        return declarations

    def _split_name_and_spec(self, declaration: str) -> Tuple[str, Optional[str]]:
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
        imports: List[SourceImport] = []
        try:
            tree = ast.parse(content, filename=str(full_path))
        except SyntaxError:
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
                    imports.append(SourceImport(
                        module=top_module,
                        imported_names=[alias.name],
                        file_path=rel_path,
                        line_number=node.lineno,
                        is_test_file=is_test,
                        is_try_except=self.in_try,
                        status=FindingStatus.OBSERVED,
                    ))
                self.generic_visit(node)

            def visit_ImportFrom(self, node: ast.ImportFrom):
                if node.module:
                    top_module = node.module.split(".")[0]
                    imported_names = [alias.name for alias in node.names]
                    imports.append(SourceImport(
                        module=top_module,
                        imported_names=imported_names,
                        file_path=rel_path,
                        line_number=node.lineno,
                        is_test_file=is_test,
                        is_try_except=self.in_try,
                        status=FindingStatus.OBSERVED,
                    ))
                self.generic_visit(node)

        visitor = ImportVisitor()
        visitor.visit(tree)
        return imports

    def _build_metadata(self, manifests: List[Path], sources: List[Path], tests: List[Path]) -> RepositoryMetadata:
        repo_name = self.repo_dir.name
        git_branch, git_commit = None, None
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

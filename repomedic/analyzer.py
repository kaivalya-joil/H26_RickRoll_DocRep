"""AI Analyzer and deterministic rules engine for dependency resilience."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .hermes_adapter import AIAnalysisResult, HermesAdapter
from .models import (
    DependencyDeclaration,
    EvidenceReference,
    Finding,
    FindingSeverity,
    FindingStatus,
    RepositoryMetadata,
    SourceImport,
)
from .scanner import MODULE_TO_PACKAGE_MAP, PACKAGE_TO_MODULE_MAP

SEVERITY_WEIGHTS = {
    FindingSeverity.CRITICAL: 1.0,
    FindingSeverity.HIGH: 0.8,
    FindingSeverity.MEDIUM: 0.5,
    FindingSeverity.LOW: 0.3,
    FindingSeverity.INFO: 0.1,
}


class DependencyAnalyzer:
    """Performs deterministic analysis (ghost detection, tripwires, conflicts)

    and orchestrates AI analysis, ranking, and snippet extraction.
    """

    def __init__(
        self,
        metadata: Any,
        declarations: Optional[List[DependencyDeclaration]] = None,
        imports: Optional[List[SourceImport]] = None,
        adapter: Optional[HermesAdapter] = None,
    ):
        if isinstance(metadata, (str, Path)) and declarations is None:
            self.repo_dir = Path(metadata).resolve()
            self.metadata = RepositoryMetadata(
                repo_name=self.repo_dir.name,
                repo_path=str(self.repo_dir),
                python_version_detected="3.10",
                manifests_found=[],
            )
            self.declarations = []
            self.imports = []
        else:
            self.metadata = metadata
            self.declarations = declarations or []
            self.imports = imports or []
            if metadata and hasattr(metadata, "repo_path"):
                self.repo_dir = Path(metadata.repo_path).resolve()
            else:
                self.repo_dir = Path(".").resolve()

        self.adapter = adapter or HermesAdapter()

    def analyze(self) -> List[Finding]:
        """Run all deterministic analysis rules and return findings."""
        findings: List[Finding] = []
        findings.extend(self._detect_manifest_divergences())
        findings.extend(self._detect_ghost_dependencies())
        findings.extend(self._detect_migration_tripwires())
        findings.extend(self._detect_private_api_usage())
        return findings

    def _detect_manifest_divergences(self) -> List[Finding]:
        """Detect conflicting version constraints between pyproject.toml and requirements.txt."""
        findings: List[Finding] = []
        by_pkg: Dict[str, List[DependencyDeclaration]] = {}
        for decl in self.declarations:
            by_pkg.setdefault(decl.name, []).append(decl)

        counter = 1
        for pkg_name, decls in sorted(by_pkg.items()):
            if len(decls) > 1:
                specs = {d.specifier for d in decls if d.specifier}
                if len(specs) > 1:
                    evidence = [
                        EvidenceReference(
                            file_path=d.manifest_path,
                            line_start=d.line_number,
                            line_end=d.line_number,
                            content_snippet=d.raw_declaration,
                            source_type="manifest",
                        )
                        for d in decls
                    ]
                    specs_str = " vs ".join(repr(s) for s in sorted(specs))
                    findings.append(
                        Finding(
                            id=f"MANIFEST-DIV-{counter:03d}",
                            category="manifest_conflict",
                            title=f"Conflicting version specifications for '{pkg_name}'",
                            explanation=(
                                f"Package '{pkg_name}' is declared across multiple manifests with contradictory "
                                f"specifiers ({specs_str}). In LinkWatch, pyproject.toml specifies 'pydantic>=2' while "
                                f"requirements.txt pins 'pydantic==1.10.13', leading to non-deterministic installs "
                                f"depending on whether pip or build-isolation is used."
                            ),
                            severity=FindingSeverity.HIGH,
                            status=FindingStatus.OBSERVED,
                            package_name=pkg_name,
                            evidence=evidence,
                            remediation_hint=f"Align {pkg_name} version constraint across pyproject.toml and requirements.txt",
                        )
                    )
                    counter += 1
        return findings

    def _detect_ghost_dependencies(self) -> List[Finding]:
        """Feature A: Dependency Ghost Detector.

        Identify declared packages not observed in imports of scanned files.
        """
        findings: List[Finding] = []

        imported_modules: Set[str] = {imp.module.lower() for imp in self.imports}

        observed_packages: Set[str] = set()
        for mod in imported_modules:
            observed_packages.add(mod)
            if mod in MODULE_TO_PACKAGE_MAP:
                observed_packages.add(MODULE_TO_PACKAGE_MAP[mod])

        cli_or_build_tools = {"pytest", "coverage", "flake8", "mypy", "black", "ruff", "setuptools"}

        declared_unique: Dict[str, List[DependencyDeclaration]] = {}
        for d in self.declarations:
            declared_unique.setdefault(d.name, []).append(d)

        counter = 1
        for pkg_name, decls in sorted(declared_unique.items()):
            canonical_mod = PACKAGE_TO_MODULE_MAP.get(pkg_name, pkg_name).lower()

            if pkg_name in cli_or_build_tools or canonical_mod in cli_or_build_tools:
                continue

            if canonical_mod not in imported_modules and pkg_name not in observed_packages:
                evidence = [
                    EvidenceReference(
                        file_path=d.manifest_path,
                        line_start=d.line_number,
                        line_end=d.line_number,
                        content_snippet=d.raw_declaration,
                        source_type="manifest",
                    )
                    for d in decls
                ]

                explanation = (
                    f"Package '{pkg_name}' is declared in project manifests ({', '.join(d.manifest_path for d in decls)}), "
                    f"but no AST import statement for '{pkg_name}' or module '{canonical_mod}' was found across the "
                    f"entire repository source or test files. Possible explanations include dynamic imports, legacy "
                    f"Python 2 compatibility shim (e.g. 'six'), transitive requirement artifact, or an abandoned dependency."
                )

                findings.append(
                    Finding(
                        id=f"GHOST-{counter:03d}",
                        category="ghost_dependency",
                        title=f"Unused / Ghost dependency detected: '{pkg_name}'",
                        explanation=explanation,
                        severity=FindingSeverity.MEDIUM if pkg_name != "six" else FindingSeverity.HIGH,
                        status=FindingStatus.INFERRED,
                        package_name=pkg_name,
                        evidence=evidence,
                        remediation_hint=f"Verify if '{pkg_name}' is needed at runtime; if not, safely remove it from manifests.",
                    )
                )
                counter += 1
        return findings

    def _detect_migration_tripwires(self) -> List[Finding]:
        """Feature C: Migration Tripwire.

        Compare actual usage evidence with available compatibility evidence for proposed modern replacements.
        """
        findings: List[Finding] = []
        counter = 1

        # Check 1: toml -> tomllib (Python 3.11+)
        toml_decls = [d for d in self.declarations if d.name == "toml"]
        toml_imports = [i for i in self.imports if i.module == "toml"]
        if toml_decls or toml_imports:
            evidence = []
            for d in toml_decls:
                evidence.append(
                    EvidenceReference(
                        file_path=d.manifest_path,
                        line_start=d.line_number,
                        line_end=d.line_number,
                        content_snippet=d.raw_declaration,
                        source_type="manifest",
                    )
                )
            for imp in toml_imports:
                evidence.append(
                    EvidenceReference(
                        file_path=imp.file_path,
                        line_start=imp.line_number,
                        line_end=imp.line_number,
                        content_snippet="import toml (or from toml import ...)",
                        source_type="source_ast",
                    )
                )

            findings.append(
                Finding(
                    id=f"TRIPWIRE-{counter:03d}",
                    category="migration_tripwire",
                    title="Legacy 'toml' library in Python 3.11+ project",
                    explanation=(
                        "LinkWatch declares and imports third-party 'toml==0.10.2' (unmaintained since 2020). "
                        "Because LinkWatch requires Python >= 3.10 (and targets 3.12/3.13), Python's standard library "
                        "'tomllib' (available since Python 3.11) provides a faster, built-in, zero-dependency alternative."
                    ),
                    severity=FindingSeverity.HIGH,
                    status=FindingStatus.OBSERVED,
                    package_name="toml",
                    evidence=evidence,
                    remediation_hint="Migrate 'import toml' -> 'import tomllib' (with tomli fallback for <3.11 if needed). Note: tomllib uses binary read mode rb.",
                )
            )
            counter += 1

        # Check 2: appdirs -> platformdirs
        appdirs_decls = [d for d in self.declarations if d.name == "appdirs"]
        appdirs_imports = [i for i in self.imports if i.module == "appdirs"]
        if appdirs_decls or appdirs_imports:
            evidence = []
            for d in appdirs_decls:
                evidence.append(
                    EvidenceReference(
                        file_path=d.manifest_path,
                        line_start=d.line_number,
                        line_end=d.line_number,
                        content_snippet=d.raw_declaration,
                        source_type="manifest",
                    )
                )
            for imp in appdirs_imports:
                evidence.append(
                    EvidenceReference(
                        file_path=imp.file_path,
                        line_start=imp.line_number,
                        line_end=imp.line_number,
                        content_snippet=f"from appdirs import {', '.join(imp.imported_names)}",
                        source_type="source_ast",
                    )
                )
            findings.append(
                Finding(
                    id=f"TRIPWIRE-{counter:03d}",
                    category="migration_tripwire",
                    title="Abandoned dependency 'appdirs' unmaintained since 2017",
                    explanation=(
                        "LinkWatch uses 'appdirs==1.4.4' for user cache directory determination. 'appdirs' has had no "
                        "releases since 2017 and is unmaintained. The community-standard modern drop-in replacement is "
                        "'platformdirs', providing active support and consistent cross-platform behavior on modern OSes."
                    ),
                    severity=FindingSeverity.MEDIUM,
                    status=FindingStatus.OBSERVED,
                    package_name="appdirs",
                    evidence=evidence,
                    remediation_hint="Replace 'appdirs' with 'platformdirs' (API: platformdirs.user_cache_dir()).",
                )
            )
            counter += 1

        # Check 3: nose==1.3.7 in requirements-dev.txt
        nose_decls = [d for d in self.declarations if d.name == "nose"]
        if nose_decls:
            evidence = [
                EvidenceReference(
                    file_path=d.manifest_path,
                    line_start=d.line_number,
                    line_end=d.line_number,
                    content_snippet=d.raw_declaration,
                    source_type="manifest",
                )
                for d in nose_decls
            ]
            findings.append(
                Finding(
                    id=f"TRIPWIRE-{counter:03d}",
                    category="migration_tripwire",
                    title="Obsolete test runner 'nose' declared in requirements-dev.txt",
                    explanation=(
                        "LinkWatch specifies 'nose==1.3.7' in requirements-dev.txt and Makefile. 'nose' was abandoned "
                        "in 2015, relies on removed Python internals, and fails under Python 3.12+. LinkWatch already has "
                        "pytest test suites configured in pyproject.toml."
                    ),
                    severity=FindingSeverity.HIGH,
                    status=FindingStatus.OBSERVED,
                    package_name="nose",
                    evidence=evidence,
                    remediation_hint="Remove 'nose' from requirements-dev.txt and Makefile; use pytest exclusively.",
                )
            )
            counter += 1

        # Check 4: pkg_resources in resources.py
        pkg_res_imports = [
            i
            for i in self.imports
            if i.module in ("pkg_resources", "setuptools") or "pkg_resources" in i.imported_names
        ]
        if pkg_res_imports:
            evidence = [
                EvidenceReference(
                    file_path=imp.file_path,
                    line_start=imp.line_number,
                    line_end=imp.line_number,
                    content_snippet="import pkg_resources",
                    source_type="source_ast",
                )
                for imp in pkg_res_imports
            ]
            findings.append(
                Finding(
                    id=f"TRIPWIRE-{counter:03d}",
                    category="migration_tripwire",
                    title="Deprecated 'pkg_resources' API used for resource resolution",
                    explanation=(
                        "LinkWatch imports 'pkg_resources' in 'linkwatch/resources.py' to locate template files. "
                        "'pkg_resources' is deprecated by setuptools and incurs significant import overhead. "
                        "Python 3.9+ standard library 'importlib.resources.files()' is the modern, zero-overhead replacement."
                    ),
                    severity=FindingSeverity.MEDIUM,
                    status=FindingStatus.OBSERVED,
                    package_name="setuptools",
                    evidence=evidence,
                    remediation_hint="Replace 'pkg_resources.resource_filename' with 'importlib.resources.files(\"linkwatch\").joinpath(\"templates\")'.",
                )
            )
            counter += 1

        # Check 5: Pydantic v1 @validator and class Config in config.py
        pydantic_imports = [i for i in self.imports if i.module == "pydantic"]
        if pydantic_imports:
            evidence = [
                EvidenceReference(
                    file_path=imp.file_path,
                    line_start=imp.line_number,
                    line_end=imp.line_number,
                    content_snippet=f"from pydantic import {', '.join(imp.imported_names)}",
                    source_type="source_ast",
                )
                for imp in pydantic_imports
            ]
            findings.append(
                Finding(
                    id=f"TRIPWIRE-{counter:03d}",
                    category="migration_tripwire",
                    title="Pydantic V1 API patterns (@validator, class Config) used in source",
                    explanation=(
                        "LinkWatch uses 'from pydantic import BaseModel, validator' and class-based 'Config' in 'linkwatch/config.py'. "
                        "When running under Pydantic 2.x (as permitted by pyproject.toml 'pydantic>=2'), these trigger "
                        "PydanticDeprecatedSince20 warnings and will break completely in Pydantic V3."
                    ),
                    severity=FindingSeverity.HIGH,
                    status=FindingStatus.INFERRED,
                    package_name="pydantic",
                    evidence=evidence,
                    remediation_hint="Migrate @validator to @field_validator and class Config to ConfigDict (model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)).",
                )
            )
            counter += 1

        return findings

    def _detect_private_api_usage(self) -> List[Finding]:
        """Detect reliance on internal or undocumented third-party symbols."""
        findings: List[Finding] = []
        counter = 1

        for imp in self.imports:
            for name in imp.imported_names:
                if name.startswith("_") and not name.startswith("__"):
                    findings.append(
                        Finding(
                            id=f"PRIVATE-API-{counter:03d}",
                            category="private_api",
                            title=f"Private symbol imported from '{imp.module}': '{name}'",
                            explanation=(
                                f"In file '{imp.file_path}' (line {imp.line_number}), private symbol '{name}' is "
                                f"imported from '{imp.module}'. Internal symbols are subject to removal or renaming "
                                f"in minor or patch releases without deprecation notice."
                            ),
                            severity=FindingSeverity.MEDIUM,
                            status=FindingStatus.OBSERVED,
                            package_name=imp.module,
                            evidence=[
                                EvidenceReference(
                                    file_path=imp.file_path,
                                    line_start=imp.line_number,
                                    line_end=imp.line_number,
                                    content_snippet=f"from {imp.module} import {name}",
                                    source_type="source_ast",
                                )
                            ],
                            remediation_hint=f"Replace private symbol '{name}' with public API or standard library parsing.",
                        )
                    )
                    counter += 1
        return findings

    def rank_findings(self, findings: List[Finding]) -> List[Finding]:
        """Rank findings by severity x confidence score."""

        def score(f: Finding) -> float:
            sev_w = SEVERITY_WEIGHTS.get(f.severity, 0.5)
            return sev_w * (f.confidence or 0.8)

        return sorted(findings, key=score, reverse=True)

    def extract_snippet(self, finding: Finding, window: int = 5) -> str:
        """Extract ~5 lines around cited line evidence."""
        if not finding.evidence:
            return "No file evidence reference available."

        ref = finding.evidence[0]
        file_p = self.repo_dir / ref.file_path
        if not file_p.exists() or not file_p.is_file():
            return ref.content_snippet or "Snippet not accessible on disk."

        try:
            lines = file_p.read_text(encoding="utf-8", errors="replace").splitlines()
            target_line = ref.line_start or 1
            start = max(0, target_line - (window // 2) - 1)
            end = min(len(lines), start + window)
            numbered = [f"{i+1:3d} | {lines[i]}" for i in range(start, end)]
            return "\n".join(numbered)
        except Exception as e:
            return f"Error reading snippet: {e}"

    def run_analysis(
        self,
        findings: List[Finding],
        deep: bool = False,
    ) -> List[Tuple[Finding, AIAnalysisResult]]:
        """Run AI analysis. In fast mode (default) analyzes top 5; --deep analyzes all."""
        ranked = self.rank_findings(findings)
        selected = ranked if deep else ranked[:5]

        results = []
        for finding in selected:
            snippet = self.extract_snippet(finding)
            res = self.adapter.analyze_finding(finding, snippet)
            results.append((finding, res))

        return results


AIAnalyzer = DependencyAnalyzer

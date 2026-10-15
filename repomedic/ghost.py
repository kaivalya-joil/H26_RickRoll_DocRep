"""Ghost Dependency Detector — evidence-backed ghost / unused dependency analysis.

Classifies each declared dependency's usage as:
  usage_found          — direct import observed in AST scan
  possibly_unused      — no import found; heuristics don't explain the absence
  usage_uncertain      — no import found, but a legitimate reason exists
  not_applicable       — build tool / test runner / entry-point / pure CLI package

Evidence is grounded in AST import data.  The detector NEVER removes dependencies;
it only produces reasoned observations.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

from .models import (
    DependencyDeclaration,
    EvidenceReference,
    Finding,
    FindingSeverity,
    FindingStatus,
    SourceImport,
)

# ---------------------------------------------------------------------------
# Distribution-name → import-name mapping
# Rules of thumb:
#   • Canonical: same name (requests → requests)
#   • Rename:    distribution uses a different top-level module
#   • Ambiguous: one distribution ships multiple top-level modules
#   • Unknown:   not in this table → mapping_status = "ambiguous"
# ---------------------------------------------------------------------------

# (distribution_name, [top-level module names], mapping_status)
_DIST_TO_MODULES: List[Tuple[str, List[str], str]] = [
    # stdlib-shims / compatibility packages
    ("six",                 ["six"],                       "direct"),
    ("future",              ["future", "past", "builtins"], "ambiguous"),
    ("typing-extensions",   ["typing_extensions"],          "direct"),
    ("importlib-metadata",  ["importlib_metadata"],         "direct"),
    ("importlib-resources", ["importlib_resources"],        "direct"),
    ("zipp",                ["zipp"],                       "direct"),
    # HTTP / network
    ("requests",            ["requests"],                   "direct"),
    ("urllib3",             ["urllib3"],                     "direct"),
    ("httpx",               ["httpx"],                      "direct"),
    ("aiohttp",             ["aiohttp"],                    "direct"),
    ("certifi",             ["certifi"],                    "direct"),
    ("chardet",             ["chardet"],                    "direct"),
    ("charset-normalizer",  ["charset_normalizer"],         "direct"),
    ("idna",                ["idna"],                       "direct"),
    # Parsing / serialisation
    ("pyyaml",              ["yaml"],                       "direct"),
    ("toml",                ["toml"],                       "direct"),
    ("tomli",               ["tomli"],                      "direct"),
    ("python-dateutil",     ["dateutil"],                   "direct"),
    ("python-dotenv",       ["dotenv"],                     "direct"),
    ("jinja2",              ["jinja2"],                     "direct"),
    ("markupsafe",          ["markupsafe"],                 "direct"),
    # CLI / TUI
    ("click",               ["click"],                      "direct"),
    ("rich",                ["rich"],                       "direct"),
    ("colorama",            ["colorama"],                   "direct"),
    ("tabulate",            ["tabulate"],                   "direct"),
    ("tqdm",                ["tqdm"],                       "direct"),
    # Data / types
    ("pydantic",            ["pydantic"],                   "direct"),
    ("attrs",               ["attr", "attrs"],              "ambiguous"),
    ("dataclasses",         ["dataclasses"],                "direct"),
    # Build / packaging
    ("setuptools",          ["setuptools", "pkg_resources"], "ambiguous"),
    ("wheel",               ["wheel"],                      "direct"),
    ("build",               ["build"],                      "direct"),
    ("flit",                ["flit"],                       "direct"),
    # File paths
    ("appdirs",             ["appdirs"],                    "direct"),
    ("platformdirs",        ["platformdirs"],               "direct"),
    # Crypto / hashing
    ("cryptography",        ["cryptography"],               "direct"),
    ("pyopenssl",           ["OpenSSL"],                    "direct"),
    # Test / dev (always not_applicable as production deps)
    ("pytest",              ["pytest", "_pytest"],          "direct"),
    ("coverage",            ["coverage"],                   "direct"),
    ("nose",                ["nose"],                       "direct"),
    ("mock",                ["mock", "unittest.mock"],      "ambiguous"),
    ("factory-boy",         ["factory"],                    "direct"),
    ("faker",               ["faker"],                      "direct"),
    ("responses",           ["responses"],                  "direct"),
    ("moto",                ["moto"],                       "direct"),
    # Linters / formatters (never imported; always not_applicable)
    ("flake8",              [],                             "cli_only"),
    ("mypy",                [],                             "cli_only"),
    ("black",               [],                             "cli_only"),
    ("ruff",                [],                             "cli_only"),
    ("isort",               [],                             "cli_only"),
    ("pyflakes",            [],                             "cli_only"),
    ("pycodestyle",         [],                             "cli_only"),
    ("pylint",              [],                             "cli_only"),
    # Type stubs (never imported at runtime)
    ("types-requests",      [],                             "type_stubs"),
    ("types-setuptools",    [],                             "type_stubs"),
    ("types-pyyaml",        [],                             "type_stubs"),
]

# Build fast lookup maps
_DIST_MODULE_MAP: Dict[str, List[str]] = {}
_DIST_MAPPING_STATUS: Dict[str, str] = {}
for _dist, _mods, _status in _DIST_TO_MODULES:
    _DIST_MODULE_MAP[_dist.lower()] = _mods
    _DIST_MAPPING_STATUS[_dist.lower()] = _status

# reverse: module → known distributions
_MODULE_DIST_MAP: Dict[str, List[str]] = {}
for _dist, _mods, _status in _DIST_TO_MODULES:
    for _mod in _mods:
        _MODULE_DIST_MAP.setdefault(_mod.lower(), []).append(_dist.lower())


# ---------------------------------------------------------------------------
# Categories that are always not_applicable regardless of import presence
# ---------------------------------------------------------------------------

NOT_APPLICABLE_CATEGORIES: Set[str] = {
    "cli_only",     # pure CLI tools — never imported
    "type_stubs",   # PEP 561 type stubs — never imported at runtime
}

# Distribution names that are always not_applicable even without explicit category
NOT_APPLICABLE_NAMES: Set[str] = {
    "pip", "setuptools", "wheel", "build", "flit", "hatchling",
    "flake8", "mypy", "black", "ruff", "isort", "pyflakes",
    "pycodestyle", "pylint", "pre-commit",
    "nose", "pytest", "coverage",
    "twine", "bumpversion", "bump2version",
}


class GhostClassification(str, Enum):
    USAGE_FOUND      = "usage_found"
    POSSIBLY_UNUSED  = "possibly_unused"
    USAGE_UNCERTAIN  = "usage_uncertain"
    NOT_APPLICABLE   = "not_applicable"


@dataclass
class GhostAnalysis:
    """Full ghost-detector result for one declared dependency."""
    package_name: str
    classification: GhostClassification
    mapping_status: str   # "direct", "ambiguous", "cli_only", "type_stubs", "unknown"
    observed_modules: List[str]  # imported module names matched to this dist
    evidence: List[EvidenceReference]
    explanation: str
    limitations: List[str] = field(default_factory=list)


class GhostDetector:
    """Classify declared dependencies by observed import evidence.

    Parameters
    ----------
    declarations:
        All dependency declarations extracted from manifests.
    imports:
        All AST-extracted imports from source and test files.
    """

    def __init__(
        self,
        declarations: List[DependencyDeclaration],
        imports: List[SourceImport],
    ) -> None:
        self._declarations = declarations
        self._imports = imports
        # Build a quick map: module.lower() → list[SourceImport]
        self._module_import_map: Dict[str, List[SourceImport]] = {}
        for imp in imports:
            key = imp.module.lower()
            self._module_import_map.setdefault(key, []).append(imp)

    def analyze(self) -> List[GhostAnalysis]:
        """Return one GhostAnalysis per unique declared distribution."""
        # Collapse duplicates (same package in multiple manifests)
        unique: Dict[str, List[DependencyDeclaration]] = {}
        for d in self._declarations:
            unique.setdefault(d.name.lower(), []).append(d)

        return [self._classify(name, decls) for name, decls in sorted(unique.items())]

    def _classify(self, name: str, decls: List[DependencyDeclaration]) -> GhostAnalysis:
        mapping_status = _DIST_MAPPING_STATUS.get(name, "unknown")
        candidate_modules = _DIST_MODULE_MAP.get(name, [name])

        # ── NOT_APPLICABLE fast path ─────────────────────────────────────────
        if mapping_status in NOT_APPLICABLE_CATEGORIES or name in NOT_APPLICABLE_NAMES:
            return GhostAnalysis(
                package_name=name,
                classification=GhostClassification.NOT_APPLICABLE,
                mapping_status=mapping_status,
                observed_modules=[],
                evidence=self._manifest_evidence(decls),
                explanation=(
                    f"'{name}' is classified as a build/test/lint tool or type-stub package "
                    f"that is never directly imported at runtime. Absence of import statements "
                    f"is expected and does not indicate an unused dependency."
                ),
                limitations=[
                    "Dynamic plugin discovery (e.g. pytest plugins) is not checked statically."
                ],
            )

        # ── Search for matching imports ──────────────────────────────────────
        found_imports: List[SourceImport] = []
        matched_modules: List[str] = []

        for mod in candidate_modules:
            hits = self._module_import_map.get(mod.lower(), [])
            if hits:
                found_imports.extend(hits)
                matched_modules.append(mod)

        # Also check if the dist name itself matches any import (name != module)
        if not found_imports:
            hits = self._module_import_map.get(name.lower(), [])
            if hits:
                found_imports.extend(hits)
                matched_modules.append(name)

        if found_imports:
            evidence = self._import_evidence(found_imports[:10]) + self._manifest_evidence(decls)
            is_dev_only = all(imp.is_test_file for imp in found_imports)
            is_guarded  = all(imp.is_try_except for imp in found_imports)

            qualifier = ""
            if is_dev_only:
                qualifier = " (all usages are in test files)"
            elif is_guarded:
                qualifier = " (all usages are in try/except — optional import)"

            return GhostAnalysis(
                package_name=name,
                classification=GhostClassification.USAGE_FOUND,
                mapping_status=mapping_status,
                observed_modules=list(set(matched_modules)),
                evidence=evidence,
                explanation=(
                    f"Import evidence found for '{name}' (matched modules: "
                    f"{', '.join(sorted(set(matched_modules)))}) across "
                    f"{len(found_imports)} import statement(s){qualifier}."
                ),
                limitations=["Dynamic imports via importlib are not detected by AST scan."],
            )

        # ── No imports found — determine why ────────────────────────────────
        limitations: List[str] = [
            "AST scan cannot detect dynamic imports (importlib.import_module, __import__).",
            "Entry points and plugin discovery mechanisms are not traced statically.",
            "Transitive dependencies may be imported by other packages, not directly.",
        ]

        # Is it dev-only declared?
        all_dev = all(d.is_dev for d in decls)
        if all_dev:
            return GhostAnalysis(
                package_name=name,
                classification=GhostClassification.USAGE_UNCERTAIN,
                mapping_status=mapping_status,
                observed_modules=[],
                evidence=self._manifest_evidence(decls),
                explanation=(
                    f"'{name}' is declared exclusively in dev/test dependency groups. "
                    f"No AST import was found, but dev tools (formatters, type stubs, "
                    f"test plugins) are often not directly imported."
                ),
                limitations=limitations,
            )

        # Is it name-import ambiguous?
        if mapping_status == "ambiguous":
            return GhostAnalysis(
                package_name=name,
                classification=GhostClassification.USAGE_UNCERTAIN,
                mapping_status=mapping_status,
                observed_modules=[],
                evidence=self._manifest_evidence(decls),
                explanation=(
                    f"'{name}' maps to multiple possible top-level module names "
                    f"({', '.join(candidate_modules)}). None of these module names "
                    f"were observed in AST imports. Mapping is ambiguous; manual "
                    f"confirmation required."
                ),
                limitations=limitations + [
                    f"Known candidate modules checked: {', '.join(candidate_modules)}. "
                    "Additional module names from this distribution are possible."
                ],
            )

        # Unknown mapping
        if mapping_status == "unknown":
            return GhostAnalysis(
                package_name=name,
                classification=GhostClassification.USAGE_UNCERTAIN,
                mapping_status=mapping_status,
                observed_modules=[],
                evidence=self._manifest_evidence(decls),
                explanation=(
                    f"'{name}' is not in the known distribution-to-module map. "
                    f"The import name was assumed to equal the distribution name, "
                    f"but this may be incorrect. No import statement was found for "
                    f"module '{name}'."
                ),
                limitations=limitations + [
                    "Distribution-to-module mapping is heuristic for unknown packages."
                ],
            )

        # Direct mapping, no imports: possibly unused
        return GhostAnalysis(
            package_name=name,
            classification=GhostClassification.POSSIBLY_UNUSED,
            mapping_status=mapping_status,
            observed_modules=[],
            evidence=self._manifest_evidence(decls),
            explanation=(
                f"'{name}' has a direct, well-known import-name mapping "
                f"('{', '.join(candidate_modules)}'), but no import of "
                f"'{', '.join(candidate_modules)}' was found in any scanned "
                f"source or test file. This dependency may be unused or rely "
                f"on dynamic import patterns not captured by static AST analysis."
            ),
            limitations=limitations,
        )

    # ── evidence builders ────────────────────────────────────────────────────

    @staticmethod
    def _manifest_evidence(decls: List[DependencyDeclaration]) -> List[EvidenceReference]:
        return [
            EvidenceReference(
                file_path=d.manifest_path,
                line_start=d.line_number,
                line_end=d.line_number,
                content_snippet=d.raw_declaration[:120],
                source_type="manifest",
            )
            for d in decls
        ]

    @staticmethod
    def _import_evidence(imps: List[SourceImport]) -> List[EvidenceReference]:
        return [
            EvidenceReference(
                file_path=imp.file_path,
                line_start=imp.line_number,
                line_end=imp.line_number,
                content_snippet=(
                    f"import {imp.module}"
                    if not imp.imported_names
                    else f"from {imp.module} import {', '.join(imp.imported_names[:5])}"
                )[:120],
                source_type="test_ast" if imp.is_test_file else "source_ast",
            )
            for imp in imps
        ]

    def to_findings(self, analyses: List[GhostAnalysis]) -> List[Finding]:
        """Convert ghost analyses to Finding objects (for capsule integration)."""
        findings: List[Finding] = []
        counter = 1
        for ga in analyses:
            if ga.classification in (
                GhostClassification.NOT_APPLICABLE,
                GhostClassification.USAGE_FOUND,
            ):
                continue
            sev = (
                FindingSeverity.HIGH
                if ga.classification == GhostClassification.POSSIBLY_UNUSED
                else FindingSeverity.LOW
            )
            status = (
                FindingStatus.INFERRED
                if ga.classification == GhostClassification.POSSIBLY_UNUSED
                else FindingStatus.OBSERVED
            )
            limitations_note = (
                "\nLimitations: " + " | ".join(ga.limitations)
                if ga.limitations else ""
            )
            findings.append(Finding(
                id=f"GHOST-{counter:03d}",
                category="ghost_dependency",
                title=f"[{ga.classification.value.upper()}] '{ga.package_name}': {ga.classification.value.replace('_',' ')}",
                explanation=ga.explanation + limitations_note,
                severity=sev,
                status=status,
                package_name=ga.package_name,
                evidence=ga.evidence,
                remediation_hint=(
                    f"Verify whether '{ga.package_name}' is used via dynamic imports, "
                    "plugin discovery, or as a transitive dependency before removing it."
                ),
            ))
            counter += 1
        return findings

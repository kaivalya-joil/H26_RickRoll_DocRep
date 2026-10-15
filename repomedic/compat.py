"""Dependency Compatibility Intelligence — local-only version constraint analysis.

Extracts version constraints from manifests and compares them against locally
available installed package metadata (importlib.metadata / pkg_resources).

Rules:
  - NEVER silently accesses the network.
  - NEVER builds a vulnerability database or assigns severity based on age alone.
  - Reports the provenance of every fact (declared vs. installed vs. inferred).
  - A dependency's presence alone is NOT evidence of incompatibility.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

try:
    from importlib.metadata import packages_distributions, version as pkg_version, PackageNotFoundError
except ImportError:
    # Python < 3.9 fallback
    try:
        from importlib_metadata import packages_distributions, version as pkg_version, PackageNotFoundError  # type: ignore
    except ImportError:
        packages_distributions = None  # type: ignore
        pkg_version = None              # type: ignore
        PackageNotFoundError = Exception  # type: ignore

from packaging.version import Version, InvalidVersion
from packaging.specifiers import SpecifierSet, InvalidSpecifier

from .models import (
    DependencyDeclaration,
    EvidenceReference,
    Finding,
    FindingSeverity,
    FindingStatus,
    RepositoryMetadata,
)


class CompatibilityStatus(str, Enum):
    COMPATIBLE             = "compatible"              # installed version satisfies declared constraint
    CONSTRAINT_VIOLATION   = "constraint_violation"    # installed version outside declared specifier
    MISSING_LOCALLY        = "missing_locally"         # installed version not detectable
    PYTHON_CONSTRAINT_FAIL = "python_constraint_fail"  # project Python requires doesn't match runtime
    SPECIFIER_MALFORMED    = "specifier_malformed"     # declared specifier cannot be parsed
    UNCHECKED              = "unchecked"               # no specifier declared; nothing to check


class EvidenceProvenance(str, Enum):
    DECLARED   = "declared"    # from manifest text
    INSTALLED  = "installed"   # from importlib.metadata on current interpreter
    INFERRED   = "inferred"    # derived from other facts


@dataclass
class VersionFact:
    """One version fact with its provenance."""
    value: str
    provenance: EvidenceProvenance
    source: str       # e.g. "requirements.txt:5", "importlib.metadata"


@dataclass
class CompatibilityResult:
    """Compatibility analysis for a single declared dependency."""
    package_name: str
    status: CompatibilityStatus
    declared_specifier: Optional[str]
    installed_version: Optional[str]
    facts: List[VersionFact] = field(default_factory=list)
    explanation: str = ""
    limitations: List[str] = field(default_factory=list)
    evidence: List[EvidenceReference] = field(default_factory=list)


class CompatibilityAnalyzer:
    """Analyse version compatibility using only local metadata.

    Parameters
    ----------
    metadata:
        Repository metadata (provides declared Python constraint).
    declarations:
        All dependency declarations from manifests.
    """

    def __init__(
        self,
        metadata: RepositoryMetadata,
        declarations: List[DependencyDeclaration],
    ) -> None:
        self._metadata = metadata
        self._declarations = declarations
        self._installed_cache: Dict[str, Optional[str]] = {}
        self._python_version = sys.version_info

    def analyze(self) -> List[CompatibilityResult]:
        """Return one CompatibilityResult per unique declared package."""
        results: List[CompatibilityResult] = []

        # Python version constraint first
        py_result = self._check_python_constraint()
        if py_result:
            results.append(py_result)

        # Per-dependency
        unique: Dict[str, List[DependencyDeclaration]] = {}
        for d in self._declarations:
            unique.setdefault(d.name.lower(), []).append(d)

        for name, decls in sorted(unique.items()):
            results.append(self._check_dependency(name, decls))

        return results

    def _check_python_constraint(self) -> Optional[CompatibilityResult]:
        declared = self._metadata.python_requires_declared
        if not declared:
            return None

        runtime_ver = f"{self._python_version.major}.{self._python_version.minor}.{self._python_version.micro}"
        facts = [
            VersionFact(declared,    EvidenceProvenance.DECLARED,  "pyproject.toml[project.requires-python]"),
            VersionFact(runtime_ver, EvidenceProvenance.INSTALLED, "sys.version_info"),
        ]

        try:
            spec = SpecifierSet(declared)
            compatible = Version(runtime_ver) in spec
        except (InvalidSpecifier, InvalidVersion) as exc:
            return CompatibilityResult(
                package_name="__python_runtime__",
                status=CompatibilityStatus.SPECIFIER_MALFORMED,
                declared_specifier=declared,
                installed_version=runtime_ver,
                facts=facts,
                explanation=f"Declared Python constraint '{declared}' could not be parsed: {exc}",
                limitations=["packaging library required for specifier parsing."],
            )

        status = CompatibilityStatus.COMPATIBLE if compatible else CompatibilityStatus.PYTHON_CONSTRAINT_FAIL
        explanation = (
            f"Runtime Python {runtime_ver} {'satisfies' if compatible else 'does NOT satisfy'} "
            f"declared constraint '{declared}'."
        )
        return CompatibilityResult(
            package_name="__python_runtime__",
            status=status,
            declared_specifier=declared,
            installed_version=runtime_ver,
            facts=facts,
            explanation=explanation,
            limitations=[
                "Only checks the currently active interpreter against the declared constraint.",
                "CI/CD may use a different Python version.",
            ],
        )

    def _check_dependency(self, name: str, decls: List[DependencyDeclaration]) -> CompatibilityResult:
        # Collect declared specifiers (may conflict across manifests)
        specifiers = list({d.specifier for d in decls if d.specifier})
        declared_specifier = specifiers[0] if len(specifiers) == 1 else (
            " | ".join(specifiers) if specifiers else None
        )

        evidence = [
            EvidenceReference(
                file_path=d.manifest_path,
                line_start=d.line_number,
                line_end=d.line_number,
                content_snippet=d.raw_declaration[:120],
                source_type="manifest",
            )
            for d in decls
        ]
        facts: List[VersionFact] = []
        for d in decls:
            if d.specifier:
                facts.append(VersionFact(
                    value=d.specifier,
                    provenance=EvidenceProvenance.DECLARED,
                    source=f"{d.manifest_path}:{d.line_number}",
                ))

        if not declared_specifier:
            installed = self._installed_version(name)
            if installed:
                facts.append(VersionFact(installed, EvidenceProvenance.INSTALLED, "importlib.metadata"))
            return CompatibilityResult(
                package_name=name,
                status=CompatibilityStatus.UNCHECKED,
                declared_specifier=None,
                installed_version=installed,
                facts=facts,
                explanation=(
                    f"'{name}' has no version constraint declared. "
                    + (f"Locally installed: {installed}." if installed else "Not found in local environment.")
                ),
                limitations=["No specifier → no compatibility check performed."],
                evidence=evidence,
            )

        # Try to parse the specifier
        try:
            spec = SpecifierSet(declared_specifier, prereleases=True)
        except InvalidSpecifier as exc:
            return CompatibilityResult(
                package_name=name,
                status=CompatibilityStatus.SPECIFIER_MALFORMED,
                declared_specifier=declared_specifier,
                installed_version=None,
                facts=facts,
                explanation=f"Version specifier '{declared_specifier}' is malformed: {exc}",
                limitations=["Malformed specifier prevents compatibility check."],
                evidence=evidence,
            )

        installed = self._installed_version(name)
        if installed is None:
            return CompatibilityResult(
                package_name=name,
                status=CompatibilityStatus.MISSING_LOCALLY,
                declared_specifier=declared_specifier,
                installed_version=None,
                facts=facts,
                explanation=(
                    f"'{name}' is declared with constraint '{declared_specifier}' but is not "
                    f"installed in the current Python environment (importlib.metadata lookup failed). "
                    f"Cannot verify compatibility without an installed version."
                ),
                limitations=[
                    "The package may be installed in a virtual environment not active for this scan.",
                    "Network lookup is explicitly disabled; PyPI is not queried.",
                ],
                evidence=evidence,
            )

        facts.append(VersionFact(installed, EvidenceProvenance.INSTALLED, "importlib.metadata"))
        evidence.append(EvidenceReference(
            file_path="__runtime__",
            line_start=None,
            line_end=None,
            content_snippet=f"{name}=={installed} (importlib.metadata)",
            source_type="runtime",
        ))

        try:
            compatible = Version(installed) in spec
        except InvalidVersion:
            return CompatibilityResult(
                package_name=name,
                status=CompatibilityStatus.SPECIFIER_MALFORMED,
                declared_specifier=declared_specifier,
                installed_version=installed,
                facts=facts,
                explanation=f"Installed version '{installed}' for '{name}' could not be parsed.",
                limitations=["Non-standard version string."],
                evidence=evidence,
            )

        status = CompatibilityStatus.COMPATIBLE if compatible else CompatibilityStatus.CONSTRAINT_VIOLATION
        explanation = (
            f"Locally installed '{name}=={installed}' "
            f"{'satisfies' if compatible else 'VIOLATES'} "
            f"declared constraint '{declared_specifier}'."
        )
        return CompatibilityResult(
            package_name=name,
            status=status,
            declared_specifier=declared_specifier,
            installed_version=installed,
            facts=facts,
            explanation=explanation,
            limitations=[
                "Only the locally installed version is checked.",
                "pip's solver behaviour (minimum vs latest) is not simulated.",
            ],
            evidence=evidence,
        )

    def _installed_version(self, name: str) -> Optional[str]:
        """Look up installed version via importlib.metadata. Returns None if not found."""
        if pkg_version is None:
            return None
        if name in self._installed_cache:
            return self._installed_cache[name]
        # Try exact name, then normalised
        for candidate in [name, name.replace("-", "_"), name.replace("_", "-")]:
            try:
                ver = pkg_version(candidate)
                self._installed_cache[name] = ver
                return ver
            except Exception:
                continue
        self._installed_cache[name] = None
        return None

    def to_findings(self, results: List[CompatibilityResult]) -> List[Finding]:
        """Emit Findings only for actionable compatibility concerns."""
        findings: List[Finding] = []
        counter = 1
        for r in results:
            if r.status in (CompatibilityStatus.COMPATIBLE, CompatibilityStatus.UNCHECKED):
                continue
            sev = {
                CompatibilityStatus.CONSTRAINT_VIOLATION:   FindingSeverity.HIGH,
                CompatibilityStatus.PYTHON_CONSTRAINT_FAIL: FindingSeverity.CRITICAL,
                CompatibilityStatus.SPECIFIER_MALFORMED:    FindingSeverity.MEDIUM,
                CompatibilityStatus.MISSING_LOCALLY:        FindingSeverity.LOW,
            }.get(r.status, FindingSeverity.INFO)

            limitations_text = (
                "\nLimitations: " + " | ".join(r.limitations) if r.limitations else ""
            )
            findings.append(Finding(
                id=f"COMPAT-{counter:03d}",
                category="compatibility",
                title=f"[{r.status.value.upper()}] '{r.package_name}': {r.explanation[:80]}",
                explanation=r.explanation + limitations_text,
                severity=sev,
                status=FindingStatus.OBSERVED if r.installed_version else FindingStatus.INFERRED,
                package_name=r.package_name,
                evidence=r.evidence,
                remediation_hint=(
                    f"Reconcile declared specifier '{r.declared_specifier}' with "
                    f"installed version '{r.installed_version}'."
                    if r.installed_version else
                    f"Install '{r.package_name}' in the active environment to verify compatibility."
                ),
            ))
            counter += 1
        return findings

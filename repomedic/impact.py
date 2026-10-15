"""Detailed dependency impact mapping with evidence attribution."""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Optional, Set
from pydantic import BaseModel, Field

from .models import BlastRadiusEntry, DependencyDeclaration, FindingSeverity, SourceImport
from .scanner import PACKAGE_TO_MODULE_MAP


class ImpactItem(BaseModel):
    item: str
    evidence_type: str  # "direct evidence" or "inferred"
    details: Optional[str] = None


class DependencyImpact(BaseModel):
    package_name: str
    importing_files: List[ImpactItem] = Field(default_factory=list)
    related_tests: List[ImpactItem] = Field(default_factory=list)
    declaring_manifests: List[ImpactItem] = Field(default_factory=list)
    affected_components: List[ImpactItem] = Field(default_factory=list)
    unclear_or_dynamic_refs: List[ImpactItem] = Field(default_factory=list)


class ImpactAnalyzer:
    """Calculates granular impact maps with explicit direct vs inferred evidence tags."""

    def __init__(
        self,
        declarations: List[DependencyDeclaration],
        imports: List[SourceImport],
    ):
        self.declarations = declarations
        self.imports = imports
        self._build_indexes()

    def _build_indexes(self):
        self.module_to_sources: Dict[str, Set[str]] = defaultdict(set)
        self.module_to_tests: Dict[str, Set[str]] = defaultdict(set)
        for imp in self.imports:
            mod = imp.module.lower()
            if imp.is_test_file:
                self.module_to_tests[mod].add(imp.file_path)
            else:
                self.module_to_sources[mod].add(imp.file_path)

    def analyze_dependency(self, pkg_name: str) -> DependencyImpact:
        canonical_mod = PACKAGE_TO_MODULE_MAP.get(pkg_name.lower(), pkg_name.lower())
        impact = DependencyImpact(package_name=pkg_name)

        # 1. Declaring manifests (direct evidence)
        for d in self.declarations:
            if d.name.lower() == pkg_name.lower():
                impact.declaring_manifests.append(ImpactItem(
                    item=f"{d.manifest_path}:{d.line_number or 1}",
                    evidence_type="direct evidence",
                    details=d.raw_declaration,
                ))

        # 2. Importing source files (direct evidence)
        direct_sources = self.module_to_sources.get(canonical_mod, set())
        for sf in sorted(direct_sources):
            impact.importing_files.append(ImpactItem(
                item=sf,
                evidence_type="direct evidence",
                details=f"AST import of '{canonical_mod}'",
            ))

        # 3. Direct tests (direct evidence)
        direct_tests = self.module_to_tests.get(canonical_mod, set())
        for tf in sorted(direct_tests):
            impact.related_tests.append(ImpactItem(
                item=tf,
                evidence_type="direct evidence",
                details=f"Direct test import of '{canonical_mod}'",
            ))

        # 4. Transitive / inferred tests & components (inferred)
        for sf in direct_sources:
            stem = sf.split("/")[-1].replace(".py", "")
            impact.affected_components.append(ImpactItem(
                item=stem,
                evidence_type="inferred",
                details=f"Component module backed by {sf}",
            ))
            for tf in self.module_to_tests.get(stem, set()):
                if tf not in direct_tests:
                    impact.related_tests.append(ImpactItem(
                        item=tf,
                        evidence_type="inferred",
                        details=f"Test imports dependent component '{stem}'",
                    ))

        # 5. Dynamic/unclear references
        impact.unclear_or_dynamic_refs.append(ImpactItem(
            item="Dynamic reflection & plugin entry points",
            evidence_type="inferred",
            details="importlib/pkg_resources dynamic references not visible via static AST.",
        ))

        return impact

    def calculate_blast_radius(self) -> List[BlastRadiusEntry]:
        """Backward-compatible summary blast radius entries."""
        entries: List[BlastRadiusEntry] = []
        unique_packages = {d.name for d in self.declarations}
        for pkg in sorted(unique_packages):
            res = self.analyze_dependency(pkg)
            src_files = [x.item for x in res.importing_files]
            test_files = [x.item for x in res.related_tests]
            risk = FindingSeverity.LOW if not src_files else (FindingSeverity.HIGH if len(src_files) > 2 else FindingSeverity.MEDIUM)
            entries.append(BlastRadiusEntry(
                dependency_name=pkg,
                importing_files=src_files,
                affected_tests=test_files,
                risk_level=risk,
                summary=f"{len(src_files)} direct source file(s), {len(test_files)} test suite(s).",
            ))
        return entries

"""Change Blast-Radius Map: maps dependencies to importing files and affected test suites."""

from collections import defaultdict
from typing import Dict, List, Set

from .models import (
    BlastRadiusEntry,
    DependencyDeclaration,
    FindingSeverity,
    SourceImport,
)
from .scanner import PACKAGE_TO_MODULE_MAP


class ImpactAnalyzer:
    """Calculates blast radius and impacted test suites for dependency changes."""

    def __init__(
        self,
        declarations: List[DependencyDeclaration],
        imports: List[SourceImport],
    ):
        self.declarations = declarations
        self.imports = imports
        self._build_dependency_graphs()

    def _build_dependency_graphs(self):
        # Map: module -> set of source files that import this module
        self.module_to_source_files: Dict[str, Set[str]] = defaultdict(set)
        # Map: module -> set of test files that import this module
        self.module_to_test_files: Dict[str, Set[str]] = defaultdict(set)
        # Map: file_path -> set of internal modules it imports
        self.internal_imports: Dict[str, Set[str]] = defaultdict(set)

        for imp in self.imports:
            mod = imp.module.lower()
            if imp.is_test_file:
                self.module_to_test_files[mod].add(imp.file_path)
            else:
                self.module_to_source_files[mod].add(imp.file_path)

    def calculate_blast_radius(self) -> List[BlastRadiusEntry]:
        """Compute blast radius for all declared dependencies."""
        entries: List[BlastRadiusEntry] = []
        unique_packages = {d.name for d in self.declarations}

        for pkg in sorted(unique_packages):
            canonical_mod = PACKAGE_TO_MODULE_MAP.get(pkg, pkg).lower()
            direct_sources = self.module_to_source_files.get(canonical_mod, set())
            direct_tests = self.module_to_test_files.get(canonical_mod, set())

            # Find transitive test impact: any test importing affected internal modules
            affected_tests = set(direct_tests)
            for src_file in direct_sources:
                # Infer internal module name, e.g. "linkwatch/config.py" -> "config" or "linkwatch"
                file_stem = src_file.split("/")[-1].replace(".py", "")
                for test_file in self.module_to_test_files.get(file_stem, set()):
                    affected_tests.add(test_file)
                for test_file in self.module_to_test_files.get("linkwatch", set()):
                    affected_tests.add(test_file)

            importing_files = sorted(list(direct_sources))
            affect_test_list = sorted(list(affected_tests))

            if not importing_files and not direct_tests:
                risk = FindingSeverity.LOW
                summary = f"Zero direct imports detected. Safely removable without impacting application code."
            elif len(importing_files) > 2 or len(affect_test_list) > 2:
                risk = FindingSeverity.HIGH
                summary = (
                    f"Directly used in {len(importing_files)} source modules and impacts {len(affect_test_list)} "
                    f"test files. Requires thorough regression testing."
                )
            else:
                risk = FindingSeverity.MEDIUM
                summary = (
                    f"Used in {len(importing_files)} source modules and impacts {len(affect_test_list)} test files."
                )

            entries.append(
                BlastRadiusEntry(
                    dependency_name=pkg,
                    importing_files=importing_files,
                    affected_tests=affect_test_list,
                    risk_level=risk,
                    summary=summary,
                )
            )
        return entries

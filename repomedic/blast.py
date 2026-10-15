"""Change Blast-Radius Map — deterministic dependency-to-files-to-tests graph.

Given a dependency name (and optionally a proposed replacement), this module:
1. Traces importing files from AST evidence.
2. Identifies candidate test files.
3. Lists configuration files referencing the package.
4. Records areas that cannot be traced statically.
5. Explicitly states what evidence is missing before compatibility can be claimed.

Graph edges are ONLY constructed from collected evidence.  The AI model is never
asked to invent graph edges.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from .models import (
    BlastRadiusEntry,
    DependencyDeclaration,
    EvidenceReference,
    Finding,
    FindingSeverity,
    FindingStatus,
    SourceImport,
)
from .inventory import ConfigEntry


@dataclass
class BlastRadiusNode:
    """A node in the blast-radius graph: a file (source, test, or config)."""
    relative_path: str
    node_type: str          # "source", "test", "config", "manifest"
    import_line: Optional[int] = None
    import_snippet: Optional[str] = None


@dataclass
class BlastRadiusGraph:
    """Deterministic graph from dependency → files → tests."""
    dependency_name: str
    proposed_replacement: Optional[str]

    # Graph edges (all from collected evidence only)
    importing_source_files: List[BlastRadiusNode] = field(default_factory=list)
    importing_test_files: List[BlastRadiusNode] = field(default_factory=list)
    referencing_config_files: List[BlastRadiusNode] = field(default_factory=list)
    manifest_declarations: List[BlastRadiusNode] = field(default_factory=list)
    transitive_test_files: List[BlastRadiusNode] = field(default_factory=list)

    # Opaque areas
    untraceable_areas: List[str] = field(default_factory=list)
    replacement_evidence_missing: List[str] = field(default_factory=list)

    @property
    def risk_level(self) -> FindingSeverity:
        total_affected = (
            len(self.importing_source_files)
            + len(self.importing_test_files)
            + len(self.transitive_test_files)
        )
        if total_affected == 0:
            return FindingSeverity.LOW
        if total_affected > 5:
            return FindingSeverity.HIGH
        return FindingSeverity.MEDIUM

    def to_blast_radius_entry(self) -> BlastRadiusEntry:
        src_paths = [n.relative_path for n in self.importing_source_files]
        test_paths = list({
            n.relative_path
            for n in self.importing_test_files + self.transitive_test_files
        })
        untraceable_note = ""
        if self.untraceable_areas:
            untraceable_note = " | Untraceable: " + "; ".join(self.untraceable_areas)

        summary = (
            f"Direct importers: {len(src_paths)} source file(s), "
            f"{len(test_paths)} test file(s). "
            f"Config refs: {len(self.referencing_config_files)}."
            + untraceable_note
        )
        return BlastRadiusEntry(
            dependency_name=self.dependency_name,
            importing_files=sorted(src_paths),
            affected_tests=sorted(test_paths),
            risk_level=self.risk_level,
            summary=summary,
        )


class BlastRadiusMapper:
    """Build deterministic dependency-to-files-to-tests graphs.

    Parameters
    ----------
    declarations:
        All dependency declarations from manifests.
    imports:
        All AST imports extracted from source and test files.
    config_files:
        Configuration files discovered by the inventory scanner.
    """

    def __init__(
        self,
        declarations: List[DependencyDeclaration],
        imports: List[SourceImport],
        config_files: Optional[List[ConfigEntry]] = None,
    ) -> None:
        self._declarations = declarations
        self._imports = imports
        self._config_files = config_files or []

        # Pre-build indexes
        self._source_import_map: Dict[str, List[SourceImport]] = defaultdict(list)
        self._test_import_map: Dict[str, List[SourceImport]] = defaultdict(list)
        for imp in imports:
            if imp.is_test_file:
                self._test_import_map[imp.module.lower()].append(imp)
            else:
                self._source_import_map[imp.module.lower()].append(imp)

        # file → set of imported top-level modules (for transitive test discovery)
        self._file_modules: Dict[str, Set[str]] = defaultdict(set)
        for imp in imports:
            self._file_modules[imp.file_path].add(imp.module.lower())

    def map_dependency(
        self,
        dep_name: str,
        proposed_replacement: Optional[str] = None,
    ) -> BlastRadiusGraph:
        """Build and return the blast-radius graph for *dep_name*."""
        graph = BlastRadiusGraph(
            dependency_name=dep_name,
            proposed_replacement=proposed_replacement,
        )

        # Resolve candidate module names from ghost module map (if available)
        try:
            from .ghost import _DIST_MODULE_MAP
            candidate_modules = _DIST_MODULE_MAP.get(dep_name.lower(), [dep_name.lower()])
        except ImportError:
            candidate_modules = [dep_name.lower()]

        # ── direct source importers ──────────────────────────────────────────
        for mod in candidate_modules:
            for imp in self._source_import_map.get(mod, []):
                graph.importing_source_files.append(BlastRadiusNode(
                    relative_path=imp.file_path,
                    node_type="source",
                    import_line=imp.line_number,
                    import_snippet=(
                        f"from {imp.module} import {', '.join(imp.imported_names[:4])}"
                        if imp.imported_names
                        else f"import {imp.module}"
                    )[:120],
                ))

        # ── direct test importers ────────────────────────────────────────────
        for mod in candidate_modules:
            for imp in self._test_import_map.get(mod, []):
                graph.importing_test_files.append(BlastRadiusNode(
                    relative_path=imp.file_path,
                    node_type="test",
                    import_line=imp.line_number,
                    import_snippet=(
                        f"from {imp.module} import {', '.join(imp.imported_names[:4])}"
                        if imp.imported_names
                        else f"import {imp.module}"
                    )[:120],
                ))

        # ── transitive test impact ───────────────────────────────────────────
        # Find test files that import any SOURCE file that in turn imports dep
        affected_source_paths = {n.relative_path for n in graph.importing_source_files}
        for test_file, modules in self._file_modules.items():
            # Check if this test file (identified by is_test_file flag) imports
            # a module corresponding to an affected source file
            is_already_direct = test_file in {n.relative_path for n in graph.importing_test_files}
            if is_already_direct:
                continue
            # Heuristic: test imports a module whose file stem matches an affected source
            for src_path in affected_source_paths:
                stem = src_path.split("/")[-1].replace(".py", "")
                if stem in modules:
                    graph.transitive_test_files.append(BlastRadiusNode(
                        relative_path=test_file,
                        node_type="test",
                        import_snippet=f"imports module '{stem}' (source using {dep_name})",
                    ))
                    break

        # ── manifest declarations ────────────────────────────────────────────
        for decl in self._declarations:
            if decl.name.lower() == dep_name.lower():
                graph.manifest_declarations.append(BlastRadiusNode(
                    relative_path=decl.manifest_path,
                    node_type="manifest",
                    import_line=decl.line_number,
                    import_snippet=decl.raw_declaration[:120],
                ))

        # ── config file references ───────────────────────────────────────────
        for cfg in self._config_files:
            # Config files were read as bytes; we don't have their text here.
            # Reference them by name pattern (Makefile, tox.ini) without text search.
            if cfg.config_type in ("makefile", "tox", "ci_github", "ci_gitlab"):
                graph.referencing_config_files.append(BlastRadiusNode(
                    relative_path=cfg.relative_path,
                    node_type="config",
                    import_snippet=f"[{cfg.config_type}] — text search not performed (binary content)",
                ))

        # ── untraceable areas ────────────────────────────────────────────────
        graph.untraceable_areas = [
            "Dynamic imports via importlib.import_module() are not traced.",
            "Entry points declared in pyproject.toml [project.entry-points] are not resolved.",
            "C extension modules and compiled code are not inspected.",
            "Conditional imports under platform checks (sys.platform) may not be reached.",
        ]

        # ── replacement evidence gaps ────────────────────────────────────────
        if proposed_replacement:
            graph.replacement_evidence_missing = [
                f"API surface of '{proposed_replacement}' has not been compared to '{dep_name}'.",
                "No test suite run has been performed with the replacement installed.",
                "Import name of the replacement was not verified against this scan.",
                "Transitive dependency compatibility of the replacement is unknown.",
            ]

        return graph

    def map_all(self) -> List[BlastRadiusGraph]:
        """Build graphs for every unique declared dependency."""
        unique_deps = sorted({d.name.lower() for d in self._declarations})
        return [self.map_dependency(dep) for dep in unique_deps]

    def to_blast_radius_entries(self, graphs: Optional[List[BlastRadiusGraph]] = None) -> List[BlastRadiusEntry]:
        """Convert graphs to legacy BlastRadiusEntry objects for capsule compatibility."""
        if graphs is None:
            graphs = self.map_all()
        return [g.to_blast_radius_entry() for g in graphs]

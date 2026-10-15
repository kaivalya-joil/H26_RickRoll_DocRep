"""Intelligence Engine — the central orchestrator for Prompt 2.

Wires together:
  RepositoryInventoryScanner  (inventory.py)
  RepositoryScanner           (scanner.py)   — manifest + AST parsing
  GhostDetector               (ghost.py)
  CompatibilityAnalyzer       (compat.py)
  BlastRadiusMapper           (blast.py)
  MigrationTripwire           (tripwire.py)
  EvidenceLedgerBuilder       (ledger.py)
  CapsuleGenerator            (capsule.py)

Produces a complete, evidence-backed DependencyExitCapsule and EvidenceLedger.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from .blast import BlastRadiusMapper
from .capsule import CapsuleGenerator
from .compat import CompatibilityAnalyzer
from .ghost import GhostDetector
from .inventory import RepositoryInventoryScanner, RepositoryInventory
from .ledger import EvidenceLedgerBuilder, EvidenceLedger, StalenessReport
from .models import (
    AuditFingerprint,
    BlastRadiusEntry,
    DependencyDeclaration,
    DependencyExitCapsule,
    Finding,
    RepositoryMetadata,
    SourceImport,
)
from .scanner import RepositoryScanner
from .tripwire import MigrationTripwire


@dataclass
class IntelligenceReport:
    """Complete output of the intelligence engine for one repository scan."""
    capsule: DependencyExitCapsule
    inventory: RepositoryInventory
    ledger: EvidenceLedger
    staleness_reports: List[StalenessReport] = field(default_factory=list)
    scan_command: str = ""

    # Hermes-ready summary (see hermes_interface property below)
    @property
    def hermes_interface(self) -> Dict:
        """Minimal structured contract for the Hermes AI layer to consume."""
        return {
            "schema_version": "2.0",
            "repo": self.capsule.metadata.repo_name,
            "audit_hash": self.ledger.composite_hash,
            "generated_at": self.capsule.generated_at,
            "findings": [
                {
                    "id": f.id,
                    "category": f.category,
                    "severity": f.severity.value,
                    "status": f.status.value,
                    "package": f.package_name,
                    "title": f.title,
                    "evidence_count": len(f.evidence),
                    "has_remediation": bool(f.remediation_hint),
                }
                for f in self.capsule.findings
            ],
            "blast_radii": [
                {
                    "package": b.dependency_name,
                    "risk": b.risk_level.value,
                    "source_file_count": len(b.importing_files),
                    "test_file_count": len(b.affected_tests),
                }
                for b in self.capsule.blast_radii
            ],
            "inventory_summary": {
                "manifests": self.inventory.supported_manifest_paths,
                "source_files": len(self.inventory.non_test_files),
                "test_files": len(self.inventory.test_files),
                "skipped": len(self.inventory.skipped),
                "unsupported_manifests": self.inventory.unsupported_manifests,
                "file_count_capped": self.inventory.file_count_capped,
            },
            "staleness": [
                {
                    "file": s.file_path,
                    "previous_sha256": s.previous_sha256,
                    "current_sha256": s.current_sha256,
                    "affected_findings": s.affected_finding_ids,
                }
                for s in self.staleness_reports
            ],
            "limitations": [
                "AST scan cannot detect dynamic imports (importlib.import_module).",
                "Network is never queried; compatibility uses local metadata only.",
                "Config-file text search was not performed (binary content not available post-inventory).",
                "Entry point and plugin discovery are not traced statically.",
            ],
        }


class IntelligenceEngine:
    """Orchestrates the full deterministic repository intelligence scan.

    Parameters
    ----------
    repo_path:
        Explicit path to the target repository root.
    previous_hashes:
        Optional dict of {rel_path: sha256} from a prior scan, used for
        staleness detection.
    """

    def __init__(
        self,
        repo_path: str | Path,
        previous_hashes: Optional[Dict[str, str]] = None,
    ) -> None:
        self._repo_path = Path(repo_path).resolve()
        self._previous_hashes = previous_hashes or {}

    def run(self, scan_command: str = "") -> IntelligenceReport:
        """Execute the full intelligence scan and return a complete report."""

        # ── Step 1: Inventory ────────────────────────────────────────────────
        inv_scanner = RepositoryInventoryScanner(self._repo_path)
        inventory = inv_scanner.scan()

        # ── Step 2: Manifest + AST parsing (existing scanner) ───────────────
        repo_scanner = RepositoryScanner(self._repo_path)
        metadata, declarations, imports, manifest_hashes, source_hashes = repo_scanner.scan()

        # ── Step 3: Build evidence ledger ────────────────────────────────────
        all_hashes = {**manifest_hashes, **source_hashes}
        ledger_builder = EvidenceLedgerBuilder(
            repo_root=self._repo_path,
            file_hashes=all_hashes,
        )

        # ── Step 4: Ghost detection ──────────────────────────────────────────
        ghost_detector = GhostDetector(declarations, imports)
        ghost_analyses = ghost_detector.analyze()
        ghost_findings = ghost_detector.to_findings(ghost_analyses)

        # ── Step 5: Compatibility analysis ──────────────────────────────────
        compat_analyzer = CompatibilityAnalyzer(metadata, declarations)
        compat_results = compat_analyzer.analyze()
        compat_findings = compat_analyzer.to_findings(compat_results)

        # ── Step 6: Migration tripwires ──────────────────────────────────────
        # Build source text map for deep API search
        source_texts = self._build_source_texts(source_hashes)
        tripwire = MigrationTripwire(declarations, imports, source_texts)
        tw_observations = tripwire.analyze_all_known()
        tw_findings = tripwire.to_findings(tw_observations)

        # ── Step 7: Blast-radius map ─────────────────────────────────────────
        blast_mapper = BlastRadiusMapper(
            declarations, imports, inventory.config_files
        )
        blast_graphs = blast_mapper.map_all()
        blast_entries = blast_mapper.to_blast_radius_entries(blast_graphs)

        # ── Step 8: Combine all findings ────────────────────────────────────
        from .analyzer import DependencyAnalyzer
        dep_analyzer = DependencyAnalyzer(metadata, declarations, imports)
        legacy_findings = dep_analyzer.analyze()
        conflict_and_private_findings = [
            f for f in legacy_findings if f.category in ("manifest_conflict", "private_api")
        ]

        all_findings: List[Finding] = (
            ghost_findings + compat_findings + tw_findings + conflict_and_private_findings
        )

        # Register all finding evidence into ledger
        for finding in all_findings:
            ledger_builder.record_finding_evidence(finding, scanner_rule_id=finding.id)

        # ── Step 9: Staleness detection ──────────────────────────────────────
        finding_file_map: Dict[str, List[str]] = {}
        for f in all_findings:
            for ev in f.evidence:
                finding_file_map.setdefault(ev.file_path, []).append(f.id)

        staleness_reports = ledger_builder.check_staleness(
            self._previous_hashes, finding_file_map
        )

        # ── Step 10: Capsule assembly ────────────────────────────────────────
        ledger = ledger_builder.build()
        fingerprint = ledger.to_audit_fingerprint()

        capsule_gen = CapsuleGenerator(
            metadata=metadata,
            declarations=declarations,
            imports=imports,
            findings=all_findings,
            recommendations=[],   # Hermes layer fills this
            verifications=[],     # verifier fills this separately
            blast_radii=blast_entries,
            manifest_hashes=manifest_hashes,
            source_hashes=source_hashes,
        )
        capsule = capsule_gen.build_capsule()

        return IntelligenceReport(
            capsule=capsule,
            inventory=inventory,
            ledger=ledger,
            staleness_reports=staleness_reports,
            scan_command=scan_command,
        )

    def _build_source_texts(self, source_hashes: Dict[str, str]) -> Dict[str, str]:
        """Read source files for deep text-based API search (tripwire module)."""
        texts: Dict[str, str] = {}
        for rel_path in source_hashes:
            abs_path = self._repo_path / rel_path
            try:
                texts[rel_path] = abs_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass
        return texts

    # ── Convenience export methods ───────────────────────────────────────────

    def export_full(
        self,
        output_dir: str | Path,
        scan_command: str = "",
    ) -> Dict[str, Path]:
        """Run scan and export all artefacts to *output_dir*."""
        report = self.run(scan_command=scan_command)
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        paths: Dict[str, Path] = {}

        # Capsule JSON
        capsule_path = out / "capsule.json"
        capsule_path.write_text(
            json.dumps(report.capsule.model_dump(), indent=2),
            encoding="utf-8",
        )
        paths["capsule_json"] = capsule_path

        # Evidence ledger JSON
        ledger_builder = EvidenceLedgerBuilder(
            repo_root=self._repo_path,
            file_hashes=report.ledger.file_hashes,
        )
        ledger_path = ledger_builder.export_json(out / "evidence_ledger.json")
        paths["ledger_json"] = ledger_path

        # Hermes interface JSON
        hermes_path = out / "hermes_interface.json"
        hermes_path.write_text(
            json.dumps(report.hermes_interface, indent=2),
            encoding="utf-8",
        )
        paths["hermes_json"] = hermes_path

        return paths, report

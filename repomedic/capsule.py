"""Dependency Exit Capsule generator: produces reproducible JSON and Markdown audit reports."""

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from .models import (
    AIRecommendation,
    AuditFingerprint,
    BlastRadiusEntry,
    DependencyDeclaration,
    DependencyExitCapsule,
    Finding,
    FindingStatus,
    RepositoryMetadata,
    SourceImport,
    VerificationResult,
)


class CapsuleGenerator:
    """Generates portable, proof-carrying Dependency Exit Capsules."""

    def __init__(
        self,
        metadata: RepositoryMetadata,
        declarations: List[DependencyDeclaration],
        imports: List[SourceImport],
        findings: List[Finding],
        recommendations: List[AIRecommendation],
        verifications: List[VerificationResult],
        blast_radii: List[BlastRadiusEntry],
        manifest_hashes: Dict[str, str],
        source_hashes: Dict[str, str],
    ):
        self.metadata = metadata
        self.declarations = declarations
        self.imports = imports
        self.findings = findings
        self.recommendations = recommendations
        self.verifications = verifications
        self.blast_radii = blast_radii
        self.manifest_hashes = manifest_hashes
        self.source_hashes = source_hashes

    def build_capsule(self) -> DependencyExitCapsule:
        """Construct the complete structured capsule with cryptographic fingerprint."""
        now_iso = datetime.now(timezone.utc).isoformat()
        
        # Calculate composite SHA-256 fingerprint
        hasher = hashlib.sha256()
        for k in sorted(self.manifest_hashes.keys()):
            hasher.update(f"{k}:{self.manifest_hashes[k]}".encode("utf-8"))
        for k in sorted(self.source_hashes.keys()):
            hasher.update(f"{k}:{self.source_hashes[k]}".encode("utf-8"))
        composite_hash = hasher.hexdigest()

        fingerprint = AuditFingerprint(
            tool_name="RepoMedic",
            tool_version="0.1.0",
            python_runtime=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            timestamp=now_iso,
            manifest_hashes=self.manifest_hashes,
            source_hashes=self.source_hashes,
            composite_hash=composite_hash,
        )

        # Calculate verification debt: recommendations without passing verification
        verified_targets = {v.target for v in self.verifications if v.status == FindingStatus.VERIFIED}
        debt = []
        for rec in self.recommendations:
            if rec.package_name not in str(verified_targets):
                debt.append(f"{rec.id}: {rec.title} (No isolated test suite passed verifying this change)")

        return DependencyExitCapsule(
            version="1.0.0",
            metadata=self.metadata,
            fingerprint=fingerprint,
            declarations=self.declarations,
            imports=self.imports,
            findings=self.findings,
            recommendations=self.recommendations,
            verifications=self.verifications,
            blast_radii=self.blast_radii,
            verification_debt=debt,
            generated_at=now_iso,
        )

    def export_json(self, output_path: Path | str) -> Path:
        """Export capsule as structured, machine-readable JSON."""
        capsule = self.build_capsule()
        out_p = Path(output_path).resolve()
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(capsule.model_dump(), f, indent=2)
        return out_p

    def export_markdown(self, output_path: Path | str) -> Path:
        """Export capsule as a comprehensive human-readable Markdown report."""
        capsule = self.build_capsule()
        out_p = Path(output_path).resolve()
        out_p.parent.mkdir(parents=True, exist_ok=True)

        md = self._render_markdown(capsule)
        out_p.write_text(md, encoding="utf-8")
        return out_p

    def _render_markdown(self, c: DependencyExitCapsule) -> str:
        lines: List[str] = []
        lines.append(f"# RepoMedic Dependency Exit Capsule")
        lines.append(f"**Target Repository:** `{c.metadata.repo_name}`  ")
        lines.append(f"**Generated:** `{c.generated_at}`  ")
        lines.append(f"**Audit Fingerprint (SHA-256):** `{c.fingerprint.composite_hash}`  ")
        lines.append(f"**Active Python Runtime:** `{c.fingerprint.python_runtime}`  ")
        lines.append(f"**Declared Python Constraint:** `{c.metadata.python_requires_declared or 'Unspecified'}`  ")
        lines.append("")
        lines.append("---")
        lines.append("")

        # 1. Executive Summary
        lines.append("## 1. Executive Summary")
        lines.append(f"- **Manifests Scanned:** {len(c.metadata.manifests_found)} ({', '.join(c.metadata.manifests_found)})")
        lines.append(f"- **Declared Dependencies:** {len(c.declarations)} across manifests")
        lines.append(f"- **Observed AST Imports:** {len(c.imports)} across {c.metadata.source_files_count} source and {c.metadata.test_files_count} test files")
        lines.append(f"- **Total Resilience Findings:** {len(c.findings)}")
        lines.append(f"- **AI Recommendations:** {len(c.recommendations)}")
        lines.append(f"- **Verification Debt Items:** {len(c.verification_debt)}")
        lines.append("")

        # 2. Findings Ledger
        lines.append("## 2. Deterministic Findings Ledger")
        lines.append("| ID | Category | Severity | Status | Package | Summary | Evidence |")
        lines.append("|---|---|---|---|---|---|---|")
        for f in c.findings:
            ev_str = "<br>".join(
                f"`{ev.file_path}:{ev.line_start or 1}` ({ev.source_type})" for ev in f.evidence[:3]
            )
            lines.append(
                f"| **{f.id}** | `{f.category}` | `{f.severity.value.upper()}` | `{f.status.value}` | `{f.package_name or 'N/A'}` | {f.title} | {ev_str} |"
            )
        lines.append("")

        # Detailed Findings
        for f in c.findings:
            lines.append(f"### Finding {f.id}: {f.title}")
            lines.append(f"- **Category:** `{f.category}`")
            lines.append(f"- **Severity:** `{f.severity.value.upper()}` | **Status:** `{f.status.value}`")
            lines.append(f"- **Explanation:** {f.explanation}")
            if f.remediation_hint:
                lines.append(f"- **Remediation Hint:** {f.remediation_hint}")
            lines.append("- **Concrete Evidence:**")
            for ev in f.evidence:
                lines.append(f"  - `{ev.file_path}:{ev.line_start}` ({ev.source_type}): `{ev.content_snippet}`")
            lines.append("")

        # 3. Change Blast-Radius Map
        lines.append("## 3. Change Blast-Radius Map")
        lines.append("| Package | Risk Level | Importing Modules | Impacted Test Suites | Assessment |")
        lines.append("|---|---|---|---|---|")
        for br in c.blast_radii:
            src_str = ", ".join(f"`{s}`" for s in br.importing_files) or "_None (Ghost)_"
            tst_str = ", ".join(f"`{t}`" for t in br.affected_tests) or "_None_"
            lines.append(
                f"| **{br.dependency_name}** | `{br.risk_level.value.upper()}` | {src_str} | {tst_str} | {br.summary} |"
            )
        lines.append("")

        # 4. AI & Resilience Recommendations
        lines.append("## 4. Maintenance Recommendations")
        lines.append("| ID | Target Package | Action | Suggested Replacement | Source | Status |")
        lines.append("|---|---|---|---|---|---|")
        for r in c.recommendations:
            rep = f"`{r.target_replacement}`" if r.target_replacement else "N/A"
            lines.append(
                f"| **{r.id}** | `{r.package_name}` | `{r.suggested_action.upper()}` | {rep} | `{r.source}` | `{r.status.value}` |"
            )
        lines.append("")

        for r in c.recommendations:
            lines.append(f"#### Recommendation {r.id}: {r.title}")
            lines.append(f"- **Action:** `{r.suggested_action}` -> `{r.target_replacement or 'N/A'}`")
            lines.append(f"- **Provenance:** `{r.source}` (confidence: {r.confidence:.2f})")
            lines.append(f"- **Rationale:** {r.rationale}")
            lines.append("")

        # 5. Executed Verification & Evidence Capture
        lines.append("## 5. Executed Verification Results")
        if not c.verifications:
            lines.append("_No verification commands executed._\n")
        else:
            lines.append("| Check ID | Target | Status | Exit Code | Duration | Sandbox |")
            lines.append("|---|---|---|---|---|---|")
            for v in c.verifications:
                code_str = str(v.exit_code) if v.exit_code is not None else "BLOCKED"
                lines.append(
                    f"| **{v.id}** | {v.target} | `{v.status.value.upper()}` | `{code_str}` | {v.duration_ms}ms | {v.sandbox_used} |"
                )
            lines.append("")
            for v in c.verifications:
                lines.append(f"#### Verification {v.id}: {v.target}")
                lines.append(f"- **Command:** `{' '.join(v.command)}`")
                lines.append(f"- **Status:** `{v.status.value}` | **Exit Code:** `{v.exit_code}` | **Duration:** {v.duration_ms}ms")
                if v.notes:
                    lines.append(f"- **Notes:** {v.notes}")
                if v.stderr:
                    lines.append("```text")
                    lines.append(v.stderr.strip()[:1000])
                    lines.append("```")
                lines.append("")

        # 6. Verification Debt & Open Questions
        lines.append("## 6. Verification Debt & Limitations")
        if not c.verification_debt:
            lines.append("No verification debt remaining. All recommendations verified.\n")
        else:
            for item in c.verification_debt:
                lines.append(f"- [ ] **Verification Debt**: {item}")
            lines.append("")

        # 7. Audit Fingerprint Ledger
        lines.append("## 7. Audit Fingerprint Ledger")
        lines.append(f"- **Composite Audit Hash:** `{c.fingerprint.composite_hash}`")
        lines.append("- **Manifest Hashes (SHA-256):**")
        for k, v in sorted(c.fingerprint.manifest_hashes.items()):
            lines.append(f"  - `{k}`: `{v}`")
        lines.append("- **Source File Hashes (SHA-256):**")
        for k, v in sorted(c.fingerprint.source_hashes.items()):
            lines.append(f"  - `{k}`: `{v}`")
        lines.append("")

        return "\n".join(lines)

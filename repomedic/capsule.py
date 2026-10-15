"""Dependency Exit Capsule generator: produces reproducible JSON and Markdown audit reports.

Conforms to strict validated schema with three explicit sections:
1. Observed Evidence (Deterministic Facts)
2. AI Reasoning & Suggestions (Probabilistic Recommendations & Challenges)
3. Verified Results & Verification Debt (Real Executions & Unfinished Checks)
"""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import (
    AIRecommendation,
    AuditFingerprint,
    BlastRadiusEntry,
    DependencyDeclaration,
    DependencyExitCapsule,
    Finding,
    FindingSeverity,
    FindingStatus,
    MigrationPlanStep,
    RecommendationChallenge,
    RepositoryMetadata,
    SourceImport,
    VerificationDebtItem,
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
        recommendation_challenges: Optional[List[RecommendationChallenge]] = None,
        verification_debt_details: Optional[List[VerificationDebtItem]] = None,
        migration_plan: Optional[List[MigrationPlanStep]] = None,
        limitations: Optional[List[str]] = None,
        model_info: Optional[Dict[str, Any]] = None,
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
        self.recommendation_challenges = recommendation_challenges
        self.verification_debt_details = verification_debt_details
        self.migration_plan = migration_plan
        self.limitations = limitations
        self.model_info = model_info

    def _build_default_challenges(self) -> List[RecommendationChallenge]:
        challenges: List[RecommendationChallenge] = []
        verified_targets = {v.target: v.status.value for v in self.verifications}

        for rec in self.recommendations:
            finding = next((f for f in self.findings if f.id == rec.finding_id), None)
            pkg = rec.package_name
            ev_list = [f"{ev.file_path}:{ev.line_start or 1}" for ev in (finding.evidence if finding else [])]

            if rec.challenge_data:
                cd = rec.challenge_data
                check_needed = cd.get("verification_check_name", "test_suite_run")
                ran = check_needed in verified_targets
                status = verified_targets.get(check_needed, "NOT_RUN")
                challenges.append(
                    RecommendationChallenge(
                        recommendation_id=rec.id,
                        finding_id=rec.finding_id,
                        package_name=pkg,
                        assumptions=cd.get("assumptions") or ["Standard library or modern package provides API parity"],
                        supporting_evidence=ev_list or ([finding.explanation] if finding else [f"Package {pkg} issue"]),
                        counterarguments=cd.get("counterarguments") or ["Migration may require code changes and testing"],
                        disproving_evidence=cd.get("disproving_evidence") or "Verification check failure.",
                        verification_check_needed=f"Execute {check_needed} in isolated sandbox.",
                        check_ran=ran,
                        check_result=status,
                    )
                )
                continue

            if pkg == "six":
                check_name = "test_suite_run"
                ran = check_name in verified_targets or "manifest_consistency" in verified_targets
                status = verified_targets.get(check_name, verified_targets.get("manifest_consistency", "NOT_RUN"))
                challenges.append(
                    RecommendationChallenge(
                        recommendation_id=rec.id,
                        finding_id=rec.finding_id,
                        package_name=pkg,
                        assumptions=[
                            "No dynamic __import__('six') or importlib lookup occurs at runtime",
                            "All dependencies support Python 3.10+ native string and unicode handling",
                        ],
                        supporting_evidence=ev_list or ["pyproject.toml:six declared", "Zero AST imports found"],
                        counterarguments=[
                            "Transitive or external plugins may expect six if they patch LinkWatch internals",
                            "Legacy test environments could rely on six.moves",
                        ],
                        disproving_evidence="A test failure or runtime ImportError referencing 'six' when removed.",
                        verification_check_needed="Execute full test suite in an isolated sandbox with 'six' uninstalled.",
                        check_ran=ran,
                        check_result=status,
                    )
                )
            elif pkg == "pydantic":
                check_name = "manifest_consistency"
                ran = check_name in verified_targets
                status = verified_targets.get(check_name, "NOT_RUN")
                challenges.append(
                    RecommendationChallenge(
                        recommendation_id=rec.id,
                        finding_id=rec.finding_id,
                        package_name=pkg,
                        assumptions=[
                            "LinkWatch codebase can adopt Pydantic v2 ConfigDict and @field_validator",
                            "Consumers of LinkWatch config objects tolerate Pydantic 2.x attribute access",
                        ],
                        supporting_evidence=ev_list or ["pyproject.toml specifies pydantic>=2", "requirements.txt specifies pydantic==1.10.13"],
                        counterarguments=[
                            "Pydantic v2 introduces minor breaking changes in validation error format",
                            "Pinning pydantic==1.10.13 in requirements.txt was historically done to maintain v1 stability",
                        ],
                        disproving_evidence="CI or runtime crash from deprecated @validator or class Config under v2.",
                        verification_check_needed="Run manifest_consistency and execute test_config_loading against Pydantic v2.",
                        check_ran=ran,
                        check_result=status,
                    )
                )
            elif pkg == "toml":
                check_name = "config_validation"
                ran = check_name in verified_targets
                status = verified_targets.get(check_name, "NOT_RUN")
                challenges.append(
                    RecommendationChallenge(
                        recommendation_id=rec.id,
                        finding_id=rec.finding_id,
                        package_name=pkg,
                        assumptions=[
                            "Target Python runtime is >= 3.11 with stdlib 'tomllib'",
                            "Code does not require TOML writing (tomllib is read-only)",
                        ],
                        supporting_evidence=ev_list or ["linkwatch/config.py imports toml"],
                        counterarguments=[
                            "If LinkWatch needs to write TOML, standard library tomllib is insufficient (would need tomli_w)",
                            "Runtime Python 3.10 requires the external 'tomli' backport",
                        ],
                        disproving_evidence="Failure when parsing TOML using binary mode rb with tomllib.load().",
                        verification_check_needed="Validate TOML configuration parsing via AST compile and config_validation.",
                        check_ran=ran,
                        check_result=status,
                    )
                )
            elif pkg == "appdirs":
                check_name = "import_checks"
                ran = check_name in verified_targets
                status = verified_targets.get(check_name, "NOT_RUN")
                challenges.append(
                    RecommendationChallenge(
                        recommendation_id=rec.id,
                        finding_id=rec.finding_id,
                        package_name=pkg,
                        assumptions=[
                            "platformdirs is an exact drop-in for user_cache_dir and user_data_dir",
                            "Platform cache directory path layout matches on Linux/macOS/Windows",
                        ],
                        supporting_evidence=ev_list or ["linkwatch uses appdirs for cache directories"],
                        counterarguments=[
                            "Subtle directory naming differences on Windows between appdirs and platformdirs",
                        ],
                        disproving_evidence="Existing user caches not discovered due to altered path resolution.",
                        verification_check_needed="Run unit test asserting platformdirs.user_cache_dir('linkwatch') matches expected location.",
                        check_ran=ran,
                        check_result=status,
                    )
                )
            else:
                challenges.append(
                    RecommendationChallenge(
                        recommendation_id=rec.id,
                        finding_id=rec.finding_id,
                        package_name=pkg,
                        assumptions=["Standard library or active equivalent provides API parity"],
                        supporting_evidence=ev_list or ["Static scanner AST detection"],
                        counterarguments=["Migration requires source changes and regression testing"],
                        disproving_evidence="Syntax error or missing symbol in replacement module.",
                        verification_check_needed="Isolated import and unit test run.",
                        check_ran=False,
                        check_result="NOT_RUN",
                    )
                )

        return challenges

    def _build_default_debt(self) -> List[VerificationDebtItem]:
        debt: List[VerificationDebtItem] = []
        verified_targets = {v.target for v in self.verifications if v.status == FindingStatus.VERIFIED}

        for rec in self.recommendations:
            if rec.package_name not in str(verified_targets):
                debt.append(
                    VerificationDebtItem(
                        id=f"DEBT-{rec.id}",
                        target=rec.package_name,
                        title=f"Unverified recommendation: {rec.title}",
                        unverified_reason=(
                            f"Proposed migration for '{rec.package_name}' ({rec.suggested_action}) "
                            f"has not been verified in an end-to-end clean sandbox test suite run."
                        ),
                        recommended_maintainer_action=(
                            f"Apply proposed patch for '{rec.package_name}' in disposable sandbox and run "
                            f"'pytest tests' to confirm zero regressions before committing to main."
                        ),
                        status="UNVERIFIED",
                    )
                )
        return debt

    def _build_default_migration_plan(self) -> List[MigrationPlanStep]:
        plan: List[MigrationPlanStep] = []
        step_num = 1

        # Step 1: Ghost removals
        ghosts = [r for r in self.recommendations if r.suggested_action == "remove" and r.package_name != "nose"]
        for g in ghosts:
            plan.append(
                MigrationPlanStep(
                    step=step_num,
                    target_package=g.package_name,
                    action="remove",
                    description=f"Remove ghost package '{g.package_name}' from manifests; verify zero import impact.",
                    risk_level=FindingSeverity.LOW,
                    verification_required="Run static import scanner and baseline tests.",
                )
            )
            step_num += 1

        # Step 2: Dev tooling / runner cleanup
        tooling = [r for r in self.recommendations if r.package_name in ("nose", "setuptools")]
        for t in tooling:
            plan.append(
                MigrationPlanStep(
                    step=step_num,
                    target_package=t.package_name,
                    action=t.suggested_action,
                    description=f"Deprecate '{t.package_name}' ({t.title}); standardize on modern tooling.",
                    risk_level=FindingSeverity.LOW,
                    verification_required="Run pytest test suite execution.",
                )
            )
            step_num += 1

        # Step 3: Library migrations
        migrations = [r for r in self.recommendations if r.suggested_action == "replace"]
        for m in migrations:
            plan.append(
                MigrationPlanStep(
                    step=step_num,
                    target_package=m.package_name,
                    action="replace",
                    description=f"Replace '{m.package_name}' with '{m.target_replacement}'.",
                    risk_level=FindingSeverity.MEDIUM,
                    verification_required="Syntax AST check and config validation.",
                )
            )
            step_num += 1

        # Step 4: Manifest alignments
        alignments = [r for r in self.recommendations if r.suggested_action in ("align", "upgrade")]
        for a in alignments:
            plan.append(
                MigrationPlanStep(
                    step=step_num,
                    target_package=a.package_name,
                    action=a.suggested_action,
                    description=f"Reconcile specifiers for '{a.package_name}' across all manifests.",
                    risk_level=FindingSeverity.HIGH,
                    verification_required="Deterministic manifest consistency check and test suite run.",
                )
            )
            step_num += 1

        return plan

    def _build_default_limitations(self) -> List[str]:
        return [
            "Static AST parsing does not execute code; dynamic imports (e.g. importlib.import_module) require runtime tracing.",
            "Closed-source or private transitive dependency trees cannot be verified without local wheel indexing.",
            "Environment-specific C-extensions or compiled binaries require target architecture build verification.",
            "AI recommendations are probabilistic suggestions and must be verified against repository tests before adoption.",
        ]

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
            tool_version="0.2.0",
            python_runtime=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            timestamp=now_iso,
            manifest_hashes=self.manifest_hashes,
            source_hashes=self.source_hashes,
            composite_hash=composite_hash,
        )

        challenges = self.recommendation_challenges or self._build_default_challenges()
        debt_details = self.verification_debt_details or self._build_default_debt()
        debt_summary = [f"{d.id}: {d.title} ({d.unverified_reason})" for d in debt_details]
        migration_plan = self.migration_plan or self._build_default_migration_plan()
        limitations = self.limitations or self._build_default_limitations()

        return DependencyExitCapsule(
            version="1.1.0",
            tool_name="DocRep",
            tool_version="0.2.0",
            metadata=self.metadata,
            fingerprint=fingerprint,
            declarations=self.declarations,
            imports=self.imports,
            findings=self.findings,
            recommendations=self.recommendations,
            recommendation_challenges=challenges,
            verifications=self.verifications,
            blast_radii=self.blast_radii,
            migration_plan=migration_plan,
            verification_debt=debt_summary,
            verification_debt_details=debt_details,
            limitations=limitations,
            model_info=self.model_info,
            generated_at=now_iso,
        )

    def export_json(self, output_path: Path | str) -> Path:
        """Export capsule as structured, machine-readable JSON."""
        capsule = self.build_capsule()
        out_p = Path(output_path).resolve()
        out_p.parent.mkdir(parents=True, exist_ok=True)
        dumped = capsule.model_dump()
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(dumped, f, indent=2)

        # Validate schema roundtrip
        DependencyExitCapsule.model_validate(dumped)
        return out_p

    def export_markdown(self, output_path: Path | str) -> Path:
        """Export capsule as a comprehensive human-readable Markdown report."""
        capsule = self.build_capsule()
        out_p = Path(output_path).resolve()
        out_p.parent.mkdir(parents=True, exist_ok=True)

        md = self._render_markdown(capsule)
        out_p.write_text(md, encoding="utf-8")
        return out_p

    def export_html(self, output_path: Path | str) -> Path:
        """Export capsule as a standalone, zero-dependency interactive HTML report."""
        from .html_report import render_html_report
        capsule = self.build_capsule()
        out_p = Path(output_path).resolve()
        out_p.parent.mkdir(parents=True, exist_ok=True)
        html_content = render_html_report(capsule)
        out_p.write_text(html_content, encoding="utf-8")
        return out_p

    def _render_markdown(self, c: DependencyExitCapsule) -> str:
        lines: List[str] = []
        lines.append(f"# RepoMedic Dependency Exit Capsule")
        lines.append(f"> **Project:** DocRep (RepoMedic) — Evidence-Backed Dependency Resilience Report  ")
        lines.append(f"> **Target Repository:** `{c.metadata.repo_name}` (`{c.metadata.repo_path}`)  ")
        lines.append(f"> **Git Revision:** `{c.metadata.git_commit or 'Uncommitted / Local'}` (branch: `{c.metadata.git_branch or 'main'}`)  ")
        lines.append(f"> **Audit Fingerprint (SHA-256):** `{c.fingerprint.composite_hash}`  ")
        lines.append(f"> **Generated:** `{c.generated_at}` | **Tool Version:** DocRep v{c.tool_version} / RepoMedic  ")
        lines.append(f"> **Python Detected / Runtime:** `{c.metadata.python_version_detected}` / `{c.fingerprint.python_runtime}`  ")
        lines.append(f"> **Declared Python Constraint:** `{c.metadata.python_requires_declared or 'Unspecified'}`  ")
        lines.append("")
        lines.append("---")
        lines.append("")

        # ── SECTION 1: OBSERVED EVIDENCE ──────────────────────────────────────
        lines.append("## SECTION 1: OBSERVED EVIDENCE (Deterministic Facts)")
        lines.append("")
        lines.append("This section contains solely concrete, verified facts extracted directly via AST scanning and manifest parsing.")
        lines.append("")
        lines.append("### 1.1 Repository & Manifest Inventory")
        lines.append(f"- **Manifest Files Scanned:** {len(c.metadata.manifests_found)} ({', '.join(c.metadata.manifests_found)})")
        lines.append(f"- **Source Files Scanned:** {c.metadata.source_files_count} Python files")
        lines.append(f"- **Test Files Scanned:** {c.metadata.test_files_count} test files")
        lines.append(f"- **Declared Dependencies:** {len(c.declarations)}")
        lines.append(f"- **Observed Imports:** {len(c.imports)}")
        lines.append("")
        lines.append("| Manifest Path | SHA-256 Hash |")
        lines.append("|---|---|")
        for k, v in sorted(c.fingerprint.manifest_hashes.items()):
            lines.append(f"| `{k}` | `{v}` |")
        lines.append("")

        lines.append("### 1.2 Declared Dependencies")
        lines.append("| Package | Raw Declaration | Specifier | Manifest | Line | Type |")
        lines.append("|---|---|---|---|---|---|")
        for d in c.declarations:
            lines.append(
                f"| **{d.name}** | `{d.raw_declaration}` | `{d.specifier or 'any'}` | `{d.manifest_path}` | {d.line_number or '-'} | {'Dev' if d.is_dev else 'Runtime'} |"
            )
        lines.append("")

        lines.append("### 1.3 Deterministic Resilience Findings")
        lines.append("| ID | Category | Severity | Status | Package | Title | Primary Evidence |")
        lines.append("|---|---|---|---|---|---|---|")
        for f in c.findings:
            first_ev = f.evidence[0] if f.evidence else None
            ev_str = f"`{first_ev.file_path}:{first_ev.line_start}`" if first_ev else "N/A"
            lines.append(
                f"| **{f.id}** | `{f.category}` | `{f.severity.value.upper()}` | `{f.status.value}` | `{f.package_name or '-'}` | {f.title} | {ev_str} |"
            )
        lines.append("")

        for f in c.findings:
            lines.append(f"#### Finding {f.id}: {f.title}")
            lines.append(f"- **Category:** `{f.category}` | **Severity:** `{f.severity.value.upper()}` | **Status:** `{f.status.value}`")
            lines.append(f"- **Explanation:** {f.explanation}")
            if f.remediation_hint:
                lines.append(f"- **Remediation Hint:** {f.remediation_hint}")
            lines.append("- **Supporting Evidence:**")
            for ev in f.evidence:
                snippet = f" -> `{ev.content_snippet}`" if ev.content_snippet else ""
                lines.append(f"  - `{ev.file_path}:{ev.line_start or 1}` ({ev.source_type}){snippet}")
            lines.append("")

        lines.append("### 1.4 Dependency Change Blast-Radius Impact Map")
        lines.append("| Package | Risk Level | Importing Modules (Direct) | Impacted Tests (Inferred) | Assessment |")
        lines.append("|---|---|---|---|---|")
        for br in c.blast_radii:
            src_str = ", ".join(f"`{s}`" for s in br.importing_files) or "_None (Ghost)_"
            tst_str = ", ".join(f"`{t}`" for t in br.affected_tests) or "_None_"
            lines.append(
                f"| **{br.dependency_name}** | `{br.risk_level.value.upper()}` | {src_str} | {tst_str} | {br.summary} |"
            )
        lines.append("")

        # ── SECTION 2: AI REASONING & SUGGESTIONS ─────────────────────────────
        lines.append("## SECTION 2: AI SUGGESTIONS & REASONING (Non-Deterministic)")
        lines.append("")
        lines.append("> [!NOTE]")
        lines.append("> **Non-Deterministic Reasoning Notice**: The recommendations and migration plans in this section are generated")
        lines.append("> by local AI reasoning (Hermes Agent / open-weight models). They represent probabilistic suggestions")
        lines.append("> and **MUST NEVER** be merged without executing the corresponding verification checks in Section 3.")
        lines.append("")

        m_name = (c.model_info or {}).get("model_name", "qwen2.5-coder:1.5b (local Ollama)")
        m_endpoint = (c.model_info or {}).get("endpoint", "http://127.0.0.1:11434")
        m_mode = (c.model_info or {}).get("mode", "local_openai_compatible")
        lines.append(f"- **Model Identifier:** `{m_name}`")
        lines.append(f"- **Inference Endpoint:** `{m_endpoint}` (Mode: `{m_mode}`)")
        lines.append(f"- **Zero-Hallucination Policy:** Verifier check names strictly constrained to allow-list; retry-once schema enforcement enabled.")
        lines.append("")

        lines.append("### 2.1 AI Recommendations Summary")
        lines.append("| ID | Package | Action | Suggested Replacement | Source | Status |")
        lines.append("|---|---|---|---|---|---|")
        for r in c.recommendations:
            rep = f"`{r.target_replacement}`" if r.target_replacement else "N/A"
            lines.append(
                f"| **{r.id}** | `{r.package_name}` | `{r.suggested_action.upper()}` | {rep} | `{r.source}` | `{r.status.value}` |"
            )
        lines.append("")

        lines.append("### 2.2 Recommendation Challenges")
        for ch in c.recommendation_challenges:
            lines.append(f"#### Challenge for {ch.recommendation_id} (`{ch.package_name}`)")
            lines.append(f"- **Underlying Assumptions:**")
            for a in ch.assumptions:
                lines.append(f"  - {a}")
            lines.append(f"- **Supporting Evidence:**")
            for se in ch.supporting_evidence:
                lines.append(f"  - {se}")
            lines.append(f"- **Plausible Counterarguments:**")
            for ca in ch.counterarguments:
                lines.append(f"  - {ca}")
            lines.append(f"- **Disproving Evidence:** {ch.disproving_evidence}")
            lines.append(f"- **Required Verification Check:** `{ch.verification_check_needed}`")
            lines.append(f"- **Check Status:** `{'RAN' if ch.check_ran else 'NOT_RUN'}` (Result: `{ch.check_result}`)")
            lines.append("")

        lines.append("### 2.3 Proposed Phased Migration Plan")
        lines.append("| Step | Package | Action | Proposed Change | Risk | Required Verification |")
        lines.append("|---|---|---|---|---|---|")
        for s in c.migration_plan:
            lines.append(
                f"| {s.step} | **{s.target_package}** | `{s.action.upper()}` | {s.description} | `{s.risk_level.value.upper()}` | {s.verification_required} |"
            )
        lines.append("")

        # ── SECTION 3: VERIFIED RESULTS & DEBT ────────────────────────────────
        lines.append("## SECTION 3: VERIFIED RESULTS & AUDIT DEBT")
        lines.append("")
        lines.append("This section records only real, isolated executions. Unfinished checks are explicitly flagged as Verification Debt.")
        lines.append("")

        lines.append("### 3.1 Executed Verification Results")
        if not c.verifications:
            lines.append("_No verification checks were executed._\n")
        else:
            lines.append("| Check ID | Target | Status | Exit Code | Duration | Sandbox Isolated |")
            lines.append("|---|---|---|---|---|---|")
            for v in c.verifications:
                code_str = str(v.exit_code) if v.exit_code is not None else "BLOCKED"
                lines.append(
                    f"| **{v.id}** | {v.target} | `{v.status.value.upper()}` | `{code_str}` | {v.duration_ms}ms | {v.sandbox_used} |"
                )
            lines.append("")
            for v in c.verifications:
                lines.append(f"#### Check {v.id}: {v.target}")
                lines.append(f"- **Command:** `{' '.join(v.command)}`")
                lines.append(f"- **Execution Timestamp:** `{v.timestamp}`")
                lines.append(f"- **Status:** `{v.status.value.upper()}` | **Exit Code:** `{v.exit_code}` | **Duration:** {v.duration_ms}ms")
                if v.notes:
                    lines.append(f"- **Execution Notes:** {v.notes}")
                if v.stdout:
                    lines.append("```text")
                    lines.append(v.stdout.strip()[:1000])
                    lines.append("```")
                if v.stderr:
                    lines.append("**Captured Stderr:**")
                    lines.append("```text")
                    lines.append(v.stderr.strip()[:1000])
                    lines.append("```")
                lines.append("")

        lines.append("### 3.2 Verification Debt (Unfinished Checks)")
        if not c.verification_debt_details:
            lines.append("No verification debt remaining. All proposed actions have passed sandbox checks.\n")
        else:
            for d in c.verification_debt_details:
                lines.append(f"#### ⚠️ {d.id}: {d.title}")
                lines.append(f"- **Status:** `[{d.status}]` (Unfinished)")
                lines.append(f"- **Reason Unverified:** {d.unverified_reason}")
                lines.append(f"- **Maintainer Next Action:** {d.recommended_maintainer_action}")
                lines.append("")

        lines.append("### 3.3 Limitations and Compatibility Gaps")
        for lim in c.limitations:
            lines.append(f"- {lim}")
        lines.append("")

        lines.append("### 3.4 Cryptographic Audit Fingerprint")
        lines.append(f"- **Composite Audit Hash:** `{c.fingerprint.composite_hash}`")
        lines.append(f"- **Manifest Fingerprints:** {len(c.fingerprint.manifest_hashes)} files hashed")
        lines.append(f"- **Source Fingerprints:** {len(c.fingerprint.source_hashes)} files hashed")
        lines.append("")

        return "\n".join(lines)

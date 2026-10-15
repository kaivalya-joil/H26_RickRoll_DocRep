"""Shared data contracts and schemas for RepoMedic."""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class FindingStatus(str, Enum):
    """Rigorous status vocabulary for facts, inferences, recommendations, and results."""
    OBSERVED = "observed"
    INFERRED = "inferred"
    RECOMMENDED = "recommended"
    VERIFIED = "verified"
    FAILED = "failed"
    BLOCKED = "blocked"
    NOT_RUN = "not_run"


class FindingSeverity(str, Enum):
    """Severity classification for dependency resilience findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EvidenceReference(BaseModel):
    """Points to concrete evidence supporting a finding or declaration."""
    file_path: str = Field(..., description="Repository-relative POSIX file path")
    line_start: Optional[int] = Field(None, description="Starting line number (1-indexed)")
    line_end: Optional[int] = Field(None, description="Ending line number (1-indexed)")
    content_snippet: Optional[str] = Field(None, description="Exact code or manifest snippet")
    source_type: str = Field(..., description="Source kind: manifest, source_ast, test_ast, command, runtime")


class DependencyDeclaration(BaseModel):
    """A declared package dependency from a manifest."""
    name: str = Field(..., description="Canonical package name (e.g. 'jinja2')")
    raw_declaration: str = Field(..., description="Raw text line as found in manifest")
    specifier: Optional[str] = Field(None, description="Version specifier (e.g. '==2.11.3', '>=2')")
    manifest_path: str = Field(..., description="Repository-relative manifest path")
    is_dev: bool = Field(False, description="True if dev/test dependency")
    line_number: Optional[int] = Field(None, description="Line number in manifest")
    status: FindingStatus = Field(default=FindingStatus.OBSERVED)


class SourceImport(BaseModel):
    """An import statement observed in Python source or test code."""
    module: str = Field(..., description="Top-level imported module or package name")
    imported_names: List[str] = Field(default_factory=list, description="Specific names imported (from X import Y)")
    file_path: str = Field(..., description="Repository-relative path of file containing the import")
    line_number: int = Field(..., description="Line number of import statement")
    is_test_file: bool = Field(False, description="Whether import occurs in a test file")
    is_try_except: bool = Field(False, description="Whether import is guarded inside try/except")
    status: FindingStatus = Field(default=FindingStatus.OBSERVED)


class Finding(BaseModel):
    """Deterministic resilience finding (e.g. ghost dependency, migration tripwire)."""
    id: str = Field(..., description="Stable unique identifier (e.g. GHOST-001, TRIPWIRE-001)")
    category: str = Field(..., description="Category: ghost_dependency, migration_tripwire, manifest_conflict, etc.")
    title: str = Field(..., description="Short descriptive title")
    explanation: str = Field(..., description="Detailed explanation of the risk, fact, or inference")
    severity: FindingSeverity = Field(..., description="Impact severity")
    status: FindingStatus = Field(..., description="Observed, Inferred, etc.")
    package_name: Optional[str] = Field(None, description="Associated package name if applicable")
    confidence: float = Field(default=1.0, description="Confidence level (0.0 to 1.0)")
    limitations: List[str] = Field(default_factory=list, description="Known scanner limitations or inconclusive caveats")
    evidence: List[EvidenceReference] = Field(default_factory=list, description="Concrete supporting evidence")
    remediation_hint: Optional[str] = Field(None, description="Proposed remediation step")


class AIRecommendation(BaseModel):
    """AI-assisted recommendation from Hermes Agent or local model."""
    id: str = Field(..., description="Unique recommendation ID (e.g. REC-001)")
    finding_id: str = Field(..., description="Associated finding ID")
    package_name: str = Field(..., description="Package targeted by recommendation")
    title: str = Field(..., description="Brief recommendation summary")
    rationale: str = Field(..., description="Technical rationale backed by evidence")
    suggested_action: str = Field(..., description="remove, replace, upgrade, or retain")
    target_replacement: Optional[str] = Field(None, description="Proposed replacement package/stdlib")
    confidence: float = Field(default=1.0, description="Model confidence score (0.0 to 1.0)")
    status: FindingStatus = Field(default=FindingStatus.RECOMMENDED)
    source: str = Field(default="hermes_agent", description="Generator source (hermes_agent or deterministic_fallback)")
    model_name: Optional[str] = Field(None, description="Name of local model used")
    challenge_data: Optional[Dict[str, Any]] = Field(default=None, description="Structured challenge and verification metadata from model")


class VerificationResult(BaseModel):
    """Executed test or check result."""
    id: str = Field(..., description="Unique verification identifier")
    target: str = Field(..., description="What was verified (e.g. LinkWatch test suite)")
    command: List[str] = Field(..., description="Exact command arguments executed")
    exit_code: Optional[int] = Field(None, description="Exit code (None if blocked/not_run)")
    stdout: Optional[str] = Field(None, description="Captured standard output")
    stderr: Optional[str] = Field(None, description="Captured standard error")
    duration_ms: int = Field(default=0, description="Execution time in milliseconds")
    status: FindingStatus = Field(..., description="VERIFIED, FAILED, BLOCKED, or NOT_RUN")
    timestamp: str = Field(..., description="ISO 8601 execution timestamp")
    sandbox_used: bool = Field(default=True, description="Whether check executed in isolated sandbox")
    notes: Optional[str] = Field(None, description="Contextual notes on execution")


class BlastRadiusEntry(BaseModel):
    """Impact analysis mapping a dependency to importing modules and affected tests."""
    dependency_name: str = Field(..., description="Package name")
    importing_files: List[str] = Field(default_factory=list, description="Relative paths of source files importing it")
    affected_tests: List[str] = Field(default_factory=list, description="Relative paths of test files covering or importing it")
    risk_level: FindingSeverity = Field(default=FindingSeverity.LOW)
    summary: str = Field(..., description="Impact description")


class RepositoryMetadata(BaseModel):
    """Contextual metadata discovered from the target repository."""
    repo_name: str
    repo_path: str
    git_branch: Optional[str] = None
    git_commit: Optional[str] = None
    python_version_detected: str
    python_requires_declared: Optional[str] = None
    manifests_found: List[str] = Field(default_factory=list)
    source_files_count: int = 0
    test_files_count: int = 0


class RecommendationChallenge(BaseModel):
    """Rigorous recommendation challenge: assumptions, counterarguments, and disproving evidence."""
    recommendation_id: str
    finding_id: str
    package_name: str
    assumptions: List[str] = Field(default_factory=list, description="Explicit assumptions made by recommendation")
    supporting_evidence: List[str] = Field(default_factory=list, description="Concrete observed repository facts supporting it")
    counterarguments: List[str] = Field(default_factory=list, description="Plausible reasons NOT to apply this recommendation")
    disproving_evidence: str = Field(..., description="What observable evidence would invalidate this recommendation")
    verification_check_needed: str = Field(..., description="Specific verification check required before merging")
    check_ran: bool = Field(default=False)
    check_result: str = Field(default="NOT_RUN", description="VERIFIED, FAILED, BLOCKED, or NOT_RUN")


class VerificationDebtItem(BaseModel):
    """Identifies an unverified change, the reason it could not be completed, and next maintainer steps."""
    id: str
    target: str
    title: str
    unverified_reason: str
    recommended_maintainer_action: str
    status: str = Field(default="UNVERIFIED", description="UNVERIFIED, BLOCKED, or PARTIAL")


class MigrationPlanStep(BaseModel):
    """Structured step within the proposed migration plan."""
    step: int
    target_package: str
    action: str
    description: str
    risk_level: FindingSeverity = Field(default=FindingSeverity.LOW)
    verification_required: str


class AuditFingerprint(BaseModel):
    """Cryptographic and environment audit record for reproducible verification."""
    tool_name: str = "RepoMedic"
    tool_version: str = "0.2.0"
    python_runtime: str
    timestamp: str
    manifest_hashes: Dict[str, str] = Field(default_factory=dict)
    source_hashes: Dict[str, str] = Field(default_factory=dict)
    composite_hash: str


class DependencyExitCapsule(BaseModel):
    """Portable, evidence-backed Dependency Exit Capsule data structure."""
    version: str = "1.1.0"
    tool_name: str = "DocRep"
    tool_version: str = "0.2.0"
    metadata: RepositoryMetadata
    fingerprint: AuditFingerprint
    declarations: List[DependencyDeclaration] = Field(default_factory=list)
    imports: List[SourceImport] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    recommendations: List[AIRecommendation] = Field(default_factory=list)
    recommendation_challenges: List[RecommendationChallenge] = Field(default_factory=list)
    verifications: List[VerificationResult] = Field(default_factory=list)
    blast_radii: List[BlastRadiusEntry] = Field(default_factory=list)
    migration_plan: List[MigrationPlanStep] = Field(default_factory=list)
    verification_debt: List[str] = Field(default_factory=list, description="Untested or partially verified recommendations summary")
    verification_debt_details: List[VerificationDebtItem] = Field(default_factory=list, description="Structured verification debt items")
    limitations: List[str] = Field(default_factory=list, description="Scanner and environment limitations")
    model_info: Optional[Dict[str, Any]] = Field(default=None, description="Metadata regarding AI model execution")
    generated_at: str

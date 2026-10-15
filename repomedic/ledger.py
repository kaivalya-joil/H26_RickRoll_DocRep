"""Evidence Ledger and Audit Fingerprint — cryptographic audit trail for every finding.

Each finding must link to actual evidence.  This module:
  1. Manages a content-addressed evidence store.
  2. Computes SHA-256 hashes of input files.
  3. Detects stale findings when file hashes change.
  4. Never hashes secrets; sensitive file patterns are excluded.
  5. Produces a composite audit fingerprint for the entire scan.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set

from .models import AuditFingerprint, EvidenceReference, Finding


# ---------------------------------------------------------------------------
# Sensitive-file exclusion patterns (never hash or excerpt these)
# ---------------------------------------------------------------------------

_SENSITIVE_PATTERNS: List[re.Pattern] = [
    re.compile(r"\.env(\.|$)", re.IGNORECASE),
    re.compile(r"secrets?\.", re.IGNORECASE),
    re.compile(r"credentials?\.", re.IGNORECASE),
    re.compile(r"\.pem$", re.IGNORECASE),
    re.compile(r"\.key$", re.IGNORECASE),
    re.compile(r"\.p12$", re.IGNORECASE),
    re.compile(r"id_rsa", re.IGNORECASE),
    re.compile(r"id_ecdsa", re.IGNORECASE),
    re.compile(r"id_ed25519", re.IGNORECASE),
    re.compile(r"\.pgp$", re.IGNORECASE),
    re.compile(r"\.gpg$", re.IGNORECASE),
]

SNIPPET_MAX_BYTES = 300    # Maximum bytes to store in an excerpt
EVIDENCE_LEDGER_VERSION = "1.0"


def _is_sensitive(relative_path: str) -> bool:
    name = relative_path.split("/")[-1]
    return any(p.search(name) for p in _SENSITIVE_PATTERNS)


@dataclass
class EvidenceEntry:
    """A content-addressed evidence record with staleness detection."""
    entry_id: str                    # sha256 of (file_path + line_start + category + rule_id)
    file_path: str                   # Repository-relative POSIX path
    line_start: Optional[int]
    line_end: Optional[int]
    excerpt: Optional[str]           # Short, bounded text excerpt
    evidence_category: str           # "manifest", "source_ast", "test_ast", "runtime", "config"
    scanner_rule_id: str             # e.g. "GHOST-001", "TRIPWIRE-002"
    file_sha256: Optional[str]       # SHA-256 of the file at scan time
    collected_at: str                # ISO 8601 timestamp


@dataclass
class StalenessReport:
    """Detected changes between a previous scan's hashes and current file hashes."""
    file_path: str
    previous_sha256: str
    current_sha256: str
    affected_finding_ids: List[str]
    stale: bool = True


@dataclass
class EvidenceLedger:
    """The complete evidence ledger for one scan."""
    version: str = EVIDENCE_LEDGER_VERSION
    scan_timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    tool_name: str = "RepoMedic"
    tool_version: str = "0.2.0"
    python_runtime: str = field(default_factory=lambda: (
        f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    ))
    entries: List[EvidenceEntry] = field(default_factory=list)
    file_hashes: Dict[str, str] = field(default_factory=dict)   # rel_path → sha256
    composite_hash: str = ""

    def to_audit_fingerprint(self) -> AuditFingerprint:
        manifest_hashes = {
            k: v for k, v in self.file_hashes.items()
            if any(k.endswith(ext) for ext in (
                "pyproject.toml", "requirements.txt", "requirements-dev.txt",
                "setup.py", "setup.cfg", "Pipfile",
            ))
        }
        source_hashes = {
            k: v for k, v in self.file_hashes.items()
            if k.endswith(".py")
        }
        return AuditFingerprint(
            tool_name=self.tool_name,
            tool_version=self.tool_version,
            python_runtime=self.python_runtime,
            timestamp=self.scan_timestamp,
            manifest_hashes=manifest_hashes,
            source_hashes=source_hashes,
            composite_hash=self.composite_hash,
        )


class EvidenceLedgerBuilder:
    """Collect, hash, and validate evidence for findings.

    Parameters
    ----------
    repo_root:
        Absolute path to the repository root — used for reading files during
        excerpt collection when source_texts is not provided.
    source_texts:
        Optional pre-read mapping of rel_path → text content, to avoid
        double-reading files.
    file_hashes:
        Pre-computed SHA-256 hashes from the scanner (rel_path → sha256).
    """

    def __init__(
        self,
        repo_root: str | Path,
        source_texts: Optional[Dict[str, str]] = None,
        file_hashes: Optional[Dict[str, str]] = None,
    ) -> None:
        self._root = Path(repo_root).resolve()
        self._source_texts = source_texts or {}
        self._file_hashes: Dict[str, str] = dict(file_hashes or {})
        self._entries: List[EvidenceEntry] = []
        self._timestamp = datetime.now(timezone.utc).isoformat()

    def register_file_hash(self, rel_path: str, sha256: str) -> None:
        """Explicitly register a file hash (e.g. from scanner output)."""
        if not _is_sensitive(rel_path):
            self._file_hashes[rel_path] = sha256

    def register_file_hashes(self, hashes: Dict[str, str]) -> None:
        for k, v in hashes.items():
            self.register_file_hash(k, v)

    def record_finding_evidence(
        self,
        finding: Finding,
        scanner_rule_id: str,
    ) -> List[EvidenceEntry]:
        """Record all evidence references attached to a finding."""
        entries: List[EvidenceEntry] = []
        for ev_ref in finding.evidence:
            entry = self._make_entry(ev_ref, scanner_rule_id)
            if entry:
                self._entries.append(entry)
                entries.append(entry)
        return entries

    def record_evidence_ref(
        self,
        ev_ref: EvidenceReference,
        scanner_rule_id: str,
    ) -> Optional[EvidenceEntry]:
        """Record a single EvidenceReference."""
        entry = self._make_entry(ev_ref, scanner_rule_id)
        if entry:
            self._entries.append(entry)
        return entry

    def check_staleness(
        self,
        previous_hashes: Dict[str, str],
        finding_id_map: Optional[Dict[str, List[str]]] = None,
    ) -> List[StalenessReport]:
        """Compare previous hashes to current — return stale files.

        Parameters
        ----------
        previous_hashes:
            Mapping of rel_path → sha256 from a prior scan.
        finding_id_map:
            Optional mapping of rel_path → list of finding IDs that referenced it.
        """
        reports: List[StalenessReport] = []
        for path, prev_hash in previous_hashes.items():
            current_hash = self._file_hashes.get(path)
            if current_hash and current_hash != prev_hash:
                affected = (finding_id_map or {}).get(path, [])
                reports.append(StalenessReport(
                    file_path=path,
                    previous_sha256=prev_hash,
                    current_sha256=current_hash,
                    affected_finding_ids=affected,
                    stale=True,
                ))
        return reports

    def build(self) -> EvidenceLedger:
        """Finalise and return the complete evidence ledger."""
        composite = self._compute_composite()
        return EvidenceLedger(
            scan_timestamp=self._timestamp,
            entries=list(self._entries),
            file_hashes=dict(self._file_hashes),
            composite_hash=composite,
        )

    def export_json(self, output_path: Path | str) -> Path:
        """Serialise the evidence ledger to JSON."""
        ledger = self.build()
        out = Path(output_path).resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(
                {
                    "version": ledger.version,
                    "scan_timestamp": ledger.scan_timestamp,
                    "tool_name": ledger.tool_name,
                    "tool_version": ledger.tool_version,
                    "python_runtime": ledger.python_runtime,
                    "composite_hash": ledger.composite_hash,
                    "file_hashes": ledger.file_hashes,
                    "evidence_entries": [
                        {
                            "entry_id":         e.entry_id,
                            "file_path":        e.file_path,
                            "line_start":       e.line_start,
                            "line_end":         e.line_end,
                            "excerpt":          e.excerpt,
                            "evidence_category": e.evidence_category,
                            "scanner_rule_id":  e.scanner_rule_id,
                            "file_sha256":      e.file_sha256,
                            "collected_at":     e.collected_at,
                        }
                        for e in ledger.entries
                    ],
                },
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        return out

    # ── private helpers ───────────────────────────────────────────────────────

    def _make_entry(
        self,
        ev_ref: EvidenceReference,
        scanner_rule_id: str,
    ) -> Optional[EvidenceEntry]:
        if _is_sensitive(ev_ref.file_path):
            return None

        # Content-address the entry
        raw_id = f"{ev_ref.file_path}|{ev_ref.line_start}|{ev_ref.source_type}|{scanner_rule_id}"
        entry_id = hashlib.sha256(raw_id.encode()).hexdigest()[:16]

        file_sha = self._file_hashes.get(ev_ref.file_path)
        excerpt = ev_ref.content_snippet

        # If no excerpt in the ref, try to pull from source_texts
        if not excerpt and ev_ref.file_path in self._source_texts and ev_ref.line_start:
            text = self._source_texts[ev_ref.file_path]
            lines = text.splitlines()
            start = max(0, (ev_ref.line_start or 1) - 1)
            end   = min(len(lines), (ev_ref.line_end or ev_ref.line_start or 1))
            excerpt = "\n".join(lines[start:end])

        if excerpt and len(excerpt) > SNIPPET_MAX_BYTES:
            excerpt = excerpt[:SNIPPET_MAX_BYTES] + " …[truncated]"

        return EvidenceEntry(
            entry_id=entry_id,
            file_path=ev_ref.file_path,
            line_start=ev_ref.line_start,
            line_end=ev_ref.line_end,
            excerpt=excerpt,
            evidence_category=ev_ref.source_type,
            scanner_rule_id=scanner_rule_id,
            file_sha256=file_sha,
            collected_at=self._timestamp,
        )

    def _compute_composite(self) -> str:
        h = hashlib.sha256()
        for path in sorted(self._file_hashes.keys()):
            h.update(f"{path}:{self._file_hashes[path]}\n".encode())
        return h.hexdigest()

"""Tests for shared schemas, data models, and JSON serialization."""

import json
import unittest

from repomedic.models import (
    EvidenceReference,
    Finding,
    FindingSeverity,
    FindingStatus,
    RepositoryMetadata,
)


class TestModels(unittest.TestCase):
    def test_status_vocabulary(self):
        valid_statuses = {"observed", "inferred", "recommended", "verified", "failed", "blocked", "not_run"}
        model_statuses = {s.value for s in FindingStatus}
        self.assertEqual(valid_statuses, model_statuses)

    def test_finding_serialization(self):
        evidence = EvidenceReference(
            file_path="pyproject.toml",
            line_start=12,
            line_end=12,
            content_snippet="six = '*'",
            source_type="manifest",
        )
        finding = Finding(
            id="GHOST-001",
            category="ghost_dependency",
            title="Unused package 'six'",
            explanation="Package 'six' is declared but never imported.",
            severity=FindingSeverity.HIGH,
            status=FindingStatus.INFERRED,
            package_name="six",
            evidence=[evidence],
            remediation_hint="Remove 'six' from pyproject.toml",
        )

        data = finding.model_dump()
        json_str = json.dumps(data)
        self.assertIn("GHOST-001", json_str)
        self.assertIn("inferred", json_str)
        self.assertIn("pyproject.toml", json_str)

        # Roundtrip
        loaded = Finding.model_validate_json(json_str)
        self.assertEqual(loaded.id, "GHOST-001")
        self.assertEqual(loaded.status, FindingStatus.INFERRED)
        self.assertEqual(len(loaded.evidence), 1)


if __name__ == "__main__":
    unittest.main()

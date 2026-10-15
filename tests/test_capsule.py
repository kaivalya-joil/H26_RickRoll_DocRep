"""Tests for Capsule generation, audit hashing, and export."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from repomedic.capsule import CapsuleGenerator
from repomedic.models import (
    AIRecommendation,
    BlastRadiusEntry,
    DependencyDeclaration,
    Finding,
    FindingSeverity,
    FindingStatus,
    RepositoryMetadata,
    SourceImport,
    VerificationResult,
)


class TestCapsule(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.out_dir = Path(self.temp_dir)

        self.metadata = RepositoryMetadata(
            repo_name="linkwatch",
            repo_path="/test/linkwatch",
            python_version_detected="3.14.0",
            python_requires_declared=">=3.10",
            manifests_found=["pyproject.toml"],
            source_files_count=1,
            test_files_count=1,
        )
        self.declarations = [
            DependencyDeclaration(name="six", raw_declaration="six", manifest_path="pyproject.toml")
        ]
        self.imports = []
        self.findings = [
            Finding(
                id="GHOST-001",
                category="ghost_dependency",
                title="Unused six",
                explanation="Package six is unused.",
                severity=FindingSeverity.HIGH,
                status=FindingStatus.INFERRED,
                package_name="six",
            )
        ]
        self.recommendations = [
            AIRecommendation(
                id="REC-001",
                finding_id="GHOST-001",
                package_name="six",
                title="Remove six",
                rationale="Unused package",
                suggested_action="remove",
            )
        ]
        self.verifications = [
            VerificationResult(
                id="VERIFY-001",
                target="test suite",
                command=["python", "-m", "unittest"],
                exit_code=0,
                status=FindingStatus.VERIFIED,
                timestamp="2026-10-15T00:00:00Z",
                sandbox_used=True,
            )
        ]
        self.blast_radii = [
            BlastRadiusEntry(
                dependency_name="six",
                importing_files=[],
                affected_tests=[],
                risk_level=FindingSeverity.LOW,
                summary="Ghost dependency",
            )
        ]
        self.m_hashes = {"pyproject.toml": "abc123hash"}
        self.s_hashes = {"main.py": "def456hash"}

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_capsule_build_and_export(self):
        gen = CapsuleGenerator(
            metadata=self.metadata,
            declarations=self.declarations,
            imports=self.imports,
            findings=self.findings,
            recommendations=self.recommendations,
            verifications=self.verifications,
            blast_radii=self.blast_radii,
            manifest_hashes=self.m_hashes,
            source_hashes=self.s_hashes,
        )

        capsule = gen.build_capsule()
        self.assertEqual(capsule.metadata.repo_name, "linkwatch")
        self.assertTrue(len(capsule.fingerprint.composite_hash) > 10)
        self.assertEqual(len(capsule.verification_debt), 1)

        # Export JSON
        json_p = gen.export_json(self.out_dir / "capsule.json")
        self.assertTrue(json_p.exists())
        data = json.loads(json_p.read_text(encoding="utf-8"))
        self.assertEqual(data["metadata"]["repo_name"], "linkwatch")
        self.assertEqual(data["fingerprint"]["tool_name"], "RepoMedic")

        # Export Markdown
        md_p = gen.export_markdown(self.out_dir / "capsule.md")
        self.assertTrue(md_p.exists())
        md_text = md_p.read_text(encoding="utf-8")
        self.assertIn("# RepoMedic Dependency Exit Capsule", md_text)
        self.assertIn("GHOST-001", md_text)
        self.assertIn("Audit Fingerprint", md_text)


if __name__ == "__main__":
    unittest.main()

"""Tests for analyzer: ghost dependency detection, tripwires, and manifest conflicts."""

import unittest
from pathlib import Path

from repomedic.analyzer import DependencyAnalyzer
from repomedic.models import (
    DependencyDeclaration,
    FindingSeverity,
    FindingStatus,
    RepositoryMetadata,
    SourceImport,
)


class TestAnalyzer(unittest.TestCase):
    def setUp(self):
        self.metadata = RepositoryMetadata(
            repo_name="linkwatch",
            repo_path="/test/linkwatch",
            python_version_detected="3.14.0",
            python_requires_declared=">=3.10",
            manifests_found=["pyproject.toml", "requirements.txt"],
            source_files_count=2,
            test_files_count=1,
        )

    def test_ghost_dependency_detected(self):
        # Declare 'six' and 'requests', but only import 'requests'
        declarations = [
            DependencyDeclaration(
                name="six",
                raw_declaration="six",
                specifier=None,
                manifest_path="pyproject.toml",
                line_number=10,
            ),
            DependencyDeclaration(
                name="requests",
                raw_declaration="requests==2.31.0",
                specifier="==2.31.0",
                manifest_path="pyproject.toml",
                line_number=11,
            ),
        ]
        imports = [
            SourceImport(
                module="requests",
                imported_names=["Session"],
                file_path="src/fetch.py",
                line_number=1,
            )
        ]
        analyzer = DependencyAnalyzer(self.metadata, declarations, imports)
        findings = analyzer.analyze()

        ghost_findings = [f for f in findings if f.category == "ghost_dependency"]
        self.assertEqual(len(ghost_findings), 1)
        self.assertEqual(ghost_findings[0].package_name, "six")
        self.assertEqual(ghost_findings[0].status, FindingStatus.INFERRED)

    def test_migration_tripwires_detected(self):
        # Declare 'toml' and 'appdirs', import them in source
        declarations = [
            DependencyDeclaration(
                name="toml",
                raw_declaration="toml==0.10.2",
                specifier="==0.10.2",
                manifest_path="pyproject.toml",
                line_number=5,
            ),
            DependencyDeclaration(
                name="appdirs",
                raw_declaration="appdirs==1.4.4",
                specifier="==1.4.4",
                manifest_path="pyproject.toml",
                line_number=6,
            ),
        ]
        imports = [
            SourceImport(
                module="toml",
                imported_names=[],
                file_path="linkwatch/config.py",
                line_number=3,
            ),
            SourceImport(
                module="appdirs",
                imported_names=["user_cache_dir"],
                file_path="linkwatch/cache.py",
                line_number=4,
            ),
        ]
        analyzer = DependencyAnalyzer(self.metadata, declarations, imports)
        findings = analyzer.analyze()

        tripwires = {f.package_name: f for f in findings if f.category == "migration_tripwire"}
        self.assertIn("toml", tripwires)
        self.assertIn("appdirs", tripwires)
        self.assertIn("tomllib", tripwires["toml"].remediation_hint)
        self.assertIn("platformdirs", tripwires["appdirs"].remediation_hint)

    def test_manifest_conflict_detected(self):
        declarations = [
            DependencyDeclaration(
                name="pydantic",
                raw_declaration="pydantic>=2",
                specifier=">=2",
                manifest_path="pyproject.toml",
                line_number=17,
            ),
            DependencyDeclaration(
                name="pydantic",
                raw_declaration="pydantic==1.10.13",
                specifier="==1.10.13",
                manifest_path="requirements.txt",
                line_number=5,
            ),
        ]
        imports = [
            SourceImport(
                module="pydantic",
                imported_names=["BaseModel"],
                file_path="src/config.py",
                line_number=1,
            )
        ]
        analyzer = DependencyAnalyzer(self.metadata, declarations, imports)
        findings = analyzer.analyze()

        conflicts = [f for f in findings if f.category == "manifest_conflict"]
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0].package_name, "pydantic")
        self.assertEqual(conflicts[0].severity, FindingSeverity.HIGH)


if __name__ == "__main__":
    unittest.main()

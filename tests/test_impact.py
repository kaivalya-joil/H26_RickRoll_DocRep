"""Tests for change blast-radius mapping and affected test calculation."""

import unittest

from repomedic.impact import ImpactAnalyzer
from repomedic.models import (
    DependencyDeclaration,
    FindingSeverity,
    SourceImport,
)


class TestImpact(unittest.TestCase):
    def test_blast_radius_calculation(self):
        declarations = [
            DependencyDeclaration(name="requests", raw_declaration="requests", manifest_path="pyproject.toml"),
            DependencyDeclaration(name="six", raw_declaration="six", manifest_path="pyproject.toml"),
        ]
        imports = [
            SourceImport(
                module="requests",
                imported_names=["Session"],
                file_path="linkwatch/checker.py",
                line_number=5,
                is_test_file=False,
            ),
            SourceImport(
                module="requests",
                imported_names=[],
                file_path="tests/test_checker.py",
                line_number=2,
                is_test_file=True,
            ),
        ]
        analyzer = ImpactAnalyzer(declarations, imports)
        radii = analyzer.calculate_blast_radius()

        radii_map = {br.dependency_name: br for br in radii}

        # requests has active imports
        self.assertIn("linkwatch/checker.py", radii_map["requests"].importing_files)
        self.assertIn("tests/test_checker.py", radii_map["requests"].affected_tests)

        # six has 0 imports (ghost) -> risk is LOW
        self.assertEqual(len(radii_map["six"].importing_files), 0)
        self.assertEqual(radii_map["six"].risk_level, FindingSeverity.LOW)


if __name__ == "__main__":
    unittest.main()

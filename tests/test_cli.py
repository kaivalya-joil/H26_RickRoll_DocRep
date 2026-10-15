"""Tests for RepoMedic Click CLI interface."""

import unittest
from click.testing import CliRunner

from repomedic.cli import cli


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.runner = CliRunner()

    def test_cli_status(self):
        result = self.runner.invoke(cli, ["status"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("RepoMedic Environment", result.output)
        self.assertIn("Python Interpreter", result.output)

    def test_cli_scan(self):
        result = self.runner.invoke(cli, ["scan", "target_repo/linkwatch"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("linkwatch", result.output)
        self.assertIn("toml", result.output)

    def test_cli_analyze(self):
        result = self.runner.invoke(cli, ["analyze", "target_repo/linkwatch"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("GHOST", result.output)
        self.assertIn("TRIPWIRE", result.output)

    def test_cli_impact(self):
        result = self.runner.invoke(cli, ["impact", "target_repo/linkwatch"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Dependency Change Blast-Radius", result.output)

    def test_cli_capsule(self):
        import tempfile
        import shutil
        from pathlib import Path
        temp_dir = tempfile.mkdtemp()
        try:
            repo_path = Path("target_repo/linkwatch").resolve()
            result = self.runner.invoke(cli, ["capsule", str(repo_path), "-o", temp_dir])
            self.assertEqual(result.exit_code, 0)
            self.assertIn("Capsule generated successfully", result.output)
            self.assertTrue((Path(temp_dir) / "capsule.json").exists())
            self.assertTrue((Path(temp_dir) / "capsule.md").exists())
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

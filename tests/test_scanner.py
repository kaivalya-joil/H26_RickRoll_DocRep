"""Tests for repository scanner, AST import extraction, and manifest parsing."""

import shutil
import tempfile
import unittest
from pathlib import Path

from repomedic.scanner import RepositoryScanner


class TestScanner(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.repo_dir = Path(self.temp_dir)

        # Create mock pyproject.toml
        pyproject = (
            "[project]\n"
            "name = 'mock-repo'\n"
            "requires-python = '>=3.11'\n"
            "dependencies = [\n"
            "    'toml==0.10.2',\n"
            "    'six',\n"
            "]\n"
        )
        (self.repo_dir / "pyproject.toml").write_text(pyproject, encoding="utf-8")

        # Create mock source file
        (self.repo_dir / "src").mkdir()
        src_code = (
            "import toml\n"
            "from math import sqrt\n"
            "try:\n"
            "    import optional_pkg\n"
            "except ImportError:\n"
            "    optional_pkg = None\n"
        )
        (self.repo_dir / "src" / "main.py").write_text(src_code, encoding="utf-8")

        # Create mock test file
        (self.repo_dir / "tests").mkdir()
        test_code = "import unittest\nfrom src.main import toml\n"
        (self.repo_dir / "tests" / "test_main.py").write_text(test_code, encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_scanner_detects_manifests_and_imports(self):
        scanner = RepositoryScanner(self.repo_dir)
        metadata, declarations, imports, m_hashes, s_hashes = scanner.scan()

        self.assertEqual(metadata.repo_name, self.repo_dir.name)
        self.assertEqual(metadata.python_requires_declared, ">=3.11")
        self.assertIn("pyproject.toml", metadata.manifests_found)

        # Declarations
        decl_names = {d.name for d in declarations}
        self.assertIn("toml", decl_names)
        self.assertIn("six", decl_names)

        # Verify line numbers captured
        toml_decl = next(d for d in declarations if d.name == "toml")
        self.assertEqual(toml_decl.specifier, "==0.10.2")
        self.assertIsNotNone(toml_decl.line_number)

        # Imports
        imported_modules = {i.module for i in imports}
        self.assertIn("toml", imported_modules)
        self.assertIn("math", imported_modules)
        self.assertIn("optional_pkg", imported_modules)

        # Check try/except context
        opt_import = next(i for i in imports if i.module == "optional_pkg")
        self.assertTrue(opt_import.is_try_except)

        # Check test file flag
        unittest_import = next(i for i in imports if i.module == "unittest")
        self.assertTrue(unittest_import.is_test_file)

        # Check SHA-256 hashes
        self.assertIn("pyproject.toml", m_hashes)
        self.assertIn("src/main.py", s_hashes)


if __name__ == "__main__":
    unittest.main()

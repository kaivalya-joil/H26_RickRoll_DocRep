"""Tests for safe path handling and sandbox isolation."""

import unittest
from pathlib import Path
import tempfile
import shutil

from repomedic.safety import (
    PathTraversalError,
    IsolatedSandbox,
    to_relative_posix,
    validate_safe_path,
)


class TestSafety(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.base_dir = Path(self.temp_dir).resolve()
        (self.base_dir / "subdir").mkdir()
        (self.base_dir / "subdir" / "file.py").write_text("print(1)", encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_safe_path_valid(self):
        valid = self.base_dir / "subdir" / "file.py"
        res = validate_safe_path(self.base_dir, valid)
        self.assertEqual(res, valid)

    def test_safe_path_traversal_rejected(self):
        invalid = self.base_dir / ".." / "external_file.txt"
        with self.assertRaises(PathTraversalError):
            validate_safe_path(self.base_dir, invalid)

    def test_to_relative_posix(self):
        target = self.base_dir / "subdir" / "file.py"
        rel = to_relative_posix(self.base_dir, target)
        self.assertEqual(rel, "subdir/file.py")

    def test_sandbox_preserves_original(self):
        with IsolatedSandbox(self.base_dir) as sandbox_path:
            self.assertTrue(sandbox_path.exists())
            # Mutate file in sandbox
            mutated = sandbox_path / "subdir" / "file.py"
            mutated.write_text("modified", encoding="utf-8")
            self.assertEqual(mutated.read_text(), "modified")

            # Original remains pristine
            orig = self.base_dir / "subdir" / "file.py"
            self.assertEqual(orig.read_text(), "print(1)")

        # Sandbox is cleaned up automatically
        self.assertFalse(sandbox_path.exists())


if __name__ == "__main__":
    unittest.main()

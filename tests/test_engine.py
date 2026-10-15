"""Comprehensive test suite for the Prompt 2 intelligence engine.

Tests cover:
  - Distribution-name vs. import-name ambiguity
  - Missing and malformed manifests
  - Unused-looking but test-only packages
  - Dynamic imports and optional imports
  - Duplicate declarations across manifests
  - Invalid repository paths
  - Symlinks pointing outside the repository
  - Empty repositories and unsupported manifest formats
  - Changed file hashes (staleness detection)
  - Deterministic graph construction
  - Integration test against the actual synthesis fixture
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import shutil
import tempfile
import textwrap
import unittest
from pathlib import Path
from typing import Dict, List
from unittest.mock import patch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_repo(files: Dict[str, str]) -> Path:
    """Create a temp directory with the given file tree. Returns the root Path."""
    root = Path(tempfile.mkdtemp(prefix="repomedic_test_"))
    for rel, content in files.items():
        dest = root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")
    return root


def cleanup(root: Path) -> None:
    shutil.rmtree(str(root), ignore_errors=True)


# ---------------------------------------------------------------------------
# 1. Inventory Scanner tests
# ---------------------------------------------------------------------------

class TestInventoryScanner(unittest.TestCase):
    def setUp(self):
        self.root = make_repo({
            "pyproject.toml": "[project]\nname='mock'\ndependencies=['click']\n",
            "requirements.txt": "requests==2.31.0\n",
            "src/app.py": "import requests\n",
            "tests/test_app.py": "import pytest\n",
            "conda.yaml": "name: env\n",           # unsupported
            ".venv/lib/site.py": "# venv file\n",  # should be pruned
        })

    def tearDown(self):
        cleanup(self.root)

    def test_manifests_detected(self):
        from repomedic.inventory import RepositoryInventoryScanner
        scanner = RepositoryInventoryScanner(self.root)
        inv = scanner.scan()
        manifest_rels = [m.relative_path for m in inv.manifests]
        self.assertIn("pyproject.toml", manifest_rels)
        self.assertIn("requirements.txt", manifest_rels)

    def test_unsupported_manifest_reported(self):
        from repomedic.inventory import RepositoryInventoryScanner
        scanner = RepositoryInventoryScanner(self.root)
        inv = scanner.scan()
        self.assertIn("conda.yaml", inv.unsupported_manifests)

    def test_venv_pruned(self):
        from repomedic.inventory import RepositoryInventoryScanner
        scanner = RepositoryInventoryScanner(self.root)
        inv = scanner.scan()
        paths = [s.relative_path for s in inv.source_files]
        self.assertFalse(any(".venv" in p for p in paths), f"venv files leaked: {paths}")

    def test_test_files_classified(self):
        from repomedic.inventory import RepositoryInventoryScanner
        scanner = RepositoryInventoryScanner(self.root)
        inv = scanner.scan()
        test_paths = [s.relative_path for s in inv.test_files]
        self.assertTrue(any("test_app" in p for p in test_paths))

    def test_sha256_hashes_populated(self):
        from repomedic.inventory import RepositoryInventoryScanner
        scanner = RepositoryInventoryScanner(self.root)
        inv = scanner.scan()
        for m in inv.manifests:
            self.assertRegex(m.sha256, r'^[0-9a-f]{64}$')

    def test_invalid_path_raises(self):
        from repomedic.inventory import RepositoryInventoryScanner
        with self.assertRaises(FileNotFoundError):
            RepositoryInventoryScanner("/does/not/exist/at/all")

    def test_empty_repository(self):
        from repomedic.inventory import RepositoryInventoryScanner
        root = Path(tempfile.mkdtemp(prefix="repomedic_empty_"))
        try:
            scanner = RepositoryInventoryScanner(root)
            inv = scanner.scan()
            self.assertEqual(inv.manifests, [])
            self.assertEqual(inv.source_files, [])
        finally:
            cleanup(root)

    def test_oversized_file_skipped(self):
        from repomedic.inventory import RepositoryInventoryScanner, MAX_FILE_SIZE_BYTES
        root = Path(tempfile.mkdtemp(prefix="repomedic_big_"))
        try:
            big = root / "bigfile.py"
            big.write_bytes(b"x" * (MAX_FILE_SIZE_BYTES + 1))
            scanner = RepositoryInventoryScanner(root)
            inv = scanner.scan()
            reasons = [s.reason for s in inv.skipped]
            self.assertTrue(any("oversized" in r for r in reasons))
        finally:
            cleanup(root)

    @unittest.skipIf(os.name == "nt", "Symlinks require elevated privileges on Windows")
    def test_symlink_escape_skipped(self):
        from repomedic.inventory import RepositoryInventoryScanner
        root = Path(tempfile.mkdtemp(prefix="repomedic_sym_"))
        outside = Path(tempfile.mkdtemp(prefix="repomedic_outside_"))
        try:
            victim = outside / "secret.py"
            victim.write_text("password = 'hunter2'\n")
            link = root / "link.py"
            link.symlink_to(victim)
            scanner = RepositoryInventoryScanner(root)
            inv = scanner.scan()
            reasons = [s.reason for s in inv.skipped]
            self.assertTrue(any("symlink_escape" in r for r in reasons))
        finally:
            cleanup(root)
            cleanup(outside)


# ---------------------------------------------------------------------------
# 2. Ghost Detector tests
# ---------------------------------------------------------------------------

class TestGhostDetector(unittest.TestCase):
    def _decl(self, name, manifest="pyproject.toml", line=1, is_dev=False, spec=None):
        from repomedic.models import DependencyDeclaration
        return DependencyDeclaration(
            name=name, raw_declaration=f"{name}{spec or ''}",
            specifier=spec, manifest_path=manifest,
            line_number=line, is_dev=is_dev,
        )

    def _imp(self, module, file_path="src/main.py", line=1, is_test=False, is_try=False, names=None):
        from repomedic.models import SourceImport
        return SourceImport(
            module=module, imported_names=names or [],
            file_path=file_path, line_number=line,
            is_test_file=is_test, is_try_except=is_try,
        )

    def test_direct_import_found(self):
        from repomedic.ghost import GhostDetector, GhostClassification
        decls = [self._decl("requests")]
        imps  = [self._imp("requests")]
        det = GhostDetector(decls, imps)
        results = det.analyze()
        r = next(x for x in results if x.package_name == "requests")
        self.assertEqual(r.classification, GhostClassification.USAGE_FOUND)

    def test_possibly_unused_direct_mapping(self):
        from repomedic.ghost import GhostDetector, GhostClassification
        decls = [self._decl("requests")]
        det = GhostDetector(decls, [])   # No imports at all
        results = det.analyze()
        r = next(x for x in results if x.package_name == "requests")
        self.assertEqual(r.classification, GhostClassification.POSSIBLY_UNUSED)

    def test_pyyaml_dist_to_yaml_module(self):
        """pyyaml maps to 'yaml' import — must detect usage correctly."""
        from repomedic.ghost import GhostDetector, GhostClassification
        decls = [self._decl("pyyaml")]
        imps  = [self._imp("yaml")]  # Distribution 'pyyaml' imports as 'yaml'
        det = GhostDetector(decls, imps)
        results = det.analyze()
        r = next(x for x in results if x.package_name == "pyyaml")
        self.assertEqual(r.classification, GhostClassification.USAGE_FOUND)

    def test_cli_tool_is_not_applicable(self):
        from repomedic.ghost import GhostDetector, GhostClassification
        decls = [self._decl("flake8")]
        det = GhostDetector(decls, [])
        results = det.analyze()
        r = next(x for x in results if x.package_name == "flake8")
        self.assertEqual(r.classification, GhostClassification.NOT_APPLICABLE)

    def test_pytest_not_applicable(self):
        from repomedic.ghost import GhostDetector, GhostClassification
        decls = [self._decl("pytest")]
        imps  = [self._imp("pytest", file_path="tests/test_x.py", is_test=True)]
        det = GhostDetector(decls, imps)
        results = det.analyze()
        r = next(x for x in results if x.package_name == "pytest")
        self.assertEqual(r.classification, GhostClassification.NOT_APPLICABLE)

    def test_dev_only_package_usage_uncertain(self):
        from repomedic.ghost import GhostDetector, GhostClassification
        decls = [self._decl("factory-boy", is_dev=True)]
        # factory-boy → 'factory' module; not imported in any file
        det = GhostDetector(decls, [])
        results = det.analyze()
        r = next(x for x in results if x.package_name == "factory-boy")
        self.assertIn(r.classification, (
            GhostClassification.USAGE_UNCERTAIN,
            GhostClassification.NOT_APPLICABLE,
        ))

    def test_optional_import_guarded_try_except(self):
        from repomedic.ghost import GhostDetector, GhostClassification
        decls = [self._decl("chardet")]
        imps  = [self._imp("chardet", is_try=True)]   # Optional import
        det = GhostDetector(decls, imps)
        results = det.analyze()
        r = next(x for x in results if x.package_name == "chardet")
        # Still usage_found — try/except is just a qualifier, not absence
        self.assertEqual(r.classification, GhostClassification.USAGE_FOUND)
        self.assertIn("try/except", r.explanation)

    def test_ambiguous_mapping_usage_uncertain(self):
        from repomedic.ghost import GhostDetector, GhostClassification
        # 'attrs' maps to both 'attr' and 'attrs'
        decls = [self._decl("attrs")]
        det = GhostDetector(decls, [])
        results = det.analyze()
        r = next(x for x in results if x.package_name == "attrs")
        self.assertIn(r.classification, (
            GhostClassification.USAGE_UNCERTAIN,
            GhostClassification.POSSIBLY_UNUSED,
        ))

    def test_duplicate_declarations_collapsed(self):
        from repomedic.ghost import GhostDetector
        decls = [
            self._decl("requests", manifest="pyproject.toml"),
            self._decl("requests", manifest="requirements.txt"),
        ]
        det = GhostDetector(decls, [])
        results = det.analyze()
        # Should produce exactly one result for 'requests'
        req_results = [r for r in results if r.package_name == "requests"]
        self.assertEqual(len(req_results), 1)


# ---------------------------------------------------------------------------
# 3. Compatibility Analyzer tests
# ---------------------------------------------------------------------------

class TestCompatibilityAnalyzer(unittest.TestCase):
    def _meta(self, requires_python=">=3.10"):
        from repomedic.models import RepositoryMetadata
        return RepositoryMetadata(
            repo_name="test", repo_path="/tmp/test",
            python_version_detected="3.14.0",
            python_requires_declared=requires_python,
            manifests_found=["pyproject.toml"],
        )

    def _decl(self, name, spec=None, manifest="pyproject.toml", line=1):
        from repomedic.models import DependencyDeclaration
        return DependencyDeclaration(
            name=name, raw_declaration=f"{name}{spec or ''}",
            specifier=spec, manifest_path=manifest, line_number=line,
        )

    def test_python_constraint_satisfied(self):
        from repomedic.compat import CompatibilityAnalyzer, CompatibilityStatus
        meta = self._meta(">=3.10")
        analyzer = CompatibilityAnalyzer(meta, [])
        results = analyzer.analyze()
        py = next((r for r in results if r.package_name == "__python_runtime__"), None)
        self.assertIsNotNone(py)
        self.assertEqual(py.status, CompatibilityStatus.COMPATIBLE)

    def test_python_constraint_violation(self):
        from repomedic.compat import CompatibilityAnalyzer, CompatibilityStatus
        meta = self._meta("==3.6")   # 3.6 does not match 3.14.x
        analyzer = CompatibilityAnalyzer(meta, [])
        results = analyzer.analyze()
        py = next((r for r in results if r.package_name == "__python_runtime__"), None)
        self.assertIsNotNone(py)
        self.assertEqual(py.status, CompatibilityStatus.PYTHON_CONSTRAINT_FAIL)

    def test_malformed_specifier(self):
        from repomedic.compat import CompatibilityAnalyzer, CompatibilityStatus
        meta = self._meta()
        decls = [self._decl("foobar", spec=">>>INVALID<<<")]
        analyzer = CompatibilityAnalyzer(meta, decls)
        results = analyzer.analyze()
        r = next((x for x in results if x.package_name == "foobar"), None)
        self.assertIsNotNone(r)
        self.assertEqual(r.status, CompatibilityStatus.SPECIFIER_MALFORMED)

    def test_installed_version_checked(self):
        from repomedic.compat import CompatibilityAnalyzer, CompatibilityStatus
        meta = self._meta()
        # click is installed; constraint allows any version
        decls = [self._decl("click", spec=">=8.0.0")]
        analyzer = CompatibilityAnalyzer(meta, decls)
        results = analyzer.analyze()
        r = next((x for x in results if x.package_name == "click"), None)
        self.assertIsNotNone(r)
        # click 8.x is installed so it should be compatible
        self.assertIn(r.status, (CompatibilityStatus.COMPATIBLE, CompatibilityStatus.MISSING_LOCALLY))

    def test_no_specifier_unchecked(self):
        from repomedic.compat import CompatibilityAnalyzer, CompatibilityStatus
        meta = self._meta()
        decls = [self._decl("click", spec=None)]
        analyzer = CompatibilityAnalyzer(meta, decls)
        results = analyzer.analyze()
        r = next((x for x in results if x.package_name == "click"), None)
        self.assertIsNotNone(r)
        self.assertEqual(r.status, CompatibilityStatus.UNCHECKED)


# ---------------------------------------------------------------------------
# 4. Blast Radius Mapper tests
# ---------------------------------------------------------------------------

class TestBlastRadiusMapper(unittest.TestCase):
    def _decl(self, name):
        from repomedic.models import DependencyDeclaration
        return DependencyDeclaration(
            name=name, raw_declaration=name, specifier=None,
            manifest_path="requirements.txt", line_number=1,
        )

    def _imp(self, module, file_path, is_test=False):
        from repomedic.models import SourceImport
        return SourceImport(
            module=module, imported_names=[], file_path=file_path,
            line_number=1, is_test_file=is_test,
        )

    def test_graph_edges_only_from_evidence(self):
        from repomedic.blast import BlastRadiusMapper
        decls = [self._decl("requests")]
        imps  = [
            self._imp("requests", "src/fetch.py"),
            self._imp("requests", "tests/test_fetch.py", is_test=True),
        ]
        mapper = BlastRadiusMapper(decls, imps)
        graph = mapper.map_dependency("requests")
        self.assertEqual(len(graph.importing_source_files), 1)
        self.assertEqual(graph.importing_source_files[0].relative_path, "src/fetch.py")
        self.assertEqual(len(graph.importing_test_files), 1)

    def test_ghost_dependency_low_risk(self):
        from repomedic.blast import BlastRadiusMapper
        from repomedic.models import FindingSeverity
        decls = [self._decl("six")]
        mapper = BlastRadiusMapper(decls, [])   # no imports
        graph = mapper.map_dependency("six")
        self.assertEqual(graph.risk_level, FindingSeverity.LOW)

    def test_deterministic_output(self):
        """Same inputs always produce the same graph — no randomness."""
        from repomedic.blast import BlastRadiusMapper
        decls = [self._decl("click")]
        imps  = [
            self._imp("click", "cmd/a.py"),
            self._imp("click", "cmd/b.py"),
        ]
        mapper1 = BlastRadiusMapper(decls, imps)
        mapper2 = BlastRadiusMapper(decls, imps)
        g1 = mapper1.map_dependency("click")
        g2 = mapper2.map_dependency("click")
        paths1 = [n.relative_path for n in g1.importing_source_files]
        paths2 = [n.relative_path for n in g2.importing_source_files]
        self.assertEqual(paths1, paths2)

    def test_replacement_evidence_missing_populated(self):
        from repomedic.blast import BlastRadiusMapper
        decls = [self._decl("appdirs")]
        mapper = BlastRadiusMapper(decls, [])
        graph = mapper.map_dependency("appdirs", proposed_replacement="platformdirs")
        self.assertGreater(len(graph.replacement_evidence_missing), 0)

    def test_untraceable_areas_always_present(self):
        from repomedic.blast import BlastRadiusMapper
        decls = [self._decl("pydantic")]
        mapper = BlastRadiusMapper(decls, [])
        graph = mapper.map_dependency("pydantic")
        self.assertGreater(len(graph.untraceable_areas), 0)


# ---------------------------------------------------------------------------
# 5. Migration Tripwire tests
# ---------------------------------------------------------------------------

class TestMigrationTripwire(unittest.TestCase):
    def _decl(self, name, spec=None):
        from repomedic.models import DependencyDeclaration
        return DependencyDeclaration(
            name=name, raw_declaration=f"{name}{spec or ''}",
            specifier=spec, manifest_path="requirements.txt", line_number=1,
        )

    def _imp(self, module, names=None, is_test=False):
        from repomedic.models import SourceImport
        return SourceImport(
            module=module, imported_names=names or [],
            file_path="src/main.py", line_number=1,
            is_test_file=is_test,
        )

    def test_toml_to_tomllib_rule_applied(self):
        from repomedic.tripwire import MigrationTripwire, TripwireClassification
        decls = [self._decl("toml", "==0.10.2")]
        imps  = [self._imp("toml")]
        tw = MigrationTripwire(decls, imps)
        obs = tw.analyze_migration("toml", "tomllib")
        self.assertTrue(len(obs) > 0)
        # Should warn about write API absence
        titles = [o.title for o in obs]
        self.assertTrue(any("toml" in t.lower() for t in titles))

    def test_breaking_api_confirmed_from_source(self):
        from repomedic.tripwire import MigrationTripwire, TripwireClassification
        decls = [self._decl("toml")]
        imps  = [self._imp("toml", ["dumps"])]
        source_texts = {"src/serialize.py": "result = toml.dumps(data)\n"}
        tw = MigrationTripwire(decls, imps, source_texts)
        obs = tw.analyze_migration("toml")
        self.assertTrue(len(obs) > 0)
        at_risk = [a for o in obs for a in o.api_calls_at_risk]
        self.assertIn("toml.dumps", at_risk)

    def test_unknown_migration_returns_compat_unknown(self):
        from repomedic.tripwire import MigrationTripwire, TripwireClassification
        decls = [self._decl("totally-unknown-pkg")]
        tw = MigrationTripwire(decls, [])
        obs = tw.analyze_migration("totally-unknown-pkg", "another-pkg")
        self.assertEqual(len(obs), 1)
        self.assertEqual(obs[0].classification, TripwireClassification.COMPAT_UNKNOWN)

    def test_appdirs_platformdirs_classified(self):
        from repomedic.tripwire import MigrationTripwire, TripwireClassification
        decls = [self._decl("appdirs", "==1.4.4")]
        imps  = [self._imp("appdirs", ["user_cache_dir"])]
        tw = MigrationTripwire(decls, imps)
        obs = tw.analyze_migration("appdirs", "platformdirs")
        self.assertTrue(len(obs) > 0)
        # appdirs→platformdirs is largely compatible
        classifications = [o.classification for o in obs]
        self.assertIn(TripwireClassification.CONFIRMED_LOCAL, classifications)

    def test_no_rewrite_of_source_code(self):
        """Tripwire must NEVER modify source text."""
        from repomedic.tripwire import MigrationTripwire
        original_text = "import toml\ndata = toml.dumps(config)\n"
        source_texts = {"src/cfg.py": original_text}
        decls = [self._decl("toml")]
        imps  = [self._imp("toml", ["dumps"])]
        tw = MigrationTripwire(decls, imps, source_texts)
        tw.analyze_migration("toml")
        # Text must be unchanged
        self.assertEqual(source_texts["src/cfg.py"], original_text)


# ---------------------------------------------------------------------------
# 6. Evidence Ledger tests
# ---------------------------------------------------------------------------

class TestEvidenceLedger(unittest.TestCase):
    def test_sensitive_files_excluded(self):
        from repomedic.ledger import EvidenceLedgerBuilder
        from repomedic.models import EvidenceReference
        builder = EvidenceLedgerBuilder(repo_root="/tmp", file_hashes={})
        ev = EvidenceReference(
            file_path=".env",
            line_start=1, line_end=1,
            content_snippet="SECRET=hunter2",
            source_type="manifest",
        )
        entry = builder.record_evidence_ref(ev, "TEST-001")
        self.assertIsNone(entry, ".env must not produce an evidence entry")

    def test_staleness_detected_on_hash_change(self):
        from repomedic.ledger import EvidenceLedgerBuilder
        prev = {"src/main.py": "abc123"}
        curr = {"src/main.py": "def456"}
        builder = EvidenceLedgerBuilder(repo_root="/tmp", file_hashes=curr)
        reports = builder.check_staleness(prev, {"src/main.py": ["GHOST-001"]})
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0].file_path, "src/main.py")
        self.assertTrue(reports[0].stale)

    def test_no_staleness_on_same_hash(self):
        from repomedic.ledger import EvidenceLedgerBuilder
        h = "aabbccdd"
        builder = EvidenceLedgerBuilder(repo_root="/tmp", file_hashes={"f.py": h})
        reports = builder.check_staleness({"f.py": h})
        self.assertEqual(reports, [])

    def test_composite_hash_deterministic(self):
        from repomedic.ledger import EvidenceLedgerBuilder
        hashes = {"a.py": "111", "b.py": "222"}
        b1 = EvidenceLedgerBuilder(repo_root="/tmp", file_hashes=hashes)
        b2 = EvidenceLedgerBuilder(repo_root="/tmp", file_hashes=hashes)
        self.assertEqual(b1.build().composite_hash, b2.build().composite_hash)

    def test_composite_hash_changes_with_content(self):
        from repomedic.ledger import EvidenceLedgerBuilder
        b1 = EvidenceLedgerBuilder(repo_root="/tmp", file_hashes={"a.py": "111"})
        b2 = EvidenceLedgerBuilder(repo_root="/tmp", file_hashes={"a.py": "999"})
        self.assertNotEqual(b1.build().composite_hash, b2.build().composite_hash)

    def test_excerpt_truncated_at_limit(self):
        from repomedic.ledger import EvidenceLedgerBuilder, SNIPPET_MAX_BYTES
        from repomedic.models import EvidenceReference
        long_snippet = "x" * (SNIPPET_MAX_BYTES + 100)
        ev = EvidenceReference(
            file_path="src/main.py",
            line_start=1, line_end=1,
            content_snippet=long_snippet,
            source_type="source_ast",
        )
        builder = EvidenceLedgerBuilder(repo_root="/tmp", file_hashes={})
        entry = builder.record_evidence_ref(ev, "RULE-001")
        self.assertIsNotNone(entry)
        self.assertLessEqual(len(entry.excerpt), SNIPPET_MAX_BYTES + 20)

    def test_key_files_excluded_from_hashing(self):
        from repomedic.ledger import EvidenceLedgerBuilder
        builder = EvidenceLedgerBuilder(
            repo_root="/tmp",
            file_hashes={"src/main.py": "aaa"},
        )
        builder.register_file_hash("id_rsa", "bbb")
        ledger = builder.build()
        self.assertNotIn("id_rsa", ledger.file_hashes)


# ---------------------------------------------------------------------------
# 7. Safety / path boundary tests
# ---------------------------------------------------------------------------

class TestSafety(unittest.TestCase):
    def test_invalid_repo_path(self):
        from repomedic.inventory import RepositoryInventoryScanner
        with self.assertRaises(FileNotFoundError):
            RepositoryInventoryScanner("/nonexistent/path/abc")

    def test_path_traversal_error(self):
        from repomedic.safety import validate_safe_path, PathTraversalError
        with self.assertRaises(PathTraversalError):
            validate_safe_path("/tmp", "/etc/passwd")


# ---------------------------------------------------------------------------
# 8. Integration test against a synthetic LinkWatch-like fixture
# ---------------------------------------------------------------------------

LINKWATCH_FIXTURE = {
    "pyproject.toml": textwrap.dedent("""\
        [project]
        name = "linkwatch"
        requires-python = ">=3.10"
        dependencies = [
            "pydantic>=2",
            "click>=8",
            "toml==0.10.2",
            "appdirs==1.4.4",
            "requests>=2.28",
        ]
        [project.optional-dependencies]
        dev = [
            "nose==1.3.7",
            "pytest>=7",
        ]
    """),
    "requirements.txt": textwrap.dedent("""\
        pydantic==1.10.13
        requests==2.31.0
        six
    """),
    "linkwatch/__init__.py": "",
    "linkwatch/config.py": textwrap.dedent("""\
        import toml
        from pydantic import BaseModel, validator
        class Config(BaseModel):
            name: str
            @validator('name')
            def validate_name(cls, v): return v
    """),
    "linkwatch/cache.py": textwrap.dedent("""\
        from appdirs import user_cache_dir
        CACHE = user_cache_dir("linkwatch")
    """),
    "linkwatch/resources.py": textwrap.dedent("""\
        import pkg_resources
        tmpl = pkg_resources.resource_filename("linkwatch", "templates/report.html")
    """),
    "linkwatch/fetcher.py": textwrap.dedent("""\
        import requests
        def fetch(url): return requests.get(url)
    """),
    "tests/__init__.py": "",
    "tests/test_fetcher.py": textwrap.dedent("""\
        import pytest
        from linkwatch.fetcher import fetch
        def test_fetch(): pass
    """),
}


class TestIntegrationLinkwatchFixture(unittest.TestCase):
    def setUp(self):
        self.root = make_repo(LINKWATCH_FIXTURE)

    def tearDown(self):
        cleanup(self.root)

    def test_full_engine_produces_structured_output(self):
        from repomedic.engine import IntelligenceEngine
        engine = IntelligenceEngine(self.root)
        report = engine.run(scan_command=f"repomedic scan {self.root}")
        capsule = report.capsule
        self.assertIsNotNone(capsule)
        self.assertGreater(len(capsule.findings), 0)
        self.assertGreater(len(capsule.declarations), 0)
        self.assertGreater(len(capsule.imports), 0)

    def test_manifest_conflict_detected(self):
        from repomedic.engine import IntelligenceEngine
        engine = IntelligenceEngine(self.root)
        report = engine.run()
        conflicts = [f for f in report.capsule.findings if f.category == "manifest_conflict"]
        # pydantic declared as >=2 in pyproject.toml and ==1.10.13 in requirements.txt
        pkg_names = [f.package_name for f in conflicts]
        self.assertIn("pydantic", pkg_names)

    def test_ghost_six_detected(self):
        """'six' is in requirements.txt but never imported anywhere."""
        from repomedic.engine import IntelligenceEngine
        from repomedic.ghost import GhostClassification
        engine = IntelligenceEngine(self.root)
        report = engine.run()
        ghost_findings = [f for f in report.capsule.findings if f.category == "ghost_dependency"]
        ghost_pkgs = [f.package_name for f in ghost_findings]
        self.assertIn("six", ghost_pkgs)

    def test_toml_tripwire_detected(self):
        from repomedic.engine import IntelligenceEngine
        engine = IntelligenceEngine(self.root)
        report = engine.run()
        tripwires = [f for f in report.capsule.findings if f.category == "migration_tripwire"]
        pkg_names = [f.package_name for f in tripwires]
        self.assertIn("toml", pkg_names)

    def test_appdirs_tripwire_detected(self):
        from repomedic.engine import IntelligenceEngine
        engine = IntelligenceEngine(self.root)
        report = engine.run()
        tripwires = [f for f in report.capsule.findings if f.category == "migration_tripwire"]
        pkg_names = [f.package_name for f in tripwires]
        self.assertIn("appdirs", pkg_names)

    def test_blast_radius_requests_has_evidence(self):
        from repomedic.engine import IntelligenceEngine
        engine = IntelligenceEngine(self.root)
        report = engine.run()
        br = next((b for b in report.capsule.blast_radii if b.dependency_name == "requests"), None)
        self.assertIsNotNone(br)
        self.assertGreater(len(br.importing_files), 0)

    def test_all_findings_have_evidence(self):
        from repomedic.engine import IntelligenceEngine
        engine = IntelligenceEngine(self.root)
        report = engine.run()
        for f in report.capsule.findings:
            self.assertGreater(
                len(f.evidence), 0,
                msg=f"Finding {f.id} '{f.title}' has no evidence references"
            )

    def test_ledger_composite_hash_non_empty(self):
        from repomedic.engine import IntelligenceEngine
        engine = IntelligenceEngine(self.root)
        report = engine.run()
        self.assertRegex(report.ledger.composite_hash, r'^[0-9a-f]{64}$')

    def test_hermes_interface_schema(self):
        from repomedic.engine import IntelligenceEngine
        engine = IntelligenceEngine(self.root)
        report = engine.run()
        hi = report.hermes_interface
        self.assertIn("schema_version", hi)
        self.assertIn("findings", hi)
        self.assertIn("blast_radii", hi)
        self.assertIn("inventory_summary", hi)
        self.assertIn("limitations", hi)
        # Every finding entry has required keys
        for f in hi["findings"]:
            for key in ("id", "category", "severity", "status", "package", "title"):
                self.assertIn(key, f)

    def test_json_capsule_serialisable(self):
        from repomedic.engine import IntelligenceEngine
        engine = IntelligenceEngine(self.root)
        report = engine.run()
        raw = json.dumps(report.capsule.model_dump())
        parsed = json.loads(raw)
        self.assertIn("findings", parsed)

    def test_staleness_detected_after_file_change(self):
        from repomedic.engine import IntelligenceEngine
        # First scan to get hashes
        engine = IntelligenceEngine(self.root)
        report1 = engine.run()
        previous = dict(report1.ledger.file_hashes)

        # Modify a file
        (self.root / "linkwatch" / "config.py").write_text(
            "# changed\nimport toml\n", encoding="utf-8"
        )

        # Second scan with previous hashes
        engine2 = IntelligenceEngine(self.root, previous_hashes=previous)
        report2 = engine2.run()
        stale_files = [s.file_path for s in report2.staleness_reports]
        self.assertTrue(
            any("config" in p for p in stale_files),
            f"Expected config.py to be stale; stale files: {stale_files}"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)

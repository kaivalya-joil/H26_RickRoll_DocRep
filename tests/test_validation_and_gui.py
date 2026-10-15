"""Step 5 Tests: Capsule validity, schema, missing evidence, failed/inconclusive checks,

malformed model output, partial scanner results, model-metadata preservation,
recommendation vs verification separation, and GUI backend API.
"""

import json
import shutil
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import MagicMock, patch

from repomedic.capsule import CapsuleGenerator
from repomedic.gui import DocRepHTTPRequestHandler, job_manager
from repomedic.hermes_adapter import HermesAdapter
from repomedic.models import (
    AIRecommendation,
    BlastRadiusEntry,
    DependencyDeclaration,
    DependencyExitCapsule,
    EvidenceReference,
    Finding,
    FindingSeverity,
    FindingStatus,
    RepositoryMetadata,
    SourceImport,
    VerificationResult,
)
from repomedic.scanner import RepositoryScanner


class TestCapsuleValidationAndSchema(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.out_dir = Path(self.temp_dir)

        self.metadata = RepositoryMetadata(
            repo_name="linkwatch",
            repo_path=str(self.out_dir),
            git_commit="abcdef1234567890",
            git_branch="main",
            python_version_detected="3.12.0",
            python_requires_declared=">=3.10",
            manifests_found=["pyproject.toml"],
            source_files_count=3,
            test_files_count=1,
        )
        self.declarations = [
            DependencyDeclaration(name="pydantic", raw_declaration="pydantic>=2", specifier=">=2", manifest_path="pyproject.toml", line_number=10)
        ]
        self.imports = [
            SourceImport(module="pydantic", imported_names=["BaseModel"], file_path="config.py", line_number=5)
        ]
        self.findings = [
            Finding(
                id="TRIPWIRE-001",
                category="migration_tripwire",
                title="Pydantic v1 patterns",
                explanation="Pydantic validator deprecation",
                severity=FindingSeverity.HIGH,
                status=FindingStatus.OBSERVED,
                package_name="pydantic",
                evidence=[
                    EvidenceReference(file_path="config.py", line_start=5, line_end=5, content_snippet="import BaseModel", source_type="source_ast")
                ],
            )
        ]
        self.recommendations = [
            AIRecommendation(
                id="REC-001",
                finding_id="TRIPWIRE-001",
                package_name="pydantic",
                title="Upgrade to Pydantic v2",
                rationale="Adopt modern ConfigDict",
                suggested_action="upgrade",
                target_replacement="pydantic>=2.0",
                source="local_ollama_hermes",
                model_name="qwen2.5-coder:1.5b",
            )
        ]
        self.verifications = [
            VerificationResult(
                id="VERIFY-001",
                target="config_validation",
                command=["internal_config_check"],
                exit_code=0,
                status=FindingStatus.VERIFIED,
                timestamp="2026-10-15T12:00:00Z",
                sandbox_used=False,
            ),
            VerificationResult(
                id="VERIFY-002",
                target="test_suite_run",
                command=["pytest", "tests"],
                exit_code=1,
                status=FindingStatus.FAILED,
                stderr="AssertionError in test_config",
                timestamp="2026-10-15T12:00:01Z",
                sandbox_used=True,
                notes="Regression detected under Pydantic v2",
            ),
        ]
        self.blast_radii = [
            BlastRadiusEntry(
                dependency_name="pydantic",
                importing_files=["config.py"],
                affected_tests=["tests/test_config.py"],
                risk_level=FindingSeverity.HIGH,
                summary="High impact on configuration loading",
            )
        ]
        self.m_hashes = {"pyproject.toml": "hash_manifest_123"}
        self.s_hashes = {"config.py": "hash_source_456"}
        self.model_info = {
            "model_name": "qwen2.5-coder:1.5b",
            "endpoint": "http://127.0.0.1:11434",
            "mode": "local_ollama_hermes",
        }

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_capsule_schema_and_agreement(self):
        """1. Capsule validity and JSON schema conformance, plus agreement with Markdown."""
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
            model_info=self.model_info,
        )

        json_p = gen.export_json(self.out_dir / "capsule.json")
        md_p = gen.export_markdown(self.out_dir / "capsule.md")

        # Validate JSON schema loading
        raw_json = json_p.read_text(encoding="utf-8")
        parsed = json.loads(raw_json)
        capsule_obj = DependencyExitCapsule.model_validate(parsed)

        self.assertEqual(capsule_obj.metadata.repo_name, "linkwatch")
        self.assertEqual(capsule_obj.metadata.git_commit, "abcdef1234567890")
        self.assertEqual(capsule_obj.tool_name, "DocRep")
        self.assertEqual(capsule_obj.model_info["model_name"], "qwen2.5-coder:1.5b")

        # Validate Markdown agreement
        md_text = md_p.read_text(encoding="utf-8")
        self.assertIn("linkwatch", md_text)
        self.assertIn("abcdef1234567890", md_text)
        self.assertIn(capsule_obj.fingerprint.composite_hash, md_text)
        self.assertIn("qwen2.5-coder:1.5b", md_text)

    def test_missing_evidence_handling(self):
        """2. Findings with zero or missing evidence references serialize gracefully."""
        orphan_finding = Finding(
            id="ORPHAN-001",
            category="ghost_dependency",
            title="Finding without direct evidence file",
            explanation="Unused package discovered via heuristics",
            severity=FindingSeverity.LOW,
            status=FindingStatus.INFERRED,
            package_name="unused_pkg",
            evidence=[],  # Empty evidence
        )
        gen = CapsuleGenerator(
            metadata=self.metadata,
            declarations=self.declarations,
            imports=self.imports,
            findings=[orphan_finding],
            recommendations=[],
            verifications=[],
            blast_radii=[],
            manifest_hashes=self.m_hashes,
            source_hashes=self.s_hashes,
        )
        md_text = gen.export_markdown(self.out_dir / "orphan_capsule.md").read_text(encoding="utf-8")
        self.assertIn("ORPHAN-001", md_text)
        self.assertIn("N/A", md_text)

    def test_failed_and_inconclusive_checks_preserved(self):
        """3. Failed, blocked, and inconclusive checks are preserved and never look done."""
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

        failed_check = next(v for v in capsule.verifications if v.id == "VERIFY-002")
        self.assertEqual(failed_check.status, FindingStatus.FAILED)
        self.assertEqual(failed_check.exit_code, 1)

        # Verification Debt must reflect unverified status
        self.assertTrue(any("DEBT" in item.id for item in capsule.verification_debt_details))
        self.assertTrue(any("UNVERIFIED" in item.status for item in capsule.verification_debt_details))

    def test_malformed_model_output_handling(self):
        """4. Malformed model output triggers retry and fails safely without crashing."""
        adapter = HermesAdapter()
        mock_finding = self.findings[0]

        bad_resp = MagicMock()
        bad_resp.status_code = 200
        bad_resp.json.return_value = {"choices": [{"message": {"content": "This is totally not JSON at all!"}}]}

        with patch("requests.post", return_value=bad_resp):
            with patch.object(HermesAdapter, "warmup_check", return_value={"status": "ok"}):
                result = adapter.analyze_finding(mock_finding, "snippet", use_cache=False)
                self.assertEqual(result.status, "failed")
                self.assertIn("Schema validation failed", result.error_message)

    def test_recommendation_vs_verification_separation(self):
        """5. Three clearly separate sections in capsule.md."""
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
        md_text = gen.export_markdown(self.out_dir / "sections_capsule.md").read_text(encoding="utf-8")

        self.assertIn("## SECTION 1: OBSERVED EVIDENCE", md_text)
        self.assertIn("## SECTION 2: AI SUGGESTIONS & REASONING", md_text)
        self.assertIn("## SECTION 3: VERIFIED RESULTS & AUDIT DEBT", md_text)
        self.assertIn("Non-Deterministic Reasoning Notice", md_text)

    def test_export_html_report(self):
        """Export standalone HTML report and verify structure."""
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
        html_path = gen.export_html(self.out_dir / "report.html")
        self.assertTrue(html_path.exists())
        content = html_path.read_text(encoding="utf-8")
        self.assertIn("<!DOCTYPE html>", content)
        self.assertIn("DocRep", content)
        self.assertIn("linkwatch", content)
        self.assertIn("capsule-data", content)


class TestPartialScannerResults(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.repo_p = Path(self.temp_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_partial_scanner_only_pyproject(self):
        """Partial scanner results: directory with only pyproject.toml and zero source files."""
        (self.repo_p / "pyproject.toml").write_text('[project]\nname="partial"\ndependencies=["requests>=2"]\n', encoding="utf-8")
        scanner = RepositoryScanner(self.repo_p)
        meta, decls, imps, m_hashes, s_hashes = scanner.scan()

        self.assertEqual(meta.repo_name, self.repo_p.name)
        self.assertEqual(meta.source_files_count, 0)
        self.assertEqual(len(decls), 1)
        self.assertEqual(decls[0].name, "requests")
        self.assertEqual(len(imps), 0)
        self.assertIn("pyproject.toml", m_hashes)


class TestGUIBackendAPI(unittest.TestCase):
    server = None
    server_thread = None
    port = 0

    @classmethod
    def setUpClass(cls):
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            cls.port = s.getsockname()[1]

        cls.server = ThreadingHTTPServer(("127.0.0.1", cls.port), DocRepHTTPRequestHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.3)

    @classmethod
    def tearDownClass(cls):
        if cls.server:
            cls.server.shutdown()
            cls.server.server_close()

    def test_api_status(self):
        """GUI API: GET /api/status returns runtime status."""
        url = f"http://127.0.0.1:{self.port}/api/status"
        with urllib.request.urlopen(url) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["project_name"], "DocRep")
            self.assertIn("hermes", data)
            self.assertIn("ollama", data)
            self.assertIn("model", data)

    def test_api_run_rejects_invalid_path(self):
        """GUI API: POST /api/run rejects non-existent paths with 400 error."""
        url = f"http://127.0.0.1:{self.port}/api/run"
        req = urllib.request.Request(
            url,
            data=json.dumps({"repo_path": "invalid/non_existent_directory_123"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(req)
            self.fail("Expected HTTPError 400 for invalid path.")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 400)
            err_data = json.loads(e.read().decode("utf-8"))
            self.assertIn("does not exist", err_data["error"])

    def test_api_job_lifecycle(self):
        """GUI API: GET /api/job reflects running and idle job states."""
        url = f"http://127.0.0.1:{self.port}/api/job"
        with urllib.request.urlopen(url) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertIn("status", data)
            self.assertIn("progress_pct", data)

    def test_api_download_capsule_html(self):
        """GUI API: GET /api/capsule.html returns HTML content."""
        url = f"http://127.0.0.1:{self.port}/api/capsule.html"
        try:
            with urllib.request.urlopen(url) as resp:
                self.assertEqual(resp.status, 200)
                self.assertIn("text/html", resp.headers.get("Content-Type", ""))
                body = resp.read().decode("utf-8")
                self.assertIn("DocRep", body)
        except urllib.error.HTTPError as e:
            self.assertIn(e.code, (200, 404))


if __name__ == "__main__":
    unittest.main()

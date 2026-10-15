"""Tests for AI analyzer, Hermes adapter, schema validation, retry-once, caching, and verifier allow-list."""

import json
import pytest
from unittest.mock import MagicMock, patch
from pathlib import Path

from repomedic.models import Finding, FindingSeverity, FindingStatus, EvidenceReference
from repomedic.hermes_adapter import (
    HermesAdapter,
    StructuredRecommendationSchema,
    ALLOWED_SAFE_CHECKS,
    CACHE_DIR,
)
from repomedic.impact import ImpactAnalyzer, ImpactItem
from repomedic.verifier import SafeVerificationRunner


@pytest.fixture
def mock_finding():
    return Finding(
        id="TEST-001",
        category="manifest_conflict",
        title="Conflicting pydantic specifiers",
        explanation="pyproject.toml has >=2, requirements.txt has ==1.10.13",
        severity=FindingSeverity.HIGH,
        status=FindingStatus.OBSERVED,
        confidence=1.0,
        evidence=[
            EvidenceReference(
                file_path="pyproject.toml",
                line_start=17,
                line_end=17,
                content_snippet="pydantic>=2",
                source_type="manifest",
            )
        ],
    )


def test_schema_validation_valid():
    valid_payload = {
        "problem_explanation": "Version conflict leads to non-deterministic builds.",
        "evidence_significance": "Direct contradiction between two manifests.",
        "impact_and_uncertainty": "Affects build tools and container builds.",
        "recommended_action": "Align pydantic versions across manifests.",
        "suggested_migration": "Adopt pydantic 2 across codebase.",
        "verification_check_name": "manifest_consistency",
        "assumptions": ["Project aims for python 3.10+"],
        "counterarguments": ["Legacy environments might require v1"],
        "disproving_evidence": "All CI workflows passing with pinned v1",
        "open_compatibility_concerns": ["class Config deprecation"],
    }
    obj = StructuredRecommendationSchema(**valid_payload)
    assert obj.verification_check_name == "manifest_consistency"


def test_schema_validation_invalid_fails():
    invalid_payload = {"problem_explanation": "Incomplete payload"}
    with pytest.raises(Exception):
        StructuredRecommendationSchema(**invalid_payload)


def test_verifier_rejects_unknown_checks():
    runner = SafeVerificationRunner(Path("."))
    res = runner.execute_check("rm_rf_dangerous_command")
    assert res.status == FindingStatus.BLOCKED
    assert "not in the allowed verification allow-list" in res.stderr


def test_verifier_runs_allowed_check(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname="test"', encoding="utf-8")
    runner = SafeVerificationRunner(tmp_path)
    res = runner.execute_check("config_validation")
    assert res.status == FindingStatus.VERIFIED
    assert res.exit_code == 0


def test_impact_map_labels_direct_vs_inferred():
    from repomedic.models import DependencyDeclaration, SourceImport
    decls = [DependencyDeclaration(
        name="requests", raw_declaration="requests==2.31.0",
        manifest_path="requirements.txt", line_number=1,
    )]
    imps = [SourceImport(
        module="requests", imported_names=[], file_path="app.py",
        line_number=1, is_test_file=False,
    )]
    analyzer = ImpactAnalyzer(decls, imps)
    impact = analyzer.analyze_dependency("requests")
    
    assert any(x.evidence_type == "direct evidence" for x in impact.importing_files)
    assert any(x.evidence_type == "inferred" for x in impact.unclear_or_dynamic_refs)


@patch("requests.get")
def test_warmup_ollama_not_running(mock_get):
    mock_get.side_effect = Exception("Connection refused")
    adapter = HermesAdapter(endpoint="http://127.0.0.1:11434")
    res = adapter.warmup_check()
    assert res["status"] == "error"
    assert "Ollama is not running" in res["error"]


@patch("requests.get")
def test_warmup_model_missing(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"models": [{"name": "mistral:latest"}]}
    mock_get.return_value = mock_resp
    adapter = HermesAdapter(model_name="qwen2.5-coder:1.5b")
    res = adapter.warmup_check()
    assert res["status"] == "error"
    assert "not found in Ollama models" in res["error"]


@patch("requests.post")
@patch.object(HermesAdapter, "warmup_check", return_value={"status": "ok"})
def test_retry_once_on_malformed_json(mock_warmup, mock_post, mock_finding):
    # First response malformed, second response valid
    bad_resp = MagicMock()
    bad_resp.status_code = 200
    bad_resp.json.return_value = {"choices": [{"message": {"content": "Not JSON!"}}]}

    good_resp = MagicMock()
    good_resp.status_code = 200
    good_resp.json.return_value = {"choices": [{"message": {"content": json.dumps({
        "problem_explanation": "Fixed",
        "evidence_significance": "Important",
        "impact_and_uncertainty": "Known",
        "recommended_action": "Fix it",
        "suggested_migration": "Step 1",
        "verification_check_name": "manifest_consistency",
        "assumptions": [],
        "counterarguments": [],
        "disproving_evidence": "None",
        "open_compatibility_concerns": []
    })}}]}

    mock_post.side_effect = [bad_resp, good_resp]
    adapter = HermesAdapter()
    result = adapter.analyze_finding(mock_finding, "snippet", use_cache=False)
    assert result.status == "success"
    assert mock_post.call_count == 2

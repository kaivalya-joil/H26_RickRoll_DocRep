"""Tests for deterministic scanner covering edge cases and LinkWatch fixture."""

import tempfile
import pytest
from pathlib import Path
from repomedic.scanner import RepositoryScanner
from repomedic.models import FindingSeverity, FindingStatus


@pytest.fixture
def make_tmp_repo():
    dirs = []
    def _create(files: dict):
        d = Path(tempfile.mkdtemp(prefix="test_repo_"))
        dirs.append(d)
        for rel, text in files.items():
            f = d / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(text, encoding="utf-8")
        return d
    yield _create
    import shutil
    for d in dirs:
        shutil.rmtree(d, ignore_errors=True)


def test_missing_path_raises():
    with pytest.raises(FileNotFoundError):
        RepositoryScanner("/nonexistent/path/xyz")


def test_empty_repo(make_tmp_repo):
    repo = make_tmp_repo({})
    scanner = RepositoryScanner(repo)
    meta, decls, imps, m_hash, s_hash = scanner.scan()
    assert len(decls) == 0
    assert len(imps) == 0


def test_conflicting_constraints_detected(make_tmp_repo):
    repo = make_tmp_repo({
        "pyproject.toml": '[project]\nname="app"\ndependencies=["pydantic>=2"]\n',
        "requirements.txt": "pydantic==1.10.13\n",
    })
    scanner = RepositoryScanner(repo)
    _, decls, imps, _, _ = scanner.scan()
    findings = scanner.run_deterministic_rules(decls, imps)
    conflicts = [f for f in findings if f.category == "manifest_conflict"]
    assert len(conflicts) == 1
    assert conflicts[0].package_name == "pydantic"
    assert conflicts[0].confidence == 1.0


def test_consistent_declarations(make_tmp_repo):
    repo = make_tmp_repo({
        "pyproject.toml": '[project]\nname="app"\ndependencies=["requests==2.31.0"]\n',
        "requirements.txt": "requests==2.31.0\n",
    })
    scanner = RepositoryScanner(repo)
    _, decls, imps, _, _ = scanner.scan()
    findings = scanner.run_deterministic_rules(decls, imps)
    conflicts = [f for f in findings if f.category == "manifest_conflict"]
    assert len(conflicts) == 0


def test_import_to_file_mapping(make_tmp_repo):
    repo = make_tmp_repo({
        "app.py": "import os\nimport requests\n",
    })
    scanner = RepositoryScanner(repo)
    _, _, imps, _, _ = scanner.scan()
    req_imp = next(i for i in imps if i.module == "requests")
    assert req_imp.file_path == "app.py"
    assert req_imp.line_number == 2


def test_undeclared_third_party_dependency(make_tmp_repo):
    repo = make_tmp_repo({
        "pyproject.toml": '[project]\nname="app"\ndependencies=[]\n',
        "app.py": "import certifi\n",
    })
    scanner = RepositoryScanner(repo)
    _, decls, imps, _, _ = scanner.scan()
    findings = scanner.run_deterministic_rules(decls, imps)
    undeclared = [f for f in findings if f.category == "undeclared_dependency"]
    assert any(f.package_name == "certifi" for f in undeclared)


def test_possibly_unused_dependency(make_tmp_repo):
    repo = make_tmp_repo({
        "requirements.txt": "six==1.16.0\n",
        "app.py": "import sys\n",
    })
    scanner = RepositoryScanner(repo)
    _, decls, imps, _, _ = scanner.scan()
    findings = scanner.run_deterministic_rules(decls, imps)
    ghosts = [f for f in findings if f.category == "ghost_dependency"]
    assert any(f.package_name == "six" for f in ghosts)
    assert ghosts[0].confidence == 0.75
    assert len(ghosts[0].limitations) > 0


def test_malformed_manifest_handled(make_tmp_repo):
    repo = make_tmp_repo({
        "pyproject.toml": "this is [not valid toml :::",
    })
    scanner = RepositoryScanner(repo)
    meta, decls, _, _, _ = scanner.scan()
    assert len(decls) == 0


def test_real_linkwatch_scan():
    linkwatch_dir = Path("D:/SVU Hackathon/RickRoll1/target_repo/linkwatch")
    if not linkwatch_dir.exists():
        pytest.skip("LinkWatch repository not available locally")

    scanner = RepositoryScanner(linkwatch_dir)
    meta, decls, imps, _, _ = scanner.scan()
    findings = scanner.run_deterministic_rules(decls, imps)

    # Verify Pydantic conflict confirmed
    pydantic_conflicts = [f for f in findings if f.category == "manifest_conflict" and f.package_name == "pydantic"]
    assert len(pydantic_conflicts) == 1

    # Verify certifi undeclared import confirmed
    certifi_findings = [f for f in findings if f.package_name == "certifi" and f.category == "undeclared_dependency"]
    assert len(certifi_findings) == 1

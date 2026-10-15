---
name: dependency-resilience
description: Evidence-backed repository dependency maintenance skill for diagnosing ghost dependencies, version conflicts, abandoned packages, and blast-radius impacts using local AI models.
compatibility: ["python>=3.10", "hermes-agent>=0.5", "ollama>=0.3"]
allowed-tools:
  - bash
  - file_read
  - pytest
metadata:
  standard: Agent Skills Open Standard
  track: "Track 2: Maintenance Agent Skill"
  author: RepoMedic Hackathon Team
---

# Dependency Resilience Skill

A verifiable, deterministic maintenance skill designed for Python repositories facing dependency rot, manifest drift, and breaking library migrations.

## Progressive Disclosure Workflow

### 1. Repository Inventory & Inspection
- Scan all package manifests (`requirements.txt`, `pyproject.toml`, `setup.cfg`).
- Discover AST source and test imports, mapping each import to its exact file path and line number.
- Separate standard-library, local, and third-party imports cleanly.

### 2. Deterministic Evidence Gathering
- Flag **Manifest Divergences**: Contradictory version constraints declared across manifests.
- Flag **Undeclared Dependencies**: Third-party packages imported in source but omitted from manifests.
- Flag **POSSIBLY Unused Dependencies**: Declared packages with 0 static AST imports (never claims "definitely unused").
- Flag **Network Call Gaps**: Missing HTTP request timeouts.

### 3. Severity × Confidence Prioritization
- Compute finding priority = `severity_weight × confidence_score`.
- In fast mode, prioritize the top 5 high-impact findings to conserve compute and avoid context bloat.

### 4. Local AI Analysis (Hermes Agent + Ollama)
- For each prioritized finding, extract a 5-line contextual code snippet.
- Transmit to the local open-weight model (`qwen2.5-coder`) via Hermes's OpenAI-compatible endpoint.
- Enforce strict JSON schema validation containing:
  - Problem explanation & evidence significance.
  - Recommended action & migration plan.
  - Allow-listed verification check name.
  - Explicit assumptions, counterarguments, and disproving evidence.
- Cache results on disk (`.repomedic_cache`) to avoid redundant inference on unchanged code.

### 5. Allow-Listed Sandbox Verification
- Execute ONLY approved checks from the fixed allow-list:
  - `manifest_consistency`
  - `version_constraint_compatibility`
  - `import_checks`
  - `config_validation`
  - `test_suite_run`
- Execute in isolated temporary sandboxes without altering target source code or host environment.

### 6. Audit Fingerprinting & Dependency Exit Capsule
- Record SHA-256 digests of all inputs and scanner rules.
- Produce `capsule.json` and `capsule.md` documenting verified findings, AI rationale, verification debt, and known limitations.
